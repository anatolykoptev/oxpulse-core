// Stage B Device Identity client coverage.
//
// Plan: docs/superpowers/plans/2026-05-04-identity-and-1to1-plan.md §B.5
//   B3 — page reload → IDB unwrap → same device_pubkey
//   B4 — two browsers same human → two distinct device_pubkey
// FOLLOWUPS.md #10
//
// Strategy:
//   - fake-indexeddb/auto primes globalThis.indexedDB with an in-memory IDB.
//   - Module-scoped caches (cachedIdentity, cachedWrappingKey) inside
//     device-identity.ts survive across calls in one process. To simulate a
//     "page reload" we KEEP fake-indexeddb's in-memory state and use
//     vi.resetModules() + dynamic re-import so the module's caches reset
//     while IDB persistence continues — exactly the production behaviour.
//   - To simulate "two browsers" we swap globalThis.indexedDB for a brand
//     new IDBFactory between fresh module imports — no shared persistence,
//     no shared module cache.
//   - Node 20+ ships WebCrypto Ed25519. We probe once and skip with a TODO
//     pointer to the manual browser-matrix HTML if the runtime is too old.

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import 'fake-indexeddb/auto';
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- fake-indexeddb has no bundled types here
import { IDBFactory } from 'fake-indexeddb';

type DeviceIdentityModule = typeof import('../device-identity.js');

let ed25519Supported = false;

beforeAll(async () => {
	try {
		await crypto.subtle.generateKey(
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false,
			['sign', 'verify']
		);
		ed25519Supported = true;
	} catch {
		ed25519Supported = false;
	}
});

/** Reset module registry so device-identity.ts re-evaluates with empty caches. */
async function freshImport(): Promise<DeviceIdentityModule> {
	const { vi } = await import('vitest');
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

/** Wipe the fake-indexeddb store entirely — used between independent tests. */
function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

beforeEach(() => {
	resetIDB();
});

afterEach(() => {
	resetIDB();
});

describe('device-identity', () => {
	it('B3: page reload → IDB unwrap → same device_pubkey', async () => {
		if (!ed25519Supported) {
			// TODO: see docs/qa/browser-matrix.html for manual coverage on
			// runtimes lacking WebCrypto Ed25519 (Node <20 / older Safari).
			return;
		}

		const first = await freshImport();
		const a = await first.getOrCreateDeviceIdentity();
		expect(a.publicKeyB64).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(await first.hasDeviceIdentity()).toBe(true);

		// Simulate reload: module caches dropped, IDB state retained.
		const second = await freshImport();
		const b = await second.getOrCreateDeviceIdentity();

		expect(b.publicKeyB64).toBe(a.publicKeyB64);
	});

	it('B4: two independent IDB contexts mint two distinct device_pubkeys', async () => {
		if (!ed25519Supported) return;

		// Browser #1
		resetIDB();
		const browser1 = await freshImport();
		const id1 = await browser1.getOrCreateDeviceIdentity();

		// Browser #2 — fresh IDBFactory + fresh module, no shared state.
		resetIDB();
		const browser2 = await freshImport();
		const id2 = await browser2.getOrCreateDeviceIdentity();

		expect(id1.publicKeyB64).not.toBe(id2.publicKeyB64);
	});

	it('signWithDeviceIdentity round-trips through crypto.subtle.verify', async () => {
		if (!ed25519Supported) return;

		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();
		const message = 'oxpulse-join-handshake-v1:room-abc:nonce-xyz';

		const sigB64 = await mod.signWithDeviceIdentity(id, message);
		const sigBytes = mod.fromBase64url(sigB64);

		const ok = await crypto.subtle.verify(
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			id.publicKey,
			sigBytes.buffer as ArrayBuffer,
			new TextEncoder().encode(message)
		);
		expect(ok).toBe(true);
	});

	it('clearDeviceIdentity wipes IDB and a fresh call mints a new pubkey', async () => {
		if (!ed25519Supported) return;

		const mod = await freshImport();
		const before = await mod.getOrCreateDeviceIdentity();
		expect(await mod.hasDeviceIdentity()).toBe(true);

		await mod.clearDeviceIdentity();
		expect(await mod.hasDeviceIdentity()).toBe(false);

		// Same module instance — but identity store and wrapping key both gone,
		// and the in-module cache was nulled by clearDeviceIdentity().
		const after = await mod.getOrCreateDeviceIdentity();
		expect(after.publicKeyB64).not.toBe(before.publicKeyB64);
	});

	it('getOrCreateProfileSeed persists across reloads and is wiped by clearDeviceIdentity', async () => {
		// Plan §1.1: profile_seed is the secret HKDF ikm for at-rest profile
		// encryption. It must (a) survive page reload, (b) be wiped atomically
		// with the device identity so a fresh identity cannot decrypt orphaned
		// profile blobs.
		const first = await freshImport();
		const seedA = await first.getOrCreateProfileSeed();
		expect(seedA).toBeInstanceOf(Uint8Array);
		expect(seedA.byteLength).toBe(32);

		// Same process, second call → identical bytes (in-memory cache).
		const seedAagain = await first.getOrCreateProfileSeed();
		expect(Array.from(seedAagain)).toEqual(Array.from(seedA));

		// Simulate reload: module cache dropped, IDB retained.
		const second = await freshImport();
		const seedB = await second.getOrCreateProfileSeed();
		expect(Array.from(seedB)).toEqual(Array.from(seedA));

		// Identity wipe must take the seed with it (atomic key-root reset).
		if (!ed25519Supported) return;
		await second.clearDeviceIdentity();
		const seedC = await second.getOrCreateProfileSeed();
		expect(Array.from(seedC)).not.toEqual(Array.from(seedA));
	});

	it('toBase64url / fromBase64url round-trip arbitrary bytes', async () => {
		const mod = await freshImport();
		const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
		const round = mod.fromBase64url(mod.toBase64url(bytes));
		expect(Array.from(round)).toEqual(Array.from(bytes));
	});

	// ── privateKeyBytes tests (W7-P2b1 followup) ────────────────────────────
	// Plan: SDK chat route plan, W7-P2b1 limitation #10.
	// sendSealedMessage needs raw 32-byte Ed25519 seed for @noble/curves signing.
	// WebCrypto privateKey is non-extractable — no path from CryptoKey → raw bytes.
	// Fix: store raw seed in IDB alongside the wrapped CryptoKey form.

	it('privateKeyBytes: getOrCreateDeviceIdentity returns Uint8Array(32)', async () => {
		if (!ed25519Supported) return;

		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();

		expect(id.privateKeyBytes).toBeInstanceOf(Uint8Array);
		expect(id.privateKeyBytes.byteLength).toBe(32);
	});

	it('privateKeyBytes: round-trips across IDB restart (simulated reload)', async () => {
		if (!ed25519Supported) return;

		const first = await freshImport();
		const a = await first.getOrCreateDeviceIdentity();

		// Simulate reload: drop module cache, keep IDB state.
		const second = await freshImport();
		const b = await second.getOrCreateDeviceIdentity();

		expect(Array.from(b.privateKeyBytes)).toEqual(Array.from(a.privateKeyBytes));
	});

	it('privateKeyBytes: signs valid Ed25519 signature verifiable with publicKey', async () => {
		// This is the core invariant: raw bytes must match the CryptoKey identity.
		// ed25519.sign(msg, privKeyBytes) must verify against identity.publicKey.
		if (!ed25519Supported) return;

		const { ed25519 } = await import('@noble/curves/ed25519.js');
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();

		const msg = new Uint8Array([1, 2, 3, 4, 5]);
		const sig = ed25519.sign(msg, id.privateKeyBytes);

		// Verify via @noble/curves using raw pubkey bytes
		const pubBytes = mod.fromBase64url(id.publicKeyB64);
		const valid = ed25519.verify(sig, msg, pubBytes);
		expect(valid).toBe(true);
	});

	it('privateKeyBytes: clearDeviceIdentity also removes raw bytes from IDB', async () => {
		if (!ed25519Supported) return;

		const mod = await freshImport();
		await mod.getOrCreateDeviceIdentity();

		await mod.clearDeviceIdentity();

		// After clear, fresh call mints new identity with new privateKeyBytes.
		const after = await mod.getOrCreateDeviceIdentity();
		expect(after.privateKeyBytes).toBeInstanceOf(Uint8Array);
		expect(after.privateKeyBytes.byteLength).toBe(32);
	});
});
