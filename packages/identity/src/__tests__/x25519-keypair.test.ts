/**
 * x25519-keypair.test.ts — B.2-noise-s-key-derivation
 *
 * Tests for the X25519 static keypair stored alongside Ed25519 in IDB.
 * The keypair is used for Noise XX `es`/`se` DH tokens (real static DH,
 * not the ephemeral-only approximation from before B.2).
 *
 * Invariants:
 *   1. X25519 keypair is generated on first call and persisted in IDB.
 *   2. Survives page reload (module cache drop, IDB retained).
 *   3. Wiped by clearDeviceIdentity() — atomic with Ed25519.
 *   4. dhX25519(remotePub) returns correct 32-byte shared secret.
 *   5. Mutual DH: dhX25519(remotePub) == x25519.getSharedSecret(remoteSk, ourPub).
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { x25519 } from '@noble/curves/ed25519.js';

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

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

async function freshImport(): Promise<DeviceIdentityModule> {
	const { vi } = await import('vitest');
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

beforeEach(() => resetIDB());
afterEach(() => resetIDB());

describe('X25519 static keypair (B.2-noise-s-key-derivation)', () => {
	it('getOrCreateX25519Keypair returns 32-byte public key', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const kp = await mod.getOrCreateX25519Keypair();
		expect(kp.publicKey).toBeInstanceOf(Uint8Array);
		expect(kp.publicKey.byteLength).toBe(32);
	});

	it('getOrCreateX25519Keypair is idempotent within same module instance', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const a = await mod.getOrCreateX25519Keypair();
		const b = await mod.getOrCreateX25519Keypair();
		expect(Array.from(a.publicKey)).toEqual(Array.from(b.publicKey));
	});

	it('X25519 keypair persists across module reloads (IDB survival)', async () => {
		if (!ed25519Supported) return;
		const first = await freshImport();
		const kp1 = await first.getOrCreateX25519Keypair();

		// Simulate reload: module caches drop, IDB state retained.
		const second = await freshImport();
		const kp2 = await second.getOrCreateX25519Keypair();

		expect(Array.from(kp2.publicKey)).toEqual(Array.from(kp1.publicKey));
	});

	it('clearDeviceIdentity wipes X25519 keypair (new keypair minted after clear)', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		await mod.getOrCreateDeviceIdentity(); // ensure Ed25519 exists
		const kp1 = await mod.getOrCreateX25519Keypair();

		await mod.clearDeviceIdentity();

		// After clear, a new X25519 keypair must be generated.
		const kp2 = await mod.getOrCreateX25519Keypair();
		// New keypair must differ from old one (overwhelmingly probable with random keys).
		expect(Array.from(kp2.publicKey)).not.toEqual(Array.from(kp1.publicKey));
	});

	it('dhX25519 produces correct shared secret (symmetric with remote DH)', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const ourKp = await mod.getOrCreateX25519Keypair();

		// Generate a remote X25519 keypair using @noble/curves.
		const remoteSk = x25519.utils.randomSecretKey();
		const remotePub = x25519.getPublicKey(remoteSk);

		// Compute DH from our side.
		const sharedOurs = await mod.dhX25519(remotePub);
		expect(sharedOurs).toBeInstanceOf(Uint8Array);
		expect(sharedOurs.byteLength).toBe(32);

		// Compute DH from remote side.
		const sharedRemote = x25519.getSharedSecret(remoteSk, ourKp.publicKey);

		// Both sides must derive the same secret.
		expect(Array.from(sharedOurs)).toEqual(Array.from(sharedRemote));
	});

	it('two independent identities produce different X25519 public keys', async () => {
		if (!ed25519Supported) return;
		resetIDB();
		const m1 = await freshImport();
		const kp1 = await m1.getOrCreateX25519Keypair();

		resetIDB();
		const m2 = await freshImport();
		const kp2 = await m2.getOrCreateX25519Keypair();

		expect(Array.from(kp1.publicKey)).not.toEqual(Array.from(kp2.publicKey));
	});
});
