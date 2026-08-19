/**
 * sealed-x25519-persistence.test.ts — T0.5b
 *
 * The sealed-messaging X25519 scalar must SURVIVE a page reload.
 *
 * Why this is the invariant and not a nicety: a peer encrypts to this public
 * key. When it was generated per session (a WeakMap in x25519-identity.ts),
 * every reload produced a different key, so anything sealed to the previous one
 * became permanently unreadable, every peer saw a TOFU fingerprint change, and
 * publishing it to the server's registry would have tripped the 1-rotation/hour
 * throttle on every load. That is why sealed 1:1 messaging could never be
 * enrolled at all — the production registry held 0 rows.
 *
 * "Reload" is modelled the way the sibling suite models it: drop the module
 * cache (vi.resetModules) while KEEPING the IDB contents. A test that also
 * reset IDB would pass against a purely in-memory implementation and prove
 * nothing.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { createIdbStore } from '../idb-store.js';

/** Pinned literal — renaming this after the first user strands their key. */
const SEALED_KEY_STORAGE_NAME = 'x25519-sealed-v1';

type DeviceIdentityModule = typeof import('../device-identity.js');
type X25519IdentityModule = typeof import('../x25519-identity.js');

let ed25519Supported = false;

beforeAll(async () => {
	try {
		await crypto.subtle.generateKey(
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false,
			['sign', 'verify'],
		);
		ed25519Supported = true;
	} catch {
		ed25519Supported = false;
	}
});

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

/** A page reload: module state gone, IDB retained. */
async function reload(): Promise<{
	device: DeviceIdentityModule;
	x25519Id: X25519IdentityModule;
}> {
	const { vi } = await import('vitest');
	vi.resetModules();
	return {
		device: (await import('../device-identity.js')) as DeviceIdentityModule,
		x25519Id: (await import('../x25519-identity.js')) as X25519IdentityModule,
	};
}

function hex(b: Uint8Array): string {
	return Array.from(b)
		.map((x) => x.toString(16).padStart(2, '0'))
		.join('');
}

beforeEach(() => resetIDB());
afterEach(() => resetIDB());

describe('sealed X25519 secret persistence', () => {
	it('returns a 32-byte scalar', async () => {
		const { device } = await reload();
		const priv = await device.getOrCreateSealedX25519Secret();
		expect(priv).toBeInstanceOf(Uint8Array);
		expect(priv.byteLength).toBe(32);
	});

	it('is idempotent within one session', async () => {
		const { device } = await reload();
		const a = await device.getOrCreateSealedX25519Secret();
		const b = await device.getOrCreateSealedX25519Secret();
		expect(hex(b)).toBe(hex(a));
	});

	// THE test. Without persistence this returns a different scalar and fails.
	it('SURVIVES a reload — same scalar after the module cache is dropped', async () => {
		const first = await reload();
		const before = hex(await first.device.getOrCreateSealedX25519Secret());

		const second = await reload();
		const after = hex(await second.device.getOrCreateSealedX25519Secret());

		expect(after).toBe(before);
	});

	it('the PUBLIC key a peer encrypts to is stable across reloads', async () => {
		const first = await reload();
		const pubBefore = hex(x25519.getPublicKey(await first.device.getOrCreateSealedX25519Secret()));

		const second = await reload();
		const pubAfter = hex(x25519.getPublicKey(await second.device.getOrCreateSealedX25519Secret()));

		expect(pubAfter).toBe(pubBefore);
	});

	it('a message sealed before a reload is still decryptable after it', async () => {
		// The consequence the invariant exists for, exercised as raw DH: a
		// sender derives a shared secret from our published public key, and we
		// must still derive the same one in the next session.
		const first = await reload();
		const ourPubBefore = x25519.getPublicKey(
			await first.device.getOrCreateSealedX25519Secret(),
		);
		const senderSk = x25519.utils.randomSecretKey();
		const senderView = hex(x25519.getSharedSecret(senderSk, ourPubBefore));

		const second = await reload();
		const ourPrivAfter = await second.device.getOrCreateSealedX25519Secret();
		const ourView = hex(x25519.getSharedSecret(ourPrivAfter, x25519.getPublicKey(senderSk)));

		expect(ourView).toBe(senderView);
	});

	it('clearDeviceIdentity REMOVES the stored entry, not just its readability', async () => {
		// "A different key comes back" is NOT this assertion. clearDeviceIdentity
		// also drops the wrapping key, so the old ciphertext becomes unreadable
		// and a fresh scalar is generated whether or not the entry itself was
		// deleted — a mutation removing the delete left that version of this test
		// green. Read the raw row instead: an orphaned wrapped secret sitting in
		// IDB after the user asked to be forgotten is exactly what "forget" is
		// supposed to mean.
		const first = await reload();
		const before = hex(await first.device.getOrCreateSealedX25519Secret());

		const store = createIdbStore({
			dbName: first.device.IDB_DB_NAME,
			storeName: first.device.IDB_STORE_NAME,
		});
		// Storage name is pinned here on purpose: renaming it after the first
		// user strands their key, so the literal belongs in a test.
		expect(await store.load(SEALED_KEY_STORAGE_NAME)).toBeTruthy();

		await first.device.clearDeviceIdentity();
		expect(await store.load(SEALED_KEY_STORAGE_NAME)).toBeFalsy();

		const second = await reload();
		const after = hex(await second.device.getOrCreateSealedX25519Secret());
		expect(after).not.toBe(before);
	});

	it('does NOT survive replaceDeviceIdentity — it belongs to the retired identity', async () => {
		// The subtle case: self_sig is recomputed from whichever seed is current,
		// so a carried-over key would still verify and nothing would look broken.
		// It would simply follow the user across the identity change it was meant
		// to be severed by, while peers hold that public key pinned against the
		// OLD user_id.
		if (!ed25519Supported) return;

		const first = await reload();
		await first.device.getOrCreateDeviceIdentity();
		const before = hex(await first.device.getOrCreateSealedX25519Secret());

		const newSeed = ed25519.utils.randomSecretKey();
		const newPub = ed25519.getPublicKey(newSeed);
		const b64u = (b: Uint8Array) =>
			btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		await first.device.replaceDeviceIdentity(newSeed, b64u(newPub));

		const second = await reload();
		const after = hex(await second.device.getOrCreateSealedX25519Secret());

		expect(after).not.toBe(before);
	});

	it('is a DIFFERENT key from the Noise static keypair', async () => {
		// Cross-protocol static-DH reuse is a question this codebase should not
		// have to answer; the two keys are separate by construction.
		if (!ed25519Supported) return;
		const { device } = await reload();
		const sealed = x25519.getPublicKey(await device.getOrCreateSealedX25519Secret());
		const noise = (await device.getOrCreateX25519Keypair()).publicKey;
		expect(hex(sealed)).not.toBe(hex(noise));
	});

	it('does not disturb the Noise keypair across a reload', async () => {
		// The Noise key's own recovery path exists precisely so it is NOT
		// regenerated (it would break TOFU with every peer). Adding a second
		// stored key must not perturb it.
		if (!ed25519Supported) return;
		const first = await reload();
		const noiseBefore = hex((await first.device.getOrCreateX25519Keypair()).publicKey);
		await first.device.getOrCreateSealedX25519Secret();

		const second = await reload();
		await second.device.getOrCreateSealedX25519Secret();
		const noiseAfter = hex((await second.device.getOrCreateX25519Keypair()).publicKey);

		expect(noiseAfter).toBe(noiseBefore);
	});
});

describe('getOrCreateX25519Identity uses the persisted scalar', () => {
	it('reports the same public key and self_sig across reloads', async () => {
		if (!ed25519Supported) return;

		const first = await reload();
		const id1 = await first.device.getOrCreateDeviceIdentity();
		const before = await first.x25519Id.getOrCreateX25519Identity(id1);

		const second = await reload();
		const id2 = await second.device.getOrCreateDeviceIdentity();
		const after = await second.x25519Id.getOrCreateX25519Identity(id2);

		expect(hex(after.pub)).toBe(hex(before.pub));
		// Ed25519 is deterministic, so a recomputed self_sig is byte-identical.
		expect(hex(after.selfSig)).toBe(hex(before.selfSig));
	});

	it('produces a self_sig that verifies against the device identity', async () => {
		if (!ed25519Supported) return;

		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();
		const sealed = await x25519Id.getOrCreateX25519Identity(identity);

		const edPub = ed25519.getPublicKey(identity.privateKeySeed!.bytes());
		expect(x25519Id.verifyX25519SelfSig(sealed.pub, sealed.selfSig, edPub)).toBe(true);
	});

	it('pub is the public key of priv', async () => {
		if (!ed25519Supported) return;
		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();
		const sealed = await x25519Id.getOrCreateX25519Identity(identity);
		expect(hex(sealed.pub)).toBe(hex(x25519.getPublicKey(sealed.priv)));
	});
});
