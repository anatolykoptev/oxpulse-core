/**
 * x25519-tofu-recovery.test.ts — S8: tests that a WebCrypto-generated
 * X25519 keypair can be recovered via the noble fallback after a
 * simulated WebCrypto X25519 downgrade, preserving TOFU trust.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { x25519 } from '@noble/curves/ed25519.js';

type DeviceIdentityModule = typeof import('../device-identity.js');

let x25519Supported = false;

beforeAll(async () => {
	try {
		await crypto.subtle.generateKey('X25519', true, ['deriveBits']);
		x25519Supported = true;
	} catch {
		x25519Supported = false;
	}
});

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

async function freshImport(): Promise<DeviceIdentityModule> {
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

beforeEach(() => resetIDB());
afterEach(() => resetIDB());

describe('S8: X25519 TOFU recovery on WebCrypto downgrade (issue #17)', () => {
	it('M1: WebCrypto keypair recovered via noble fallback after downgrade — same pubkey', async () => {
		if (!x25519Supported) return;

		// Step 1: generate keypair with WebCrypto available.
		const mod1 = await freshImport();
		const kp1 = await mod1.getOrCreateX25519Keypair();
		const pub1 = new Uint8Array(kp1.publicKey);

		// Step 2: simulate WebCrypto X25519 downgrade by stubbing
		// crypto.subtle.unwrapKey to throw NotSupportedError for X25519.
		const realUnwrapKey = crypto.subtle.unwrapKey.bind(crypto.subtle);
		vi.spyOn(crypto.subtle, 'unwrapKey').mockImplementation(
			async (_format: string, _key: BufferSource, _wrappingKey: CryptoKey, _wrapAlgo: AlgorithmIdentifier, keyAlgo: KeyAlgorithm, _extractable: boolean, _usages: KeyUsage[]) => {
				// Throw NotSupportedError only for X25519 key imports.
				if (keyAlgo === 'X25519' || (keyAlgo && (keyAlgo as { name?: string }).name === 'X25519')) {
					const err = new Error('X25519 not supported');
					err.name = 'NotSupportedError';
					throw err;
				}
				return realUnwrapKey(_format, _key, _wrappingKey, _wrapAlgo, keyAlgo, _extractable, _usages);
			},
		);

		try {
			// Step 3: reload module — should recover via noble fallback.
			const mod2 = await freshImport();
			const kp2 = await mod2.getOrCreateX25519Keypair();

			// The public key MUST be the same — TOFU trust preserved.
			expect(Array.from(kp2.publicKey)).toEqual(Array.from(pub1));

			// The private key should be loaded as privateKeyBytes (noble path).
			expect(kp2.privateKey).toBeNull();
			expect(kp2.privateKeyBytes).not.toBeNull();
		} finally {
			vi.restoreAllMocks();
		}
	});

	it('M2: recovered keypair produces same shared secret as original', async () => {
		if (!x25519Supported) return;

		// Generate keypair with WebCrypto.
		const mod1 = await freshImport();
		const kp1 = await mod1.getOrCreateX25519Keypair();

		// Generate a remote keypair.
		const remoteSk = x25519.utils.randomSecretKey();
		const remotePub = x25519.getPublicKey(remoteSk);

		// Compute DH with original keypair.
		const shared1 = await mod1.dhX25519(remotePub);

		// Simulate downgrade and reload.
		const realUnwrapKey = crypto.subtle.unwrapKey.bind(crypto.subtle);
		vi.spyOn(crypto.subtle, 'unwrapKey').mockImplementation(
			async (_format: string, _key: BufferSource, _wrappingKey: CryptoKey, _wrapAlgo: AlgorithmIdentifier, keyAlgo: KeyAlgorithm, _extractable: boolean, _usages: KeyUsage[]) => {
				if (keyAlgo === 'X25519' || (keyAlgo && (keyAlgo as { name?: string }).name === 'X25519')) {
					const err = new Error('X25519 not supported');
					err.name = 'NotSupportedError';
					throw err;
				}
				return realUnwrapKey(_format, _key, _wrappingKey, _wrapAlgo, keyAlgo, _extractable, _usages);
			},
		);

		try {
			const mod2 = await freshImport();
			const shared2 = await mod2.dhX25519(remotePub);

			// Same shared secret — the recovered key is functionally identical.
			expect(Array.from(shared2)).toEqual(Array.from(shared1));
		} finally {
			vi.restoreAllMocks();
		}
	});

	it('M3: pre-S8 keypair (no wrappedPrivateKeyRaw) regenerates on downgrade', async () => {
		if (!x25519Supported) return;

		// Generate keypair with WebCrypto.
		const mod1 = await freshImport();
		const kp1 = await mod1.getOrCreateX25519Keypair();

		// Manually strip wrappedPrivateKeyRaw from IDB to simulate pre-S8 storage.
		const { createIdbStore } = await import('../idb-store.js');
		const idb = createIdbStore({ dbName: 'oxpulse-device-id', storeName: 'identity' });
		const X25519_KEYPAIR_NAME = 'x25519-keypair-v1';
		const existing = await idb.load<{ publicKey: ArrayBuffer; wrappedPrivateKey: ArrayBuffer; wrappedPrivateKeyRaw?: ArrayBuffer }>(X25519_KEYPAIR_NAME);
		if (existing) {
			delete existing.wrappedPrivateKeyRaw;
			await idb.save(X25519_KEYPAIR_NAME, existing);
		}

		// Simulate downgrade.
		const realUnwrapKey = crypto.subtle.unwrapKey.bind(crypto.subtle);
		vi.spyOn(crypto.subtle, 'unwrapKey').mockImplementation(
			async (_format: string, _key: BufferSource, _wrappingKey: CryptoKey, _wrapAlgo: AlgorithmIdentifier, keyAlgo: KeyAlgorithm, _extractable: boolean, _usages: KeyUsage[]) => {
				if (keyAlgo === 'X25519' || (keyAlgo && (keyAlgo as { name?: string }).name === 'X25519')) {
					const err = new Error('X25519 not supported');
					err.name = 'NotSupportedError';
					throw err;
				}
				return realUnwrapKey(_format, _key, _wrappingKey, _wrapAlgo, keyAlgo, _extractable, _usages);
			},
		);

		try {
			const mod2 = await freshImport();
			const kp2 = await mod2.getOrCreateX25519Keypair();

			// Without the S8 fix, the keypair is regenerated — different pubkey.
			// This test documents the pre-S8 behavior (regeneration).
			expect(Array.from(kp2.publicKey)).not.toEqual(Array.from(kp1.publicKey));
		} finally {
			vi.restoreAllMocks();
		}
	});
});
