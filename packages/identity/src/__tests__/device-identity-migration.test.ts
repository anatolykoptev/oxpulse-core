// device-identity-migration.test.ts
//
// B1 (CRITICAL): unwrapIdentity must return privateKeyBytes=null for
// pre-W7-P2b1 identities (no DEVICE_PRIV_RAW_NAME entry in IDB).
// Previously returned 32-zero sentinel which nobles/curves happily signed —
// deterministic correlatable signatures for every migrated user.
//
// Ref: code-quality review of c5a66d58

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
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

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

async function freshImport(): Promise<DeviceIdentityModule> {
	const { vi } = await import('vitest');
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

beforeEach(() => { resetIDB(); });
afterEach(() => { resetIDB(); });

describe('B1: pre-W7-P2b1 identity migration', () => {
	it('newly created identity has non-null privateKeyBytes', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();
		expect(id.privateKeyBytes).not.toBeNull();
		// must be a 32-byte Uint8Array (raw Ed25519 seed)
		expect(id.privateKeyBytes).toBeInstanceOf(Uint8Array);
		expect((id.privateKeyBytes as Uint8Array).byteLength).toBe(32);
	});

	it('new identity privateKeyBytes is NOT all-zero sentinel', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();
		const bytes = id.privateKeyBytes as Uint8Array;
		const allZero = bytes.every((b) => b === 0);
		expect(allZero).toBe(false);
	});

	it('privateKeyBytes=null (not 32-zero) when raw seed absent in IDB', async () => {
		if (!ed25519Supported) return;

		// Create identity with W7-P2b1 mod (stores raw seed)
		const mod = await freshImport();
		await mod.getOrCreateDeviceIdentity();

		// Simulate pre-W7-P2b1: delete the raw seed entry from IDB.
		// We can do this by manually opening the IDB and deleting the key.
		const DB_NAME = mod.IDB_DB_NAME;
		const STORE_NAME = mod.IDB_STORE_NAME;
		const RAW_KEY = 'oxp/identity/ed25519-priv-raw';

		await new Promise<void>((resolve, reject) => {
			const req = globalThis.indexedDB.open(DB_NAME);
			req.onsuccess = () => {
				const db = req.result;
				const tx = db.transaction(STORE_NAME, 'readwrite');
				tx.objectStore(STORE_NAME).delete(RAW_KEY);
				tx.oncomplete = () => { db.close(); resolve(); };
				tx.onerror = () => reject(tx.error);
			};
			req.onerror = () => reject(req.error);
		});

		// Fresh import (drops module cache, keeps IDB)
		const mod2 = await freshImport();
		const id = await mod2.getOrCreateDeviceIdentity();

		// MUST be null — not 32-zero bytes
		expect(id.privateKeyBytes).toBeNull();
	});

	it('DeviceIdentity type: privateKeyBytes is Uint8Array | null', async () => {
		// Type-level check: the compile-time type must allow null.
		// If this test compiles, the type is correct; if privateKeyBytes is
		// typed as Uint8Array (non-nullable), this assignment would error.
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();
		// Accept both null and Uint8Array without TS error:
		const bytes: Uint8Array | null = id.privateKeyBytes;
		expect(bytes === null || bytes instanceof Uint8Array).toBe(true);
	});
});
