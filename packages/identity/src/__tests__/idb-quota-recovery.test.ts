/**
 * idb-quota-recovery.test.ts — S9: tests that getOrCreateDeviceIdentity
 * falls back to an ephemeral identity when IDB throws QuotaExceededError,
 * instead of crashing the app.
 */

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

async function freshImport(): Promise<DeviceIdentityModule> {
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

beforeEach(() => resetIDB());
afterEach(() => resetIDB());

describe('S9: IDB quota recovery (issue #18)', () => {
	it('M1: QuotaExceededError on persist → ephemeral identity fallback, no crash', async () => {
		if (!ed25519Supported) return;

		// Mock idb.save to throw QuotaExceededError.
		const { createIdbStore } = await import('../idb-store.js');
		vi.spyOn({ createIdbStore }, 'createIdbStore').mockImplementation(() => {
			const store = createIdbStore({ dbName: 'oxpulse-device-id', storeName: 'identity' });
			vi.spyOn(store, 'save').mockRejectedValue(
				Object.assign(new Error('Quota exceeded'), { name: 'QuotaExceededError' }),
			);
			return store;
		});

		const mod = await freshImport();
		const identity = await mod.getOrCreateDeviceIdentity();

		// App should boot with an ephemeral identity, not crash.
		expect(identity).toBeDefined();
		expect(identity.publicKey).toBeDefined();
	});

	it('M2: QuotaExceededError on load → ephemeral identity fallback, no crash', async () => {
		if (!ed25519Supported) return;

		// Mock idb.load to throw QuotaExceededError.
		const { createIdbStore } = await import('../idb-store.js');
		vi.spyOn({ createIdbStore }, 'createIdbStore').mockImplementation(() => {
			const store = createIdbStore({ dbName: 'oxpulse-device-id', storeName: 'identity' });
			vi.spyOn(store, 'load').mockRejectedValue(
				Object.assign(new Error('Quota exceeded'), { name: 'QuotaExceededError' }),
			);
			return store;
		});

		const mod = await freshImport();
		const identity = await mod.getOrCreateDeviceIdentity();

		// App should boot with an ephemeral identity, not crash.
		expect(identity).toBeDefined();
		expect(identity.publicKey).toBeDefined();
	});
});
