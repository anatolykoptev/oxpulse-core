// @vitest-environment jsdom
//
// kek-readback.test.ts — the KEK must survive a SECOND load, in the environment
// consumers actually run in.
//
// This file is deliberately jsdom while the rest of the package is
// `environment: 'node'` (vitest.config.ts). That is not cosmetic: every defect
// this file gates is invisible under node, because node binds `CryptoKey` and
// hands out same-realm ArrayBuffers. Simulating a consumer runtime by poking
// globals inside a node test is what let the first attempt at this fix ship a
// worse bug than the one it removed.
//
// Deleting the legacy-KEK migration in #104 removed the only test that loaded an
// EXISTING KEK; everything left asserts the creation path, which is the branch
// that works. See #108.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';

type DeviceIdentityModule = typeof import('../device-identity.js');

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

/**
 * A fresh module graph over the SAME IndexedDB — this is what a page reload is.
 * `cachedWrappingKey` and the structured-clone probe are module-level, so
 * resetting modules WITHOUT resetting IDB is the only way to reach the
 * load-an-existing-KEK branch at all.
 */
async function reload(): Promise<DeviceIdentityModule> {
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

const KEK_DB_NAME = 'oxpulse-device-id-kek';
const KEK_STORE_NAME = 'kek';
const KEK_KEY_NAME = 'wrapping-key';

/** Write straight into the KEK store, bypassing the module under test. */
function idbPut(dbName: string, storeName: string, key: string, value: unknown): Promise<void> {
	return new Promise((resolve, reject) => {
		const open = globalThis.indexedDB.open(dbName, 1);
		open.onupgradeneeded = () => {
			if (!open.result.objectStoreNames.contains(storeName)) {
				open.result.createObjectStore(storeName);
			}
		};
		open.onerror = () => reject(open.error);
		open.onsuccess = () => {
			const db = open.result;
			const tx = db.transaction(storeName, 'readwrite');
			tx.objectStore(storeName).put(value as never, key);
			tx.oncomplete = () => { db.close(); resolve(); };
			tx.onerror = () => { db.close(); reject(tx.error); };
		};
	});
}

beforeEach(() => { resetIDB(); });
afterEach(() => { resetIDB(); });

describe('KEK read-back (#108)', () => {
	// No `if (!ed25519Supported) return` guard here, on purpose. That pattern
	// records a PASS having asserted nothing, and it fires exactly on the
	// runtimes this package's noble fallback exists for. Measured: with
	// WebCrypto Ed25519 forced to throw, every assertion below still holds —
	// generateDeviceIdentity takes both the public key and the seed from noble
	// and only *tries* the WebCrypto import inside a catch.

	it('reloads an existing CryptoKey KEK with NO global CryptoKey binding', async () => {
		const first = await reload();
		const before = await first.getOrCreateDeviceIdentity();

		// The #108 trigger: a runtime with crypto.subtle and structuredClone but
		// no CryptoKey constructor bound. Observed for real in oxpulse-chat's
		// vitest (jsdom 29.1.1); this repo's jsdom does bind it, so the binding
		// is removed explicitly rather than assumed absent.
		const savedCtor = (globalThis as Record<string, unknown>).CryptoKey;
		delete (globalThis as Record<string, unknown>).CryptoKey;
		try {
			const second = await reload();
			const after = await second.getOrCreateDeviceIdentity();
			expect(after.publicKeyB64).toBe(before.publicKeyB64);
			// Byte equality, not just non-null: a re-minted identity would also
			// be non-null, and that is the failure this test exists to exclude.
			expect(after.privateKeySeed).not.toBeNull();
			expect(Array.from(after.privateKeySeed!.bytes()))
				.toEqual(Array.from(before.privateKeySeed!.bytes()));
		} finally {
			(globalThis as Record<string, unknown>).CryptoKey = savedCtor;
		}
	});

	it('reloads a RAW-BYTES KEK across a realm boundary', async () => {
		// Forces the structured-clone fallback so the KEK is persisted as raw
		// bytes, then reads it back. Under jsdom those bytes fail
		// `instanceof ArrayBuffer` — crypto.subtle returns a Node-realm buffer
		// while the global is jsdom's — so a discriminator built on `instanceof`
		// classifies a perfectly readable KEK as a CryptoKey and the identity
		// becomes undecryptable. Measured before this assertion existed:
		//   TypeError: 'unwrapKey' 3rd argument is not of type CryptoKey
		const savedClone = globalThis.structuredClone;
		const isCryptoKey = (v: unknown) =>
			Object.prototype.toString.call(v) === '[object CryptoKey]';
		globalThis.structuredClone = ((v: unknown, opts?: unknown) => {
			// Reject only CryptoKey, the way a WebView without CryptoKey
			// structured-clone does. Everything else must still clone, or IDB
			// itself stops working and the test would pass for the wrong reason.
			if (isCryptoKey(v)) throw new Error('cannot clone CryptoKey');
			return (savedClone as (a: unknown, b?: unknown) => unknown)(v, opts);
		}) as typeof structuredClone;

		try {
			const first = await reload();
			const before = await first.getOrCreateDeviceIdentity();

			const second = await reload();
			const after = await second.getOrCreateDeviceIdentity();

			expect(after.publicKeyB64).toBe(before.publicKeyB64);
			expect(Array.from(after.privateKeySeed!.bytes()))
				.toEqual(Array.from(before.privateKeySeed!.bytes()));
		} finally {
			globalThis.structuredClone = savedClone;
		}
	});

	it('refuses to cache a KEK entry that is neither shape', async () => {
		// The classifier validates the CryptoKey side POSITIVELY rather than by
		// elimination, so a corrupted or unexpected entry fails at the KEK layer
		// with a name that says so — instead of being cached as a key handle for
		// the rest of the process and resurfacing later as `unwrap_failed`.
		//
		// Added because the mutation matrix caught this: replacing the positive
		// validation with a bare `existing as CryptoKey` SURVIVED the rest of
		// this file. Untested validation is decoration.
		await idbPut(KEK_DB_NAME, KEK_STORE_NAME, KEK_KEY_NAME, { not: 'a key' });

		const mod = await reload();
		await expect(mod.getOrCreateDeviceIdentity()).rejects.toThrow(
			/neither an AES-KW CryptoKey nor raw bytes/,
		);
	});

	it('refuses an AES-KW CryptoKey that is EXTRACTABLE', async () => {
		// #95's whole point. An extractable KEK in the store means either a
		// downgrade or tampering; accepting it would silently undo the guarantee
		// the non-extractable generation exists to provide.
		const extractable = await crypto.subtle.generateKey(
			{ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey'],
		);
		await idbPut(KEK_DB_NAME, KEK_STORE_NAME, KEK_KEY_NAME, extractable);

		const mod = await reload();
		await expect(mod.getOrCreateDeviceIdentity()).rejects.toThrow(
			/neither an AES-KW CryptoKey nor raw bytes/,
		);
	});

	// NOTE — a further defect was hypothesised for the old line: that `canClone`
	// (a WRITE-capability probe) gating a READ would mishandle a stored CryptoKey
	// after a WebView downgrade. Measured, that case is NOT reachable: IndexedDB
	// structured-clones on read too, so a runtime that cannot clone a CryptoKey
	// cannot return one either — the load rejects first, which is the honest
	// "unreadable KEK" hard error the docstring already promises. Recorded here
	// rather than as a test that would pass vacuously.
});
