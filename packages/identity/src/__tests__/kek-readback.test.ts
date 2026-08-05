// @vitest-environment jsdom
//
// kek-readback.test.ts — every KEK store must survive a SECOND load, in the
// environment consumers actually run in.
//
// This file is deliberately jsdom while the rest of the package is
// `environment: 'node'` (vitest.config.ts). That is not cosmetic: every defect
// gated here is invisible under node, which binds `CryptoKey` and hands out
// same-realm ArrayBuffers. Simulating a consumer runtime by poking globals
// inside a node test is what let the first attempt at this fix ship a worse bug
// than the one it removed.
//
// PARAMETRISED OVER EVERY STORE, on purpose. The first version of this file
// covered device-identity only, and a review measured that reverting
// room-host-seed.ts to the exact 0.2.0 defect left the whole suite green — the
// code sweep had landed and the test sweep had not. A new KEK store added to
// STORES below inherits all four cases; one added without a STORES entry is the
// failure this shape exists to make hard.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';

interface StoreUnderTest {
	name: string;
	db: string;
	store: string;
	kekKey: string;
	/** Load (creating on first call) whatever this store's KEK protects. */
	load: () => Promise<unknown>;
	/** Stable string identity of that value, for same-across-reload assertions. */
	fingerprint: (v: never) => string;
}

const STORES: StoreUnderTest[] = [
	{
		name: 'device-identity',
		db: 'oxpulse-device-id-kek',
		store: 'kek',
		kekKey: 'wrapping-key',
		load: async () => (await import('../device-identity.js')).getOrCreateDeviceIdentity(),
		fingerprint: (v: { publicKeyB64: string; privateKeySeed: { bytes(): Uint8Array } | null }) =>
			`${v.publicKeyB64}:${Array.from(v.privateKeySeed!.bytes()).join(',')}`,
	},
	{
		name: 'room-host-seed',
		db: 'oxpulse-room-host-seed',
		store: 'seed',
		kekKey: 'wrapping_key',
		load: async () => (await import('../room-host-seed.js')).getOrCreateRoomHostSeed(),
		fingerprint: (v: Uint8Array) => Array.from(v).join(','),
	},
];

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

/**
 * A fresh module graph over the SAME IndexedDB — this is what a page reload is.
 * `cachedWrappingKey` and the structured-clone probe are module-level in every
 * store, so resetting modules WITHOUT resetting IDB is the only way to reach the
 * load-an-existing-KEK branch at all.
 */
function reload(): void {
	vi.resetModules();
}

/** Write straight into a KEK store, bypassing the module under test. */
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

describe.each(STORES)('KEK read-back — $name (#108)', (S) => {
	// No `if (!ed25519Supported) return` guard anywhere in this file, on purpose.
	// That pattern records a PASS having asserted nothing, and it fires exactly
	// on the runtimes this package's noble fallback exists for. Measured: with
	// WebCrypto Ed25519 forced to throw, every assertion below still holds.

	it('reloads an existing CryptoKey KEK with NO global CryptoKey binding', async () => {
		reload();
		const before = S.fingerprint((await S.load()) as never);

		// The #108 trigger: a runtime with crypto.subtle and structuredClone but
		// no CryptoKey constructor bound. Observed for real in oxpulse-chat's
		// vitest (jsdom 29.1.1); this repo's jsdom does bind it, so the binding
		// is removed explicitly rather than assumed absent.
		const savedCtor = (globalThis as Record<string, unknown>).CryptoKey;
		delete (globalThis as Record<string, unknown>).CryptoKey;
		try {
			reload();
			const after = S.fingerprint((await S.load()) as never);
			// Byte equality, not merely non-null: a silently re-minted secret
			// would also be non-null, and that is the failure being excluded.
			expect(after).toBe(before);
		} finally {
			(globalThis as Record<string, unknown>).CryptoKey = savedCtor;
		}
	});

	it('reloads a RAW-BYTES KEK across a realm boundary', async () => {
		// Forces the structured-clone fallback so the KEK is persisted as raw
		// bytes, then reads it back. Under jsdom those bytes fail
		// `instanceof ArrayBuffer` — crypto.subtle returns a Node-realm buffer
		// while the global is jsdom's — so a discriminator built on `instanceof`
		// classifies a perfectly readable KEK as a CryptoKey and the secret
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
			reload();
			const before = S.fingerprint((await S.load()) as never);
			reload();
			const after = S.fingerprint((await S.load()) as never);
			expect(after).toBe(before);
		} finally {
			globalThis.structuredClone = savedClone;
		}
	});

	it('refuses a KEK entry that is neither shape', async () => {
		// The classifier validates the CryptoKey side POSITIVELY rather than by
		// elimination, so a corrupted or unexpected entry fails at the KEK layer
		// with a name that says so — instead of being cached as a key handle for
		// the rest of the process and resurfacing later as `unwrap_failed`.
		await idbPut(S.db, S.store, S.kekKey, { not: 'a key' });
		reload();
		await expect(S.load()).rejects.toThrow(/neither an AES-KW CryptoKey nor raw bytes/);
	});

	it('refuses an AES-KW CryptoKey that is EXTRACTABLE', async () => {
		// #95's whole point. An extractable KEK in the store means a downgrade or
		// tampering; accepting it would silently undo the guarantee that
		// non-extractable generation exists to provide.
		const extractable = await crypto.subtle.generateKey(
			{ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey'],
		);
		await idbPut(S.db, S.store, S.kekKey, extractable);
		reload();
		await expect(S.load()).rejects.toThrow(/neither an AES-KW CryptoKey nor raw bytes/);
	});

	// NOTE — a further defect was hypothesised for the old line: that `canClone`
	// (a WRITE-capability probe) gating a READ would mishandle a stored CryptoKey
	// after a WebView downgrade. Measured, that case is NOT reachable: IndexedDB
	// structured-clones on read too, so a runtime that cannot clone a CryptoKey
	// cannot return one either — the load rejects first, which is the honest
	// "unreadable KEK" hard error the docstring already promises. Recorded here
	// rather than as a test that would pass vacuously.
});
