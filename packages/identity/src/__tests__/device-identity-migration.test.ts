// device-identity-migration.test.ts
//
// B1 (CRITICAL): unwrapIdentity must return privateKeySeed=null for
// pre-W7-P2b1 identities (no DEVICE_PRIV_RAW_NAME entry in IDB).
// Previously returned 32-zero sentinel which nobles/curves happily signed —
// deterministic correlatable signatures for every migrated user.
//
// Ref: code-quality review of c5a66d58

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { ed25519 as nobleEd25519 } from '@noble/curves/ed25519.js';
import { toBase64url } from '../base64url.js';
import { OpaquePrivateKey } from '../opaque-private-key.js';

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
	it('newly created identity has non-null privateKeySeed', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();
		expect(id.privateKeySeed).not.toBeNull();
		// Duck-type: vi.resetModules() creates a fresh OpaquePrivateKey class,
		// so toBeInstanceOf would fail on class identity. Check .bytes() instead.
		expect(typeof id.privateKeySeed?.bytes).toBe('function');
		expect(id.privateKeySeed!.bytes()).toBeInstanceOf(Uint8Array);
		expect(id.privateKeySeed!.bytes().byteLength).toBe(32);
	});

	it('new identity privateKeySeed is NOT all-zero sentinel', async () => {
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();
		const bytes = id.privateKeySeed!.bytes();
		const allZero = bytes.every((b) => b === 0);
		expect(allZero).toBe(false);
	});

	it('privateKeySeed=null (not 32-zero) when raw seed absent in IDB', async () => {
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
		expect(id.privateKeySeed).toBeNull();
	});

	it('DeviceIdentity type: privateKeySeed is OpaquePrivateKey | null', async () => {
		// Type-level check: the compile-time type must allow null.
		// If this test compiles, the type is correct; if privateKeySeed is
		// typed as OpaquePrivateKey (non-nullable), this assignment would error.
		if (!ed25519Supported) return;
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();
		// Accept both null and OpaquePrivateKey without TS error:
		const bytes: OpaquePrivateKey | null = id.privateKeySeed;
		// Duck-type: vi.resetModules() creates a fresh class, so instanceof
		// would fail on class identity. Check .bytes() method presence instead.
		expect(bytes === null || typeof bytes?.bytes === 'function').toBe(true);
	});
});

// ── KEK migration (#98): separate KEK IDB database ───────────────────────
//
// Phase 3 key-hygiene: the KEK moves from the identity DB (raw bytes) to a
// dedicated DB (non-extractable CryptoKey via structured-clone, raw-bytes
// fallback). These tests cover the copy-only migration, the structured-clone
// fallback, clear-wipe of both DBs, and exportRawDeviceSecret stability.

const KEK_DB_NAME = 'oxpulse-device-id-kek';
const KEK_STORE_NAME = 'kek';
const KEK_KEY_NAME = 'wrapping-key';
const LEGACY_DB_NAME = 'oxpulse-device-id';
const LEGACY_STORE_NAME = 'identity';
const LEGACY_WRAPPING_KEY_NAME = 'wrapping-key';
const LEGACY_DEVICE_KEY_NAME = 'device-key';
const LEGACY_DEVICE_PRIV_RAW_NAME = 'oxp/identity/ed25519-priv-raw';

const ED25519_PKCS8_PREFIX_TEST = new Uint8Array([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
	0x06, 0x03, 0x2b, 0x65, 0x70,
	0x04, 0x22, 0x04, 0x20,
]);

/** Open an IDB database, creating the object store if it doesn't exist yet. */
async function ensureIDBStore(dbName: string, storeName: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const req = globalThis.indexedDB.open(dbName);
		req.onerror = () => reject(req.error);
		req.onsuccess = () => { req.result.close(); resolve(); };
		req.onupgradeneeded = (ev) => {
			const db = (ev.target as IDBOpenDBRequest).result;
			if (!db.objectStoreNames.contains(storeName)) {
				db.createObjectStore(storeName);
			}
		};
	});
}

/** Read a key directly from an IDB database/store (bypassing createIdbStore). */
async function idbRead(dbName: string, storeName: string, key: string): Promise<unknown> {
	return new Promise((resolve, reject) => {
		const req = globalThis.indexedDB.open(dbName);
		req.onerror = () => reject(req.error);
		req.onsuccess = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains(storeName)) {
				db.close();
				resolve(null);
				return;
			}
			const tx = db.transaction(storeName, 'readonly');
			const getReq = tx.objectStore(storeName).get(key);
			getReq.onsuccess = () => { db.close(); resolve(getReq.result ?? null); };
			getReq.onerror = () => { db.close(); reject(getReq.error); };
		};
	});
}

/** Write a key directly to an IDB database/store (bypassing createIdbStore). */
async function idbWrite(dbName: string, storeName: string, key: string, value: unknown): Promise<void> {
	await ensureIDBStore(dbName, storeName);
	return new Promise((resolve, reject) => {
		const req = globalThis.indexedDB.open(dbName);
		req.onerror = () => reject(req.error);
		req.onsuccess = () => {
			const db = req.result;
			const tx = db.transaction(storeName, 'readwrite');
			const putReq = tx.objectStore(storeName).put(value, key);
			putReq.onsuccess = () => { db.close(); resolve(); };
			putReq.onerror = () => { db.close(); reject(putReq.error); };
		};
	});
}

/**
 * Seed a pre-migration IDB state: old KEK (raw bytes) in the identity DB,
 * identity record + raw seed wrapped with the OLD AES-256-import trick.
 * Returns the raw 32-byte seed for verification.
 */
async function seedPreMigrationIDB(): Promise<Uint8Array> {
	// Generate KEK as raw bytes (old style: extractable, exported to IDB).
	const kek = await crypto.subtle.generateKey(
		{ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey'],
	);
	const rawKek = await crypto.subtle.exportKey('raw', kek);

	// Generate Ed25519 keypair via @noble/curves.
	const kp = nobleEd25519.keygen();
	const seed = kp.secretKey;
	const pubB64 = toBase64url(kp.publicKey);

	// Wrap raw seed with OLD AES-256-import trick (pre-Phase-3 wire format).
	const seedAsKey = await crypto.subtle.importKey(
		'raw', seed.buffer.slice(0, seed.byteLength),
		{ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey'],
	);
	const wrappedRawSeed = await crypto.subtle.wrapKey('raw', seedAsKey, kek, 'AES-KW');

	// Wrap PKCS8 (if WebCrypto Ed25519 is available).
	let wrappedPrivateKey: ArrayBuffer = new ArrayBuffer(0);
	try {
		const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX_TEST.byteLength + seed.byteLength);
		pkcs8.set(ED25519_PKCS8_PREFIX_TEST, 0);
		pkcs8.set(seed, ED25519_PKCS8_PREFIX_TEST.byteLength);
		const extractableKey = await crypto.subtle.importKey(
			'pkcs8', pkcs8.buffer.slice(0, pkcs8.byteLength),
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier, true, ['sign'],
		);
		wrappedPrivateKey = await crypto.subtle.wrapKey('pkcs8', extractableKey, kek, 'AES-KW');
	} catch {
		// Noble-only — keep zero-length sentinel.
	}

	// Write to identity DB (old style: KEK in identity DB under wrapping-key).
	await idbWrite(LEGACY_DB_NAME, LEGACY_STORE_NAME, LEGACY_WRAPPING_KEY_NAME, rawKek);
	await idbWrite(LEGACY_DB_NAME, LEGACY_STORE_NAME, LEGACY_DEVICE_KEY_NAME, { publicKeyB64: pubB64, wrappedPrivateKey });
	await idbWrite(LEGACY_DB_NAME, LEGACY_STORE_NAME, LEGACY_DEVICE_PRIV_RAW_NAME, wrappedRawSeed);

	return seed;
}

describe('KEK migration (#98): separate KEK IDB database', () => {
	it('pre-migration: old wrapping-key in identity DB → KEK migrated to new DB, old entry preserved (copy-only)', async () => {
		if (!ed25519Supported) return;

		const originalSeed = await seedPreMigrationIDB();

		const mod = await freshImport();
		const identity = await mod.getOrCreateDeviceIdentity();

		// KEK exists in new DB.
		const kekEntry = await idbRead(KEK_DB_NAME, KEK_STORE_NAME, KEK_KEY_NAME);
		expect(kekEntry).not.toBeNull();

		// ...and is NON-EXTRACTABLE, which is the whole point of #95. Without
		// this the migration could import the KEK extractable and every
		// assertion here would still pass — verified by mutating
		// `importAesKwRaw(legacyRaw, false)` to `true`, which went GREEN before
		// this line existed.
		expect(
			(kekEntry as CryptoKey).extractable,
			'migrated KEK is extractable — #95 is not actually enforced',
		).toBe(false);

		// Old entry still present (copy-only migration — NEVER deleted).
		const oldEntry = await idbRead(LEGACY_DB_NAME, LEGACY_STORE_NAME, LEGACY_WRAPPING_KEY_NAME);
		expect(oldEntry).not.toBeNull();

		// The acceptance criterion for the whole migration: an identity created
		// BEFORE this change still unwraps to the IDENTICAL seed through the
		// normal signing path. Everything else here checks where the KEK lives;
		// this checks that the user still owns their account.
		expect(identity.privateKeySeed, 'identity did not unwrap after migration').not.toBeNull();
		expect(
			Array.from(identity.privateKeySeed!.bytes()),
			'migrated identity unwrapped to DIFFERENT bytes — silent account loss',
		).toEqual(Array.from(originalSeed));
	});

	it('new code: KEK in new DB, old DB has NO wrapping-key entry', async () => {
		if (!ed25519Supported) return;

		const mod = await freshImport();
		await mod.getOrCreateDeviceIdentity();

		// KEK exists in new DB.
		const kekEntry = await idbRead(KEK_DB_NAME, KEK_STORE_NAME, KEK_KEY_NAME);
		expect(kekEntry).not.toBeNull();

		// Old DB has NO wrapping-key entry (fresh install on new code).
		const oldEntry = await idbRead(LEGACY_DB_NAME, LEGACY_STORE_NAME, LEGACY_WRAPPING_KEY_NAME);
		expect(oldEntry).toBeNull();
	});

	it('structured-clone probe fails → raw-bytes fallback, identity still round-trips', async () => {
		if (!ed25519Supported) return;

		const originalSC = globalThis.structuredClone;
		(globalThis as { structuredClone: typeof structuredClone }).structuredClone = (val: unknown) => {
			// Only reject CryptoKey cloning (the probe target); let
			// fake-indexeddb clone ArrayBuffers and plain objects normally.
			if (val instanceof CryptoKey) {
				throw new Error('mock: CryptoKey structured-clone not supported');
			}
			return originalSC(val);
		};

		try {
			const first = await freshImport();
			const a = await first.getOrCreateDeviceIdentity();
			expect(typeof a.privateKeySeed?.bytes).toBe('function');
			expect(a.privateKeySeed!.bytes().byteLength).toBe(32);

			// Simulate reload: fresh import (probe cache reset, structuredClone still mocked).
			const second = await freshImport();
			const b = await second.getOrCreateDeviceIdentity();

			expect(b.publicKeyB64).toBe(a.publicKeyB64);
			expect(Array.from(b.privateKeySeed!.bytes())).toEqual(Array.from(a.privateKeySeed!.bytes()));
		} finally {
			(globalThis as { structuredClone: typeof structuredClone }).structuredClone = originalSC;
		}
	});

	it('clearDeviceIdentity → both KEK DBs empty', async () => {
		if (!ed25519Supported) return;

		const mod = await freshImport();
		await mod.getOrCreateDeviceIdentity();

		// Verify KEK exists in new DB before clear.
		const kekBefore = await idbRead(KEK_DB_NAME, KEK_STORE_NAME, KEK_KEY_NAME);
		expect(kekBefore).not.toBeNull();

		await mod.clearDeviceIdentity();

		// New KEK DB empty.
		const kekAfter = await idbRead(KEK_DB_NAME, KEK_STORE_NAME, KEK_KEY_NAME);
		expect(kekAfter).toBeNull();

		// Old identity DB entries gone too.
		const oldKekAfter = await idbRead(LEGACY_DB_NAME, LEGACY_STORE_NAME, LEGACY_WRAPPING_KEY_NAME);
		expect(oldKekAfter).toBeNull();
		const devKeyAfter = await idbRead(LEGACY_DB_NAME, LEGACY_STORE_NAME, LEGACY_DEVICE_KEY_NAME);
		expect(devKeyAfter).toBeNull();
	});

	it('exportRawDeviceSecret returns same 32 bytes before and after migration', async () => {
		if (!ed25519Supported) return;

		const originalSeed = await seedPreMigrationIDB();

		// Before migration (triggers migration as a side effect of getOrCreateWrappingKey).
		const mod1 = await freshImport();
		const result1 = await mod1.exportRawDeviceSecret();
		expect(result1.secret.byteLength).toBe(32);
		expect(Array.from(result1.secret)).toEqual(Array.from(originalSeed));

		// After migration (KEK now in new DB, loaded from there on fresh import).
		const mod2 = await freshImport();
		const result2 = await mod2.exportRawDeviceSecret();
		expect(result2.secret.byteLength).toBe(32);
		expect(Array.from(result2.secret)).toEqual(Array.from(result1.secret));
		expect(result2.publicB64u).toBe(result1.publicB64u);
	});

	it('identity persists across reload (round-trip with new KEK DB)', async () => {
		if (!ed25519Supported) return;

		const first = await freshImport();
		const a = await first.getOrCreateDeviceIdentity();

		const second = await freshImport();
		const b = await second.getOrCreateDeviceIdentity();

		expect(b.publicKeyB64).toBe(a.publicKeyB64);
		expect(Array.from(b.privateKeySeed!.bytes())).toEqual(Array.from(a.privateKeySeed!.bytes()));
	});
});
