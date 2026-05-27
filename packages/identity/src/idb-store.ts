// Minimal IndexedDB store factory for @oxpulse/identity.
//
// Copied and stripped from web/src/lib/idb-store.ts. The web/ version imports
// tracker.ts (30+ unrelated consumers) for CONN-1.c DataCloneError analytics.
// Since identity cannot depend on web/, this copy omits the analytics — identity
// modules emit their own lifecycle events via tracker-shim.ts instead.
//
// web/src/lib/idb-store.ts stays in web/ (contacts-store, chat-store,
// profile-store, idb-store.test.ts all consume it).
//
// See identity-extraction-adr.md §2.2 for the sole-consumer audit rationale.
//
// WEBVIEW-GUARD: openIDB() calls probeIDBAvailability() before the first
// real open and throws IDBUnavailableError when IDB is absent or broken
// (Instagram/TikTok in-app WebViews). device-identity.ts catches this and
// falls back gracefully rather than propagating an uncaught TypeError at boot.

import { probeIDBAvailability } from './idb-availability.js';
export { IDBUnavailableError } from './idb-errors.js';
import { IDBUnavailableError } from './idb-errors.js';

/** Cache TTL: 5 minutes. Prevents permanent ephemeral state when IDB is only
 *  transiently broken (e.g. WebView memory pressure or transient SecurityError).
 *  After TTL expiry the next assertIDBAvailable() re-probes live. */
const CACHE_TTL_MS = 5 * 60 * 1000;

/** Cached availability result with timestamp for TTL eviction. */
let idbAvailabilityCache: { available: boolean; reason?: string; cachedAt: number } | null = null;

async function assertIDBAvailable(): Promise<void> {
	const now = Date.now();
	if (idbAvailabilityCache !== null && (now - idbAvailabilityCache.cachedAt) < CACHE_TTL_MS) {
		if (!idbAvailabilityCache.available) {
			throw new IDBUnavailableError(
				idbAvailabilityCache.reason as 'no_indexedDB' | 'open_failed' | 'timeout',
			);
		}
		return;
	}
	// Cache absent or expired — re-probe.
	const outcome = await probeIDBAvailability();
	idbAvailabilityCache = outcome.available
		? { available: true, cachedAt: now }
		: { available: false, reason: outcome.reason, cachedAt: now };
	if (!outcome.available) {
		throw new IDBUnavailableError(outcome.reason);
	}
}

/**
 * Reset the cached IDB availability result.
 *
 * TEST ONLY — never call in production. Allows tests that manipulate
 * `globalThis.indexedDB` to re-probe on the next `createIdbStore` call
 * without resetting the entire module registry via `vi.resetModules()`
 * (which would corrupt WebCrypto key contexts across tests).
 */
export function _resetIDBAvailabilityCache(): void {
	idbAvailabilityCache = null;
}

export interface IdbStoreOptions {
	dbName: string;
	storeName: string;
	version?: number; // default 1
}

export interface IdbStore {
	save<T>(key: string, value: T): Promise<void>;
	load<T>(key: string): Promise<T | null>;
	delete(key: string): Promise<void>;
	clear(): Promise<void>;
}

export function createIdbStore(opts: IdbStoreOptions): IdbStore {
	const { dbName, storeName, version = 1 } = opts;

	async function openIDB(): Promise<IDBDatabase> {
		await assertIDBAvailable();
		return new Promise((resolve, reject) => {
			const req = indexedDB.open(dbName, version);
			req.onerror = () => reject(req.error);
			req.onsuccess = () => resolve(req.result);
			req.onupgradeneeded = (ev) => {
				const db = (ev.target as IDBOpenDBRequest).result;
				// Null-guard: broken WebViews (Instagram/TikTok in-app) can fire
				// onupgradeneeded with ev.target.result = null, producing the prod
				// TypeError: "undefined is not an object (evaluating 't.objectStoreNames')".
				// Reject cleanly so the IDBUnavailableError path handles it.
				if (!db) { reject(new DOMException('IDBDatabase result is null', 'UnknownError')); return; }
				if (!db.objectStoreNames.contains(storeName)) {
					db.createObjectStore(storeName);
				}
			};
		});
	}

	return {
		async save<T>(key: string, value: T): Promise<void> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readwrite');
				const store = tx.objectStore(storeName);
				let req: IDBRequest;
				try {
					req = store.put(value, key);
				} catch (err) {
					reject(err);
					return;
				}
				req.onerror = () => reject(req.error);
				req.onsuccess = () => resolve();
			});
		},

		async load<T>(key: string): Promise<T | null> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readonly');
				const store = tx.objectStore(storeName);
				const req = store.get(key);
				req.onerror = () => reject(req.error);
				req.onsuccess = () => resolve(req.result ?? null);
			});
		},

		async delete(key: string): Promise<void> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readwrite');
				const store = tx.objectStore(storeName);
				const req = store.delete(key);
				req.onerror = () => reject(req.error);
				req.onsuccess = () => resolve();
			});
		},

		async clear(): Promise<void> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readwrite');
				const store = tx.objectStore(storeName);
				const req = store.clear();
				req.onerror = () => reject(req.error);
				req.onsuccess = () => resolve();
			});
		},
	};
}
