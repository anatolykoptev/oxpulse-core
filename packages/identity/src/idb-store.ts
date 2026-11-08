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

/** One step of an {@link IdbStore.transact} batch. */
export type IdbTxOp =
	| { readonly op: 'put'; readonly key: string; readonly value: unknown }
	| { readonly op: 'delete'; readonly key: string }
	/** Delete every key starting with `prefix` (string keys only). */
	| { readonly op: 'deletePrefix'; readonly prefix: string };

/**
 * Thrown by {@link IdbStore.transact} when its `guard` would be exceeded. The
 * transaction is aborted: nothing was written.
 */
export class IdbCapExceededError extends Error {
	constructor() {
		super('IndexedDB transaction refused: prefix capacity would be exceeded');
		this.name = 'IdbCapExceededError';
	}
}

/** Key range covering exactly the string keys that start with `prefix`. */
function prefixRange(prefix: string): IDBKeyRange {
	return IDBKeyRange.bound(prefix, prefix + '\uffff');
}

export interface IdbStore {
	save<T>(key: string, value: T): Promise<void>;
	/**
	 * Put several entries in ONE readwrite transaction — all land or none do.
	 * Exists for writes whose entries are only valid together (the Ed25519
	 * seed + pubkey record pair, SEC-CR-009): two separate transactions make
	 * a split pair representable, and a split pair signs under an identity
	 * the device does not hold.
	 */
	saveMany(entries: ReadonlyArray<readonly [string, unknown]>): Promise<void>;
	/**
	 * Apply puts and deletes in ONE readwrite transaction — all land or none do.
	 * Every request is issued synchronously, so callers must finish any async
	 * work (WebCrypto wrapping) BEFORE calling: awaiting inside an open IDB
	 * transaction lets it auto-commit.
	 */
	transact(
		ops: ReadonlyArray<IdbTxOp>,
		/**
		 * Capacity checked INSIDE the transaction: the number of records already
		 * under `prefix` plus the puts under it must not exceed `max`, else the
		 * transaction aborts with IdbCapExceededError. This is what makes a cap
		 * hold across tabs and runtimes with no Web Locks, where a read-then-write
		 * check in the caller can be raced.
		 */
		guard?: { prefix: string; max: number },
	): Promise<void>;
	/**
	 * Point-in-time read of several keys plus the key NAMES under a prefix, in ONE
	 * readonly transaction: the answers are mutually consistent, which separate
	 * load() calls are not (a commit can land between them).
	 */
	snapshot(
		keys: ReadonlyArray<string>,
		prefix: string,
		limit?: number,
	): Promise<{ values: unknown[]; prefixKeys: string[] }>;
	/**
	 * Every record whose string key starts with `prefix`, in key order. `limit`
	 * bounds the read itself, so a corrupt store cannot make the caller allocate
	 * an unbounded result.
	 */
	loadPrefix<T>(prefix: string, limit?: number): Promise<Array<{ key: string; value: T }>>;
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

		async saveMany(entries: ReadonlyArray<readonly [string, unknown]>): Promise<void> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readwrite');
				const store = tx.objectStore(storeName);
				try {
					for (const [key, value] of entries) {
						store.put(value, key);
					}
				} catch (err) {
					try { tx.abort(); } catch { /* already aborting */ }
					reject(err);
					return;
				}
				// Resolve on transaction COMPLETION, not per-request success —
				// completion is the atomicity boundary; a request can succeed
				// and the transaction still abort.
				tx.oncomplete = () => resolve();
				tx.onerror = () => reject(tx.error);
				tx.onabort = () => reject(tx.error ?? new DOMException('transaction aborted', 'AbortError'));
			});
		},

		async transact(
			ops: ReadonlyArray<IdbTxOp>,
			guard?: { prefix: string; max: number },
		): Promise<void> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readwrite');
				const store = tx.objectStore(storeName);
				// Completion, not per-request success: see saveMany.
				tx.oncomplete = () => resolve();
				tx.onerror = () => reject(tx.error);
				tx.onabort = () => reject(tx.error ?? new DOMException('transaction aborted', 'AbortError'));
				const abort = (err: unknown) => {
					try { tx.abort(); } catch { /* already aborting */ }
					reject(err);
				};
				const apply = () => {
					try {
						for (const o of ops) {
							if (o.op === 'put') store.put(o.value, o.key);
							else if (o.op === 'delete') store.delete(o.key);
							else store.delete(prefixRange(o.prefix));
						}
					} catch (err) {
						abort(err);
					}
				};
				if (!guard) {
					apply();
					return;
				}
				// Only keys that do not exist yet consume capacity: re-putting a held key
				// (an identical concurrent import) is an overwrite, not growth.
				const putKeys = [
					...new Set(
						ops
							.filter((o): o is Extract<IdbTxOp, { op: 'put' }> => o.op === 'put')
							.map((o) => o.key)
							.filter((k) => k.startsWith(guard.prefix)),
					),
				];
				const counted = store.count(prefixRange(guard.prefix));
				counted.onsuccess = () => {
					const have = counted.result;
					const decide = (adding: number) => {
						if (have + adding > guard.max) abort(new IdbCapExceededError());
						else apply();
					};
					if (putKeys.length === 0) return decide(0);
					let pending = putKeys.length;
					let adding = 0;
					for (const k of putKeys) {
						const probe = store.getKey(k);
						probe.onsuccess = () => {
							if (probe.result === undefined) adding++;
							if (--pending === 0) decide(adding);
						};
					}
				};
			});
		},

		async snapshot(
			keys: ReadonlyArray<string>,
			prefix: string,
			limit?: number,
		): Promise<{ values: unknown[]; prefixKeys: string[] }> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readonly');
				const store = tx.objectStore(storeName);
				const gets = keys.map((k) => store.get(k));
				const names = store.getAllKeys(prefixRange(prefix), limit);
				tx.oncomplete = () =>
					resolve({
						values: gets.map((g) => g.result ?? null),
						prefixKeys: (names.result as IDBValidKey[]).map(String),
					});
				tx.onerror = () => reject(tx.error);
				tx.onabort = () => reject(tx.error ?? new DOMException('transaction aborted', 'AbortError'));
			});
		},

		async loadPrefix<T>(prefix: string, limit?: number): Promise<Array<{ key: string; value: T }>> {
			const db = await openIDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(storeName, 'readonly');
				const store = tx.objectStore(storeName);
				const range = prefixRange(prefix);
				const keysReq = store.getAllKeys(range, limit);
				const valuesReq = store.getAll(range, limit);
				tx.oncomplete = () => {
					const keys = keysReq.result as IDBValidKey[];
					const values = valuesReq.result as T[];
					resolve(keys.map((k, i) => ({ key: String(k), value: values[i] as T })));
				};
				tx.onerror = () => reject(tx.error);
				tx.onabort = () => reject(tx.error ?? new DOMException('transaction aborted', 'AbortError'));
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
