/**
 * spool.ts — B.3 mailbox primitive (consumed by B.4 gossip).
 *
 * IndexedDB-backed store of bundles held for forwarding to peers we have
 * not yet encountered. Distinct from outbox (locally-originated, addressed
 * to "the mesh") and inbox (received and pending local consume).
 *
 * Schema per entry:
 *   msgId          string      primary key
 *   channelId      Uint8Array  4 B
 *   bundle         Uint8Array  wire bytes
 *   addedAtMs      number      wall-clock ms when first spooled
 *   hopsRemaining  number      decrements on each forward; 0 = drop
 *
 * Bounded storage: put() enforces MESH_SPOOL_MAX_ENTRIES atomically —
 * count + evict-oldest + put in a single readwrite transaction.
 * QuotaExceededError triggers aggressive eviction + retry.
 *
 * Eviction:
 * - wall-time TTL via addedAtMs (typical 7 days, caller-supplied)
 * - hop budget via decrementHops() — auto-removes at 0
 * - entry-count cap via bounded put() (MESH_SPOOL_MAX_ENTRIES)
 */

import { MESH_SPOOL_MAX_ENTRIES } from '../constants.generated.js';
import { emitMeshMetric } from '../metrics.js';

export interface SpoolEntry {
  msgId: string;
  channelId: Uint8Array;
  bundle: Uint8Array;
  addedAtMs: number;
  hopsRemaining: number;
}

export const MESH_SPOOL_DB_NAME = 'mesh-router-spool';
export const MESH_SPOOL_STORE_NAME = 'spool';

const DB_VERSION = 1;

/**
 * Fraction of maxEntries to evict on QuotaExceededError before retry.
 */
const QUOTA_EVICT_FRACTION = 0.1;

export class Spool {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;
  private readonly maxEntries: number;

  constructor(dbName = MESH_SPOOL_DB_NAME, maxEntries = MESH_SPOOL_MAX_ENTRIES) {
    this.dbName = dbName;
    this.maxEntries = maxEntries;
  }

  open(): Promise<void> {
    if (this.db) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, DB_VERSION);
      req.onupgradeneeded = (ev) => {
        const db = (ev.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(MESH_SPOOL_STORE_NAME)) {
          const store = db.createObjectStore(MESH_SPOOL_STORE_NAME, { keyPath: 'msgId' });
          store.createIndex('addedAtMs', 'addedAtMs', { unique: false });
        }
      };
      req.onsuccess = (ev) => {
        this.db = (ev.target as IDBOpenDBRequest).result;
        resolve();
      };
      req.onerror = () => reject(req.error);
    });
  }

  close(): void {
    this.db?.close();
    this.db = null;
  }

  private getDb(): IDBDatabase {
    if (!this.db) throw new Error('Spool: call open() first');
    return this.db;
  }

  /**
   * Insert an entry, atomically enforcing the maxEntries cap.
   *
   * Count + evict-oldest + put in a single readwrite transaction.
   * On QuotaExceededError: aggressively evict 10% of maxEntries and retry once.
   */
  put(entry: SpoolEntry): Promise<void> {
    return this.putBounded(entry, false);
  }

  private putBounded(entry: SpoolEntry, isRetry: boolean): Promise<void> {
    return new Promise((resolve, reject) => {
      const db = this.getDb();
      const tx = db.transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_SPOOL_STORE_NAME);

      const countReq = store.count();
      countReq.onsuccess = () => {
        const total = countReq.result;
        const toEvict = total >= this.maxEntries ? total - this.maxEntries + 1 : 0;

        if (toEvict === 0) {
          const putReq = store.put(entry);
          putReq.onsuccess = () => resolve();
          putReq.onerror = () => reject(putReq.error);
          return;
        }

        const index = store.index('addedAtMs');
        const cursorReq = index.openCursor(); // ascending = oldest first
        let evicted = 0;
        cursorReq.onsuccess = (ev) => {
          const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
          if (!cursor || evicted >= toEvict) {
            const putReq = store.put(entry);
            putReq.onsuccess = () => {
              emitMeshMetric('mailbox_evicted', { store: 'spool', count: String(evicted) });
              resolve();
            };
            putReq.onerror = () => reject(putReq.error);
            return;
          }
          cursor.delete();
          evicted++;
          cursor.continue();
        };
        cursorReq.onerror = () => reject(cursorReq.error);
      };
      countReq.onerror = () => reject(countReq.error);

      tx.onerror = () => {
        const error = tx.error;
        if (error && error.name === 'QuotaExceededError' && !isRetry) {
          emitMeshMetric('mailbox_quota_exceeded', { store: 'spool' });
          this.evictAggressive(Math.max(1, Math.floor(this.maxEntries * QUOTA_EVICT_FRACTION)))
            .then(() => this.putBounded(entry, true))
            .then(resolve, reject);
        } else {
          reject(error || new Error('Spool: transaction aborted'));
        }
      };
      tx.onabort = () => {
        const error = tx.error;
        if (error && error.name === 'QuotaExceededError' && !isRetry) {
          emitMeshMetric('mailbox_quota_exceeded', { store: 'spool' });
          this.evictAggressive(Math.max(1, Math.floor(this.maxEntries * QUOTA_EVICT_FRACTION)))
            .then(() => this.putBounded(entry, true))
            .then(resolve, reject);
        } else {
          reject(error || new Error('Spool: transaction aborted'));
        }
      };
    });
  }

  private evictAggressive(count: number): Promise<number> {
    return new Promise((resolve, reject) => {
      const db = this.getDb();
      const tx = db.transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const index = tx.objectStore(MESH_SPOOL_STORE_NAME).index('addedAtMs');
      const req = index.openCursor();
      let deleted = 0;
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor || deleted >= count) {
          if (deleted > 0) emitMeshMetric('mailbox_evicted', { store: 'spool', count: String(deleted) });
          resolve(deleted);
          return;
        }
        cursor.delete();
        deleted++;
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  /**
   * Return up to `limit` most-recent entries via bounded cursor walk (NOT getAll).
   *
   * Walks the addedAtMs index in DESCENDING order (newest first) and collects
   * up to `limit` entries. This replaces the previous all() which used getAll()
   * and loaded the entire store into memory (S5 fix). Default limit matches
   * MESH_SPOOL_MAX_ENTRIES for backward compatibility, but callers SHOULD pass
   * a smaller limit (e.g. 100) for gossip forwarding.
   */
  recent(limit: number = MESH_SPOOL_MAX_ENTRIES): Promise<SpoolEntry[]> {
    if (limit < 0) throw new Error('Spool: recent limit must be >= 0');
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readonly');
      const index = tx.objectStore(MESH_SPOOL_STORE_NAME).index('addedAtMs');
      const req = index.openCursor(null, 'prev'); // descending = newest first
      const results: SpoolEntry[] = [];
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor || results.length >= limit) { resolve(results); return; }
        results.push(cursor.value as SpoolEntry);
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  /**
   * Return ALL entries via cursor walk.
   *
   * @deprecated Use recent(limit) for gossip forwarding to avoid loading
   * the entire store into memory. This method is retained for backward
   * compatibility and tests, but should not be used in production paths
   * where the store may be large.
   */
  all(): Promise<SpoolEntry[]> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readonly');
      const req = tx.objectStore(MESH_SPOOL_STORE_NAME).getAll();
      req.onsuccess = () => resolve(req.result as SpoolEntry[]);
      req.onerror = () => reject(req.error);
    });
  }

  size(): Promise<number> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readonly');
      const req = tx.objectStore(MESH_SPOOL_STORE_NAME).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  remove(msgId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const req = tx.objectStore(MESH_SPOOL_STORE_NAME).delete(msgId);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  /**
   * Decrement hopsRemaining by 1. If the result is zero or negative,
   * delete the entry (forwarded its budget worth).
   *
   * B5: uses cursor.update() / cursor.delete() for atomic read-modify-write.
   * The cursor holds the record lock within the transaction — concurrent
   * decrementHops calls for the same msgId are serialized by IDB's
   * readwrite transaction locking. No caller-side mutex needed.
   */
  decrementHops(msgId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_SPOOL_STORE_NAME);
      const cursorReq = store.openCursor(IDBKeyRange.only(msgId));
      cursorReq.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor) { resolve(); return; }
        const entry = cursor.value as SpoolEntry;
        const next = entry.hopsRemaining - 1;
        if (next <= 0) {
          const delReq = cursor.delete();
          delReq.onsuccess = () => resolve();
          delReq.onerror = () => reject(delReq.error);
          return;
        }
        const updateReq = cursor.update({ ...entry, hopsRemaining: next });
        updateReq.onsuccess = () => resolve();
        updateReq.onerror = () => reject(updateReq.error);
      };
      cursorReq.onerror = () => reject(cursorReq.error);
    });
  }

    /**
   * EXTERNAL API — has no caller inside this repository, and that is expected.
   * The consumer is oxpulse-chat's periodic eviction sweep
   * (web/src/lib/chat/mesh-dedup.ts), which calls this on an interval with its
   * OWN cap constant and reports the returned count to analytics.
   *
   * Do NOT delete it as dead code on the strength of a repo-scoped search: this
   * package is published to npm, so its callers live in other repositories. It
   * was deleted once on exactly that reasoning and broke the consumer's build.
   *
   * It is not redundant with the bounded put(): put() enforces the cap at
   * INSERT time using the package default, while this sweeps to a
   * caller-supplied cap on a schedule and returns how many entries went.
   *
   * Evict the OLDEST entries (lowest addedAtMs) until the store contains
   * at most `maxEntries`. Single readwrite transaction for count + cursor-walk
   * (eliminates the two-transaction race — W6 fix).
   *
   * Returns the number of entries deleted.
   */
  async evictExcess(maxEntries: number): Promise<number> {
    if (maxEntries < 0) throw new Error('Spool: evictExcess maxEntries must be >= 0');
    const db = this.getDb();

    return new Promise<number>((resolve, reject) => {
      const tx = db.transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_SPOOL_STORE_NAME);

      const countReq = store.count();
      countReq.onsuccess = () => {
        const total = countReq.result;
        if (total <= maxEntries) { resolve(0); return; }

        const toDelete = total - maxEntries;
        let deleted = 0;

        const index = store.index('addedAtMs');
        const cursorReq = index.openCursor(); // ascending = oldest first
        cursorReq.onsuccess = (ev) => {
          const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
          if (!cursor || deleted >= toDelete) {
            if (deleted > 0) emitMeshMetric('mailbox_evicted', { store: 'spool', count: String(deleted) });
            resolve(deleted);
            return;
          }
          cursor.delete();
          deleted++;
          cursor.continue();
        };
        cursorReq.onerror = () => reject(cursorReq.error);
      };
      countReq.onerror = () => reject(countReq.error);
    });
  }

  evictOlderThan(ttlMs: number): Promise<void> {
    const cutoff = Date.now() - ttlMs;
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const index = tx.objectStore(MESH_SPOOL_STORE_NAME).index('addedAtMs');
      const range = IDBKeyRange.upperBound(cutoff, false);
      const req = index.openCursor(range);
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor) { resolve(); return; }
        cursor.delete();
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }
}
