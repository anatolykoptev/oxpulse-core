/**
 * inbox.ts — B.3 mailbox primitive.
 *
 * IndexedDB-backed store of mesh bundles received from peers, pending
 * consumption by the application layer (e.g. SSE-style fanout on reconnect,
 * UI presentation). Distinct from outbox (pending OUT) and spool (pending
 * forward in store-and-forward gossip).
 *
 * Schema per entry:
 *   msgId          string      primary key
 *   channelId      Uint8Array  4 B
 *   bundle         Uint8Array  wire bytes (already verified by caller)
 *   receivedAtMs   number      wall-clock ms when the bundle was inserted
 *   consumed       boolean     true once application has acked it
 *
 * Bounded storage: put() enforces MESH_INBOX_MAX_ENTRIES atomically —
 * count + evict-oldest + put in a single readwrite transaction. This
 * eliminates the count-then-cursor-walk race (two separate transactions)
 * and ensures the cap is enforced on every insert without relying on
 * callers to invoke evictExcess(). QuotaExceededError triggers aggressive
 * eviction (drop 10% of oldest) + retry.
 *
 * TTL eviction uses receivedAtMs (wall-time, not hop count). Default budget
 * is set by callers (mesh-roadmap §B.3 suggests 7 days).
 */

import { MESH_INBOX_MAX_ENTRIES } from '../constants.generated.js';
import { emitMeshMetric } from '../metrics.js';

export interface InboxEntry {
  msgId: string;
  channelId: Uint8Array;
  bundle: Uint8Array;
  receivedAtMs: number;
  consumed: boolean;
}

export const MESH_INBOX_DB_NAME = 'mesh-router-inbox';
export const MESH_INBOX_STORE_NAME = 'inbox';

const DB_VERSION = 1;

/**
 * Fraction of maxEntries to evict on QuotaExceededError before retry.
 * Dropping 10% gives headroom for the retry to succeed without thrashing.
 */
const QUOTA_EVICT_FRACTION = 0.1;

export class Inbox {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;
  private readonly maxEntries: number;

  constructor(dbName = MESH_INBOX_DB_NAME, maxEntries = MESH_INBOX_MAX_ENTRIES) {
    this.dbName = dbName;
    this.maxEntries = maxEntries;
  }

  open(): Promise<void> {
    if (this.db) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, DB_VERSION);
      req.onupgradeneeded = (ev) => {
        const db = (ev.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(MESH_INBOX_STORE_NAME)) {
          const store = db.createObjectStore(MESH_INBOX_STORE_NAME, { keyPath: 'msgId' });
          store.createIndex('consumed', 'consumed', { unique: false });
          store.createIndex('receivedAtMs', 'receivedAtMs', { unique: false });
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
    if (!this.db) throw new Error('Inbox: call open() first');
    return this.db;
  }

  /**
   * Insert an entry, atomically enforcing the maxEntries cap.
   *
   * Count + evict-oldest + put happen in a single readwrite transaction,
   * eliminating the race between separate count and cursor-walk transactions.
   * If the store is at or above maxEntries, the oldest entries (lowest
   * receivedAtMs) are deleted before the new entry is inserted.
   *
   * On QuotaExceededError: aggressively evict 10% of maxEntries and retry once.
   */
  put(entry: InboxEntry): Promise<void> {
    return this.putBounded(entry, false);
  }

  private putBounded(entry: InboxEntry, isRetry: boolean): Promise<void> {
    return new Promise((resolve, reject) => {
      const db = this.getDb();
      const tx = db.transaction(MESH_INBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_INBOX_STORE_NAME);

      // Phase 1: count existing entries.
      const countReq = store.count();
      countReq.onsuccess = () => {
        const total = countReq.result;

        // Phase 2: if at or above cap, evict oldest entries via cursor.
        // We need to evict (total - maxEntries + 1) to make room for the new entry.
        const toEvict = total >= this.maxEntries ? total - this.maxEntries + 1 : 0;

        if (toEvict === 0) {
          // Under cap — just put.
          const putReq = store.put(entry);
          putReq.onsuccess = () => resolve();
          putReq.onerror = () => reject(putReq.error);
          return;
        }

        // Evict oldest entries via receivedAtMs index cursor.
        const index = store.index('receivedAtMs');
        const cursorReq = index.openCursor(); // ascending = oldest first
        let evicted = 0;
        cursorReq.onsuccess = (ev) => {
          const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
          if (!cursor || evicted >= toEvict) {
            // Done evicting — now put the new entry on the SAME transaction.
            const putReq = store.put(entry);
            putReq.onsuccess = () => {
              emitMeshMetric('mailbox_evicted', { store: 'inbox', count: String(evicted) });
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

      // QuotaExceededError handling: on tx abort, check error, evict aggressively, retry.
      tx.onerror = () => {
        const error = tx.error;
        if (error && error.name === 'QuotaExceededError' && !isRetry) {
          emitMeshMetric('mailbox_quota_exceeded', { store: 'inbox' });
          // Aggressively evict 10% of cap, then retry the put.
          this.evictAggressive(Math.max(1, Math.floor(this.maxEntries * QUOTA_EVICT_FRACTION)))
            .then(() => this.putBounded(entry, true))
            .then(resolve, reject);
        } else {
          reject(error || new Error('Inbox: transaction aborted'));
        }
      };
      tx.onabort = () => {
        const error = tx.error;
        if (error && error.name === 'QuotaExceededError' && !isRetry) {
          emitMeshMetric('mailbox_quota_exceeded', { store: 'inbox' });
          this.evictAggressive(Math.max(1, Math.floor(this.maxEntries * QUOTA_EVICT_FRACTION)))
            .then(() => this.putBounded(entry, true))
            .then(resolve, reject);
        } else {
          reject(error || new Error('Inbox: transaction aborted'));
        }
      };
    });
  }

  /**
   * Aggressively evict the N oldest entries. Used on QuotaExceededError.
   * Separate transaction from the failed one.
   */
  private evictAggressive(count: number): Promise<number> {
    return new Promise((resolve, reject) => {
      const db = this.getDb();
      const tx = db.transaction(MESH_INBOX_STORE_NAME, 'readwrite');
      const index = tx.objectStore(MESH_INBOX_STORE_NAME).index('receivedAtMs');
      const req = index.openCursor();
      let deleted = 0;
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor || deleted >= count) {
          if (deleted > 0) emitMeshMetric('mailbox_evicted', { store: 'inbox', count: String(deleted) });
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
   * Return all unconsumed entries via cursor walk (NOT getAll).
   *
   * IDB does not index booleans (not a valid key type per spec), so we
   * cannot use IDBKeyRange.only(false) on the 'consumed' index. Instead,
   * we walk the store via cursor and filter inline — O(n) iteration but
   * only unconsumed entries are retained in the results array, avoiding
   * the full-store heap allocation of getAll() (S4 fix).
   */
  unconsumed(): Promise<InboxEntry[]> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_INBOX_STORE_NAME, 'readonly');
      const req = tx.objectStore(MESH_INBOX_STORE_NAME).openCursor();
      const results: InboxEntry[] = [];
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor) { resolve(results); return; }
        const entry = cursor.value as InboxEntry;
        if (!entry.consumed) results.push(entry);
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  markConsumed(msgId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_INBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_INBOX_STORE_NAME);
      const get = store.get(msgId);
      get.onsuccess = () => {
        const entry = get.result as InboxEntry | undefined;
        if (!entry) { resolve(); return; }
        const put = store.put({ ...entry, consumed: true });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      };
      get.onerror = () => reject(get.error);
    });
  }

  /**
   * Evict the OLDEST entries (lowest receivedAtMs) until the store contains
   * at most `maxEntries`. Uses the `receivedAtMs` index for O(N) cursor walk.
   *
   * This is now a TWO-PHASE operation on a SINGLE readwrite transaction:
   * count + cursor-walk-delete are on the same tx, eliminating the
   * count-then-cursor race (W6 fix). The previous two-transaction pattern
   * could leave the store at total+k after eviction (overshoot) due to a
   * concurrent put between the count and the cursor walk.
   *
   * Returns the number of entries deleted.
   */
  async evictExcess(maxEntries: number): Promise<number> {
    if (maxEntries < 0) throw new Error('Inbox: evictExcess maxEntries must be >= 0');
    const db = this.getDb();

    return new Promise<number>((resolve, reject) => {
      const tx = db.transaction(MESH_INBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_INBOX_STORE_NAME);

      // Count on the SAME transaction as the cursor walk — no race.
      const countReq = store.count();
      countReq.onsuccess = () => {
        const total = countReq.result;
        if (total <= maxEntries) { resolve(0); return; }

        const toDelete = total - maxEntries;
        let deleted = 0;

        const index = store.index('receivedAtMs');
        const cursorReq = index.openCursor(); // ascending = oldest first
        cursorReq.onsuccess = (ev) => {
          const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
          if (!cursor || deleted >= toDelete) {
            if (deleted > 0) emitMeshMetric('mailbox_evicted', { store: 'inbox', count: String(deleted) });
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
      const tx = this.getDb().transaction(MESH_INBOX_STORE_NAME, 'readwrite');
      const index = tx.objectStore(MESH_INBOX_STORE_NAME).index('receivedAtMs');
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
