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
 * Eviction:
 * - wall-time TTL via addedAtMs (typical 7 days, caller-supplied)
 * - hop budget via decrementHops() — auto-removes at 0
 */

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

export class Spool {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;

  constructor(dbName = MESH_SPOOL_DB_NAME) {
    this.dbName = dbName;
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

  put(entry: SpoolEntry): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const req = tx.objectStore(MESH_SPOOL_STORE_NAME).put(entry);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

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
   * CALLER CONTRACT (B.4 hardening note): this is a get-then-put on a
   * single IDB tx but issues two requests; two concurrent decrementHops
   * calls for the same msgId race — both reads observe N, both writes
   * commit N-1, single decrement applied. The B.4 gossip caller MUST
   * serialize decrementHops per msgId (e.g. via a per-msgId Mutex or by
   * folding decrement into the same callback chain that picks the next
   * peer to forward to). For B.3 there is no caller — this hazard is
   * documented for the B.4 plan.
   */
  decrementHops(msgId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_SPOOL_STORE_NAME);
      const get = store.get(msgId);
      get.onsuccess = () => {
        const entry = get.result as SpoolEntry | undefined;
        if (!entry) { resolve(); return; }
        const next = entry.hopsRemaining - 1;
        if (next <= 0) {
          const del = store.delete(msgId);
          del.onsuccess = () => resolve();
          del.onerror = () => reject(del.error);
          return;
        }
        const put = store.put({ ...entry, hopsRemaining: next });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      };
      get.onerror = () => reject(get.error);
    });
  }

  /**
   * Evict the OLDEST entries (lowest addedAtMs) until the store contains
   * at most `maxEntries`. Uses the `addedAtMs` index for O(N) cursor walk.
   *
   * Proxy for the 50 MB cap claim in mesh-roadmap §B.3 — at expected payload
   * sizes (1.6 KB average per bundle), 30k entries ≈ 48 MB. Exact byte
   * accounting deferred (would require a running counter or per-row size
   * field; entry-count is good enough for the order-of-magnitude bound).
   *
   * Best-effort cap: count and cursor-walk are separate IDB transactions;
   * a concurrent put between them can leave the store at total+k after
   * eviction (overshoot). The next sweep absorbs the residual.
   *
   * Returns the number of entries deleted.
   */
  async evictExcess(maxEntries: number): Promise<number> {
    if (maxEntries < 0) throw new Error('Spool: evictExcess maxEntries must be >= 0');
    const db = this.getDb();

    // Count first; cheaper than walking when already under cap.
    const total = await new Promise<number>((resolve, reject) => {
      const tx = db.transaction(MESH_SPOOL_STORE_NAME, 'readonly');
      const req = tx.objectStore(MESH_SPOOL_STORE_NAME).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (total <= maxEntries) return 0;

    const toDelete = total - maxEntries;
    let deleted = 0;

    return new Promise<number>((resolve, reject) => {
      const tx = db.transaction(MESH_SPOOL_STORE_NAME, 'readwrite');
      const index = tx.objectStore(MESH_SPOOL_STORE_NAME).index('addedAtMs');
      const req = index.openCursor(); // ascending = oldest first
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor || deleted >= toDelete) { resolve(deleted); return; }
        cursor.delete();
        deleted++;
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
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
