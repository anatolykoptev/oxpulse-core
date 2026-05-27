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
 * TTL eviction uses receivedAtMs (wall-time, not hop count). Default budget
 * is set by callers (mesh-roadmap §B.3 suggests 7 days).
 */

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

export class Inbox {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;

  constructor(dbName = MESH_INBOX_DB_NAME) {
    this.dbName = dbName;
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

  put(entry: InboxEntry): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_INBOX_STORE_NAME, 'readwrite');
      const req = tx.objectStore(MESH_INBOX_STORE_NAME).put(entry);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  unconsumed(): Promise<InboxEntry[]> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_INBOX_STORE_NAME, 'readonly');
      // IDB does not index booleans reliably across engines; full scan + filter is fine
      // at expected mailbox scale (<50 MB cap from roadmap; ~30k entries worst case).
      const req = tx.objectStore(MESH_INBOX_STORE_NAME).getAll();
      req.onsuccess = () => {
        const all = req.result as InboxEntry[];
        resolve(all.filter((e) => !e.consumed));
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
    if (maxEntries < 0) throw new Error('Inbox: evictExcess maxEntries must be >= 0');
    const db = this.getDb();

    // Count first; cheaper than walking when already under cap.
    const total = await new Promise<number>((resolve, reject) => {
      const tx = db.transaction(MESH_INBOX_STORE_NAME, 'readonly');
      const req = tx.objectStore(MESH_INBOX_STORE_NAME).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (total <= maxEntries) return 0;

    const toDelete = total - maxEntries;
    let deleted = 0;

    return new Promise<number>((resolve, reject) => {
      const tx = db.transaction(MESH_INBOX_STORE_NAME, 'readwrite');
      const index = tx.objectStore(MESH_INBOX_STORE_NAME).index('receivedAtMs');
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
