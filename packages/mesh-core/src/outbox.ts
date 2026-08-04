/**
 * outbox.ts — B-4 Phase.
 *
 * IndexedDB-backed queue of pending outgoing mesh-bundle sends.
 *
 * Schema per entry:
 *   msgId           string      primary key
 *   channelId       Uint8Array  4 B
 *   bundle          Uint8Array  wire bytes
 *   attempts        number      default 0
 *   lastAttemptMs   number      ms timestamp (0 = never attempted)
 *   status          'pending' | 'sent' | 'failed'
 *
 * API: enqueue, nextPending, markSent, markFailed, evictOlderThan, open, close.
 *
 * S6: bounded storage — enqueue() enforces MESH_OUTBOX_MAX_ENTRIES atomically
 * (count + evict-oldest + put in a single readwrite transaction).
 */

import { emitMeshMetric } from './metrics.js';

export interface OutboxEntry {
  msgId: string;
  channelId: Uint8Array;
  bundle: Uint8Array;
  attempts: number;
  lastAttemptMs: number;
  status: 'pending' | 'sent' | 'failed';
}

interface EnqueueArgs {
  msgId: string;
  channelId: Uint8Array;
  bundle: Uint8Array;
  lastAttemptMs?: number;
}

const DB_VERSION = 1;

/** Maximum delivery attempts before an entry is marked terminal (status='failed'). */
export const MAX_OUTBOX_ATTEMPTS = 8;

/** S6: Maximum entry count — bounded put enforces this atomically. */
export const MESH_OUTBOX_MAX_ENTRIES = 5000;

/** Canonical object store name — import this instead of using a string literal. */
export const MESH_OUTBOX_STORE_NAME = 'outbox';

/** Canonical default IndexedDB database name for the router outbox. */
export const MESH_OUTBOX_DB_NAME = 'mesh-router-outbox';

export class Outbox {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;

  constructor(dbName = MESH_OUTBOX_DB_NAME) {
    this.dbName = dbName;
  }

  open(): Promise<void> {
    // Idempotent: if already open, return immediately without leaking a second connection.
    if (this.db) return Promise.resolve();

    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, DB_VERSION);
      req.onupgradeneeded = (ev) => {
        const db = (ev.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(MESH_OUTBOX_STORE_NAME)) {
          const store = db.createObjectStore(MESH_OUTBOX_STORE_NAME, { keyPath: 'msgId' });
          store.createIndex('status', 'status', { unique: false });
          store.createIndex('lastAttemptMs', 'lastAttemptMs', { unique: false });
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
    if (!this.db) throw new Error('Outbox: call open() first');
    return this.db;
  }

  /**
   * S6: Bounded enqueue — count + evict-oldest + put in a single readwrite
   * transaction. If the store exceeds MESH_OUTBOX_MAX_ENTRIES, the oldest
   * entries (lowest lastAttemptMs) are evicted before the put.
   */
  enqueue(args: EnqueueArgs): Promise<void> {
    return new Promise((resolve, reject) => {
      const entry: OutboxEntry = {
        msgId: args.msgId,
        channelId: args.channelId,
        bundle: args.bundle,
        attempts: 0,
        lastAttemptMs: args.lastAttemptMs ?? 0,
        status: 'pending',
      };
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_OUTBOX_STORE_NAME);
      const countReq = store.count();
      countReq.onsuccess = () => {
        const count = countReq.result;
        if (count >= MESH_OUTBOX_MAX_ENTRIES) {
          // Evict oldest entries (lowest lastAttemptMs) to make room.
          const evictCount = Math.max(1, Math.floor(count * 0.1));
          const index = store.index('lastAttemptMs');
          let evicted = 0;
          const evictCursor = index.openCursor();
          evictCursor.onsuccess = (ev) => {
            const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
            if (!cursor || evicted >= evictCount) {
              // Done evicting — now put the new entry.
              const putReq = store.put(entry);
              putReq.onsuccess = () => {
                emitMeshMetric('mailbox_evicted', { store: 'outbox', count: String(evicted) });
                resolve();
              };
              putReq.onerror = () => reject(putReq.error);
              return;
            }
            cursor.delete();
            evicted++;
            cursor.continue();
          };
          evictCursor.onerror = () => reject(evictCursor.error);
        } else {
          // Under cap — just put.
          const putReq = store.put(entry);
          putReq.onsuccess = () => resolve();
          putReq.onerror = () => reject(putReq.error);
        }
      };
      countReq.onerror = () => reject(countReq.error);
    });
  }

  nextPending(): Promise<OutboxEntry | null> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readonly');
      const index = tx.objectStore(MESH_OUTBOX_STORE_NAME).index('status');
      const req = index.openCursor(IDBKeyRange.only('pending'));
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        resolve(cursor ? (cursor.value as OutboxEntry) : null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  markSent(msgId: string): Promise<void> {
    return this.updateEntry(msgId, (e) => ({ ...e, status: 'sent' as const }));
  }

  markFailed(msgId: string): Promise<void> {
    return this.updateEntry(msgId, (e) => {
      const attempts = e.attempts + 1;
      const terminal = attempts >= MAX_OUTBOX_ATTEMPTS;
      return {
        ...e,
        status: terminal ? 'failed' as const : 'pending' as const,
        attempts,
        lastAttemptMs: Date.now(),
      };
    });
  }

  /** Returns all entries with status='failed' (terminal, not retried). */
  failedEntries(): Promise<OutboxEntry[]> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readonly');
      const index = tx.objectStore(MESH_OUTBOX_STORE_NAME).index('status');
      const req = index.getAll(IDBKeyRange.only('failed'));
      req.onsuccess = () => resolve(req.result as OutboxEntry[]);
      req.onerror = () => reject(req.error);
    });
  }

  /** Removes all terminal ('failed') entries from the outbox. */
  clearFailed(): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_OUTBOX_STORE_NAME);
      const index = store.index('status');
      const req = index.openCursor(IDBKeyRange.only('failed'));
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor) { resolve(); return; }
        cursor.delete();
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  private updateEntry(msgId: string, fn: (e: OutboxEntry) => OutboxEntry): Promise<void> {
    // B5: use cursor.update() for atomic read-modify-write.
    // The cursor holds the record lock within the transaction — no other
    // readwrite transaction can interleave between the read and the write.
    // Previous get-then-put pattern relied on IDB transaction serialization
    // which is correct per spec but fragile across implementations.
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_OUTBOX_STORE_NAME);
      const cursorReq = store.openCursor(IDBKeyRange.only(msgId));
      cursorReq.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor) { resolve(); return; }
        const existing = cursor.value as OutboxEntry;
        const updated = fn(existing);
        const updateReq = cursor.update(updated);
        updateReq.onsuccess = () => resolve();
        updateReq.onerror = () => reject(updateReq.error);
      };
      cursorReq.onerror = () => reject(cursorReq.error);
    });
  }

  evictOlderThan(ms: number): Promise<void> {
    const cutoff = Date.now() - ms;
    return new Promise((resolve, reject) => {
      // Open a single rw transaction for the entire eviction operation.
      // We collect IDs to delete via the cursor walk, then delete them all
      // on THE SAME transaction's object store — no second inner transaction.
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_OUTBOX_STORE_NAME);
      const index = store.index('lastAttemptMs');
      // Evict entries where lastAttemptMs is in range (0, cutoff] — i.e. attempted
      // but old. Entries with lastAttemptMs=0 (never attempted) are NOT evicted.
      const range = IDBKeyRange.bound(1, cutoff, false, false);
      const req = index.openCursor(range);
      req.onsuccess = (ev) => {
        const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (!cursor) {
          resolve();
          return;
        }
        // Use cursor.delete() for inline deletion — avoids collect-then-delete pattern
        // and keeps all deletes on the same rw transaction opened above.
        cursor.delete();
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  /** S6: Return the current entry count. */
  size(): Promise<number> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readonly');
      const req = tx.objectStore(MESH_OUTBOX_STORE_NAME).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  /**
   * S6: Evict the OLDEST entries (lowest lastAttemptMs) until the store
   * contains at most `maxEntries`. Single readwrite transaction.
   */
  evictExcess(maxEntries: number = MESH_OUTBOX_MAX_ENTRIES): Promise<number> {
    return new Promise((resolve, reject) => {
      const tx = this.getDb().transaction(MESH_OUTBOX_STORE_NAME, 'readwrite');
      const store = tx.objectStore(MESH_OUTBOX_STORE_NAME);
      const countReq = store.count();
      countReq.onsuccess = () => {
        const count = countReq.result;
        if (count <= maxEntries) { resolve(0); return; }
        const toEvict = count - maxEntries;
        const index = store.index('lastAttemptMs');
        let evicted = 0;
        const cursorReq = index.openCursor();
        cursorReq.onsuccess = (ev) => {
          const cursor = (ev.target as IDBRequest<IDBCursorWithValue | null>).result;
          if (!cursor || evicted >= toEvict) {
            if (evicted > 0) emitMeshMetric('mailbox_evicted', { store: 'outbox', count: String(evicted) });
            resolve(evicted);
            return;
          }
          cursor.delete();
          evicted++;
          cursor.continue();
        };
        cursorReq.onerror = () => reject(cursorReq.error);
      };
      countReq.onerror = () => reject(countReq.error);
    });
  }
}
