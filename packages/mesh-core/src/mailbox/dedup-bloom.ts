/**
 * dedup-bloom.ts — B.3 mailbox primitive.
 *
 * Persistent Bloom filter for scaled inbound dedup. Trades exact membership
 * for ~88 KB storage at 50k capacity / 0.1% FP rate.
 *
 * A false positive = silently dropping a duplicate that was actually new.
 * Acceptable at design FP rate (one in a thousand bundles).
 * A false negative = impossible (Bloom invariant).
 *
 * Persistence:
 *   IndexedDB row { id='bits', bits: Uint8Array, m, k }
 *   flush() schedules a put; durability bounded by the next IDB tx
 *   completion (style-matched to Inbox/Outbox: resolves on req.onsuccess,
 *   not tx.oncomplete). Stale-on-crash is acceptable — Bloom is a lossy
 *   dedup hint, not a correctness primitive. Server `repo.append`
 *   idempotency on msg_id is authoritative.
 *
 * Hash strategy:
 *   murmur3_32 with two seeds (0 and 0xdeadbeef). Each Bloom probe index
 *   k_i = (h1 + i * h2) mod m. Non-cryptographic by design — adversary
 *   cannot influence which slot a hostile msgId hits with these seeds,
 *   and bloom-poisoning attacks (full fill) require the attacker to also
 *   bypass signature validation upstream.
 */

import { DEDUP_BLOOM_CAPACITY, DEDUP_BLOOM_FP_RATE } from '../constants.generated.js';

export interface BloomDedupOptions {
  dbName?: string;
  /** Target number of distinct keys before FP rate degrades. */
  capacity?: number;
  /** Acceptable false-positive rate at capacity. */
  fpRate?: number;
}

export const MESH_BLOOM_DB_NAME = 'mesh-router-bloom';
export const MESH_BLOOM_STORE_NAME = 'bloom';
const DB_VERSION = 1;
const ROW_KEY = 'bits';

interface BloomRow {
  id: string;
  bits: Uint8Array;
  m: number;
  k: number;
}

function murmur3_32(input: string, seed: number): number {
  // Compact pure-TS implementation. Returns u32.
  let h = seed >>> 0;
  let i = 0;
  const len = input.length;
  while (i + 4 <= len) {
    let k =
      (input.charCodeAt(i) & 0xff) |
      ((input.charCodeAt(i + 1) & 0xff) << 8) |
      ((input.charCodeAt(i + 2) & 0xff) << 16) |
      ((input.charCodeAt(i + 3) & 0xff) << 24);
    k = Math.imul(k, 0xcc9e2d51) >>> 0;
    k = ((k << 15) | (k >>> 17)) >>> 0;
    k = Math.imul(k, 0x1b873593) >>> 0;
    h ^= k;
    h = ((h << 13) | (h >>> 19)) >>> 0;
    h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
    i += 4;
  }
  let kTail = 0;
  if (i < len) kTail ^= (input.charCodeAt(i) & 0xff);
  if (i + 1 < len) kTail ^= (input.charCodeAt(i + 1) & 0xff) << 8;
  if (i + 2 < len) kTail ^= (input.charCodeAt(i + 2) & 0xff) << 16;
  if (kTail !== 0) {
    kTail = Math.imul(kTail, 0xcc9e2d51) >>> 0;
    kTail = ((kTail << 15) | (kTail >>> 17)) >>> 0;
    kTail = Math.imul(kTail, 0x1b873593) >>> 0;
    h ^= kTail;
  }
  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

function paramsFor(capacity: number, fpRate: number): { m: number; k: number } {
  // m = -(n * ln p) / (ln 2)^2; k = (m/n) * ln 2
  const m = Math.ceil(-(capacity * Math.log(fpRate)) / Math.LN2 ** 2);
  const k = Math.max(1, Math.round((m / capacity) * Math.LN2));
  return { m, k };
}

export class BloomDedup {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;
  private bits!: Uint8Array;
  private readonly m: number;
  private readonly k: number;

  constructor(opts: BloomDedupOptions = {}) {
    this.dbName = opts.dbName ?? MESH_BLOOM_DB_NAME;
    const { m, k } = paramsFor(
      opts.capacity ?? DEDUP_BLOOM_CAPACITY,
      opts.fpRate ?? DEDUP_BLOOM_FP_RATE,
    );
    this.m = m;
    this.k = k;
  }

  async open(): Promise<void> {
    if (this.db) return;
    this.db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(this.dbName, DB_VERSION);
      req.onupgradeneeded = (ev) => {
        const db = (ev.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(MESH_BLOOM_STORE_NAME)) {
          db.createObjectStore(MESH_BLOOM_STORE_NAME, { keyPath: 'id' });
        }
      };
      req.onsuccess = (ev) => resolve((ev.target as IDBOpenDBRequest).result);
      req.onerror = () => reject(req.error);
    });

    // Load existing row, or initialize fresh bits array.
    const row = await new Promise<BloomRow | undefined>((resolve, reject) => {
      const tx = this.db!.transaction(MESH_BLOOM_STORE_NAME, 'readonly');
      const req = tx.objectStore(MESH_BLOOM_STORE_NAME).get(ROW_KEY);
      req.onsuccess = () => resolve(req.result as BloomRow | undefined);
      req.onerror = () => reject(req.error);
    });

    if (row && row.m === this.m && row.k === this.k) {
      this.bits = row.bits;
    } else {
      if (row) {
        // Existing row had different params (capacity/fpRate changed between sessions).
        // Bits cannot be re-mapped — discard. Log once so operators can spot it.
        console.warn(
          `[bloom] params changed (m: ${row.m}→${this.m}, k: ${row.k}→${this.k}); discarding ${row.bits.byteLength} bytes of state`
        );
      }
      this.bits = new Uint8Array(Math.ceil(this.m / 8));
    }
  }

  close(): void {
    this.db?.close();
    this.db = null;
  }

  /**
   * msgId MUST be ASCII (hex/base64). Non-BMP UTF-16 input has unspecified
   * FP behaviour because murmur3_32 here hashes code units, not codepoints.
   * Internal mesh msgIds are 16-byte UUIDs hex/base64-encoded, so this is fine
   * for in-tree callers.
   */
  hasSeen(msgId: string): boolean {
    const h1 = murmur3_32(msgId, 0);
    let h2 = murmur3_32(msgId, 0xdeadbeef);
    if (h2 === 0) h2 = 1;
    for (let i = 0; i < this.k; i++) {
      const idx = (h1 + Math.imul(i, h2)) >>> 0;
      const bit = idx % this.m;
      const byte = bit >>> 3;
      const mask = 1 << (bit & 7);
      if ((this.bits[byte]! & mask) === 0) return false;
    }
    return true;
  }

  /**
   * msgId MUST be ASCII (hex/base64). Non-BMP UTF-16 input has unspecified
   * FP behaviour because murmur3_32 here hashes code units, not codepoints.
   * Internal mesh msgIds are 16-byte UUIDs hex/base64-encoded, so this is fine
   * for in-tree callers.
   */
  markSeen(msgId: string): void {
    const h1 = murmur3_32(msgId, 0);
    let h2 = murmur3_32(msgId, 0xdeadbeef);
    if (h2 === 0) h2 = 1;
    for (let i = 0; i < this.k; i++) {
      const idx = (h1 + Math.imul(i, h2)) >>> 0;
      const bit = idx % this.m;
      const byte = bit >>> 3;
      const mask = 1 << (bit & 7);
      this.bits[byte]! |= mask;
    }
  }

  flush(): Promise<void> {
    if (!this.db) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const tx = this.db!.transaction(MESH_BLOOM_STORE_NAME, 'readwrite');
      const row: BloomRow = { id: ROW_KEY, bits: this.bits, m: this.m, k: this.k };
      const req = tx.objectStore(MESH_BLOOM_STORE_NAME).put(row);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }
}
