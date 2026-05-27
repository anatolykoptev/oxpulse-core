/**
 * dedupe.ts — B-4 Phase.
 *
 * In-memory LRU deduplication cache for inbound mesh bundles.
 * Key: composite (channelId, msgId) — both are strings.
 * Capacity: configurable, default 5000.
 * No persistence — replay protection across reloads handled by server seq.
 */

export interface DedupeCacheOptions {
  capacity?: number;
}

export class DedupeCache {
  private readonly capacity: number;
  // Map preserves insertion order; we use this for LRU eviction.
  private readonly seen: Map<string, true>;

  constructor(opts: DedupeCacheOptions = {}) {
    this.capacity = opts.capacity ?? 5000;
    this.seen = new Map();
  }

  private key(channelId: string, msgId: string): string {
    return `${channelId}\x00${msgId}`;
  }

  hasSeen(channelId: string, msgId: string): boolean {
    return this.seen.has(this.key(channelId, msgId));
  }

  markSeen(channelId: string, msgId: string): void {
    const k = this.key(channelId, msgId);
    if (this.seen.has(k)) {
      // Refresh: delete + re-insert to move to "most recent" position.
      this.seen.delete(k);
    } else if (this.seen.size >= this.capacity) {
      // Evict oldest (first insertion order key).
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.set(k, true);
  }

  /** Clear all entries from the deduplication cache. */
  clear(): void {
    this.seen.clear();
  }
}
