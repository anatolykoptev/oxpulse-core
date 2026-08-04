import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { Spool } from '../../mailbox/spool.ts';
import { setMeshMetricSink, type MeshMetric } from '../../metrics.ts';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const spoolEntry = (msgId: string, addedAtMs: number, hopsRemaining = 3) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  addedAtMs,
  hopsRemaining,
});

// ─── B1: Bounded put — eviction wired into put() ──────────────────────────────

describe('B1: Spool.put() bounded storage enforcement', () => {
  let spool: Spool;
  let metrics: { metric: MeshMetric; labels?: Record<string, string> }[];

  beforeEach(async () => {
    metrics = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    spool = new Spool('test-spool-bounded-' + Math.random(), 5);
    await spool.open();
  });

  afterEach(() => {
    spool.close();
    setMeshMetricSink(() => {});
  });

  it('enforces cap: inserting beyond maxEntries evicts oldest', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      await spool.put(spoolEntry(`s-${i}`, now - (5 - i) * 1000));
    }
    expect(await spool.size()).toBe(5);

    // Insert 6th — should evict s-0 (oldest).
    await spool.put(spoolEntry('s-5', now));
    expect(await spool.size()).toBe(5); // still 5, not 6
    const remaining = (await spool.all()).map((e) => e.msgId).sort();
    expect(remaining).toEqual(['s-1', 's-2', 's-3', 's-4', 's-5']);
  });

  it('emits mailbox_evicted metric on eviction', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      await spool.put(spoolEntry(`s-${i}`, now - (5 - i) * 1000));
    }
    metrics = []; // reset after warm-up
    await spool.put(spoolEntry('s-5', now));
    const evictedMetrics = metrics.filter((m) => m.metric === 'mailbox_evicted');
    expect(evictedMetrics).toHaveLength(1);
    expect(evictedMetrics[0]!.labels?.store).toBe('spool');
  });

  it('does NOT evict when under cap (no metric)', async () => {
    const now = Date.now();
    for (let i = 0; i < 4; i++) {
      await spool.put(spoolEntry(`s-${i}`, now - (4 - i) * 1000));
    }
    const evictedMetrics = metrics.filter((m) => m.metric === 'mailbox_evicted');
    expect(evictedMetrics).toHaveLength(0);
  });

  it('evicts oldest by addedAtMs, not by insertion order', async () => {
    const now = Date.now();
    await spool.put(spoolEntry('middle', now - 5000));
    await spool.put(spoolEntry('oldest', now - 10000));
    await spool.put(spoolEntry('newest', now - 100));
    await spool.put(spoolEntry('v2', now - 200));
    await spool.put(spoolEntry('v3', now - 300));

    await spool.put(spoolEntry('s-5', now));
    const remaining = (await spool.all()).map((e) => e.msgId);
    expect(remaining).not.toContain('oldest');
    expect(remaining).toContain('newest');
    expect(remaining).toContain('s-5');
  });

  it('put is idempotent on msgId (update does not trigger eviction)', async () => {
    const now = Date.now();
    await spool.put(spoolEntry('s-a', now - 1000));
    await spool.put(spoolEntry('s-b', now - 500));
    // Re-put same msgId — should update, not add a new entry.
    await spool.put(spoolEntry('s-a', now, 5));
    expect(await spool.size()).toBe(2);
    const all = await spool.all();
    const updated = all.find((e) => e.msgId === 's-a');
    expect(updated?.addedAtMs).toBe(now);
    expect(updated?.hopsRemaining).toBe(5);
  });
});

// ─── S5: recent() bounded cursor walk ─────────────────────────────────────────

describe('S5: Spool.recent() bounded cursor walk', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool('test-spool-recent-' + Math.random(), 100);
    await spool.open();
  });

  afterEach(() => spool.close());

  it('returns up to limit entries, newest first', async () => {
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      await spool.put(spoolEntry(`s-${i}`, now + i));
    }
    const recent = await spool.recent(3);
    expect(recent).toHaveLength(3);
    // Newest first: s-9, s-8, s-7
    expect(recent[0]!.msgId).toBe('s-9');
    expect(recent[1]!.msgId).toBe('s-8');
    expect(recent[2]!.msgId).toBe('s-7');
  });

  it('returns all entries when limit exceeds store size', async () => {
    const now = Date.now();
    await spool.put(spoolEntry('s-a', now));
    await spool.put(spoolEntry('s-b', now + 1));
    const recent = await spool.recent(100);
    expect(recent).toHaveLength(2);
    // Newest first
    expect(recent[0]!.msgId).toBe('s-b');
    expect(recent[1]!.msgId).toBe('s-a');
  });

  it('returns empty array when store is empty', async () => {
    expect(await spool.recent(10)).toHaveLength(0);
  });

  it('returns empty array when limit=0', async () => {
    const now = Date.now();
    await spool.put(spoolEntry('s-a', now));
    expect(await spool.recent(0)).toHaveLength(0);
  });

  it('throws on negative limit', () => {
    expect(() => spool.recent(-1)).toThrow('limit must be >= 0');
  });
});

// ─── W6: evictExcess single-transaction ───────────────────────────────────────

describe('W6: Spool.evictExcess single-transaction', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool('test-spool-evict-race-' + Math.random(), 100);
    await spool.open();
  });

  afterEach(() => spool.close());

  it('evicts correct count to reach exactly maxEntries', async () => {
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      await spool.put(spoolEntry(`s-${i}`, now - (10 - i) * 1000));
    }
    const deleted = await spool.evictExcess(4);
    expect(deleted).toBe(6);
    expect(await spool.size()).toBe(4);
  });

  it('returns 0 when already under cap', async () => {
    const now = Date.now();
    await spool.put(spoolEntry('s-a', now));
    expect(await spool.evictExcess(10)).toBe(0);
  });

  it('handles maxEntries=0 (evict everything)', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      await spool.put(spoolEntry(`s-${i}`, now + i));
    }
    const deleted = await spool.evictExcess(0);
    expect(deleted).toBe(5);
    expect(await spool.size()).toBe(0);
  });

  it('throws on negative maxEntries', async () => {
    await expect(spool.evictExcess(-1)).rejects.toThrow('maxEntries must be >= 0');
  });
});
