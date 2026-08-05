import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { Inbox } from '../../mailbox/inbox.ts';
import { setMeshMetricSink, type MeshMetric } from '../../metrics.ts';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const entry = (msgId: string, receivedAtMs: number, consumed = false) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  receivedAtMs,
  consumed,
});

// ─── B1: Bounded put — eviction wired into put() ──────────────────────────────

describe('B1: Inbox.put() bounded storage enforcement', () => {
  let inbox: Inbox;
  let metrics: { metric: MeshMetric; labels?: Record<string, string> }[];

  beforeEach(async () => {
    metrics = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    // Use a small maxEntries for testability.
    inbox = new Inbox('test-inbox-bounded-' + Math.random(), 5);
    await inbox.open();
  });

  afterEach(() => {
    inbox.close();
    setMeshMetricSink(() => {});
  });

  it('enforces cap: inserting beyond maxEntries evicts oldest', async () => {
    const now = Date.now();
    // Insert 5 entries (at cap).
    for (let i = 0; i < 5; i++) {
      await inbox.put(entry(`msg-${i}`, now - (5 - i) * 1000));
    }
    expect(await inbox.unconsumed()).toHaveLength(5);

    // Insert 6th — should evict msg-0 (oldest).
    await inbox.put(entry('msg-5', now));
    const remaining = await inbox.unconsumed();
    expect(remaining).toHaveLength(5); // still 5, not 6
    const ids = remaining.map((e) => e.msgId).sort();
    expect(ids).toEqual(['msg-1', 'msg-2', 'msg-3', 'msg-4', 'msg-5']);
  });

  it('emits mailbox_evicted metric on eviction', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      await inbox.put(entry(`msg-${i}`, now - (5 - i) * 1000));
    }
    metrics = []; // reset after warm-up
    await inbox.put(entry('msg-5', now));
    const evictedMetrics = metrics.filter((m) => m.metric === 'mailbox_evicted');
    expect(evictedMetrics).toHaveLength(1);
    expect(evictedMetrics[0]!.labels?.store).toBe('inbox');
    expect(evictedMetrics[0]!.labels?.count).toBe('1');
  });

  it('does NOT evict when under cap (no metric)', async () => {
    const now = Date.now();
    for (let i = 0; i < 4; i++) {
      await inbox.put(entry(`msg-${i}`, now - (4 - i) * 1000));
    }
    const evictedMetrics = metrics.filter((m) => m.metric === 'mailbox_evicted');
    expect(evictedMetrics).toHaveLength(0);
  });

  it('evicts multiple entries when far over cap via repeated puts', async () => {
    const now = Date.now();
    // Insert 10 entries one at a time with cap=5.
    // Each insert beyond 5 should evict 1 oldest.
    for (let i = 0; i < 10; i++) {
      await inbox.put(entry(`msg-${i}`, now + i));
    }
    const remaining = await inbox.unconsumed();
    expect(remaining).toHaveLength(5); // cap enforced
    const ids = remaining.map((e) => e.msgId).sort();
    // Last 5 inserted should remain: msg-5..msg-9
    expect(ids).toEqual(['msg-5', 'msg-6', 'msg-7', 'msg-8', 'msg-9']);
  });

  it('evicts oldest by receivedAtMs, not by insertion order', async () => {
    const now = Date.now();
    // Insert out of order: middle, oldest, newest
    await inbox.put(entry('middle', now - 5000));
    await inbox.put(entry('oldest', now - 10000));
    await inbox.put(entry('newest', now - 100));
    await inbox.put(entry('v2', now - 200));
    await inbox.put(entry('v3', now - 300));

    // Now insert 6th — 'oldest' (now - 10000) should be evicted.
    await inbox.put(entry('msg-5', now));
    const remaining = await inbox.unconsumed();
    const ids = remaining.map((e) => e.msgId);
    expect(ids).not.toContain('oldest');
    expect(ids).toContain('newest');
    expect(ids).toContain('msg-5');
  });

  it('put is idempotent on msgId (update does not trigger eviction)', async () => {
    const now = Date.now();
    await inbox.put(entry('msg-a', now - 1000));
    await inbox.put(entry('msg-b', now - 500));
    // Re-put same msgId — should update, not add a new entry.
    await inbox.put(entry('msg-a', now));
    const remaining = await inbox.unconsumed();
    expect(remaining).toHaveLength(2);
    // Verify the update took effect.
    const updated = remaining.find((e) => e.msgId === 'msg-a');
    expect(updated?.receivedAtMs).toBe(now);
  });

  it('cap=0 evicts everything before insert (edge case)', async () => {
    const edgeInbox = new Inbox('test-inbox-cap0-' + Math.random(), 0);
    await edgeInbox.open();
    const now = Date.now();
    await edgeInbox.put(entry('msg-1', now));
    // With cap=0, the store should have at most 1 entry (the one just put,
    // since eviction happens BEFORE put). Actually: count=0, toEvict=0,
    // so put succeeds. Second put: count=1, toEvict=2, evicts 1, puts 1.
    await edgeInbox.put(entry('msg-2', now + 1));
    const remaining = await edgeInbox.unconsumed();
    // After second put: evicted msg-1, put msg-2. Store has 1 entry.
    // But cap=0 means we should evict to 0 before put... let's check:
    // count=1, maxEntries=0, toEvict = 1 - 0 + 1 = 2. But only 1 to evict.
    // So evict 1, put 1 → store has 1. Next put would evict that 1.
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!.msgId).toBe('msg-2');
    edgeInbox.close();
  });
});

// ─── S4: unconsumed() cursor walk (no getAll) ─────────────────────────────────

describe('S4: Inbox.unconsumed() cursor-based walk', () => {
  let inbox: Inbox;

  beforeEach(async () => {
    inbox = new Inbox('test-inbox-cursor-' + Math.random(), 100);
    await inbox.open();
  });

  afterEach(() => inbox.close());

  it('returns only unconsumed entries (excludes consumed)', async () => {
    const now = Date.now();
    await inbox.put(entry('msg-a', now - 300));
    await inbox.put(entry('msg-b', now - 200));
    await inbox.put(entry('msg-c', now - 100));
    await inbox.markConsumed('msg-a');
    await inbox.markConsumed('msg-c');
    const unconsumed = await inbox.unconsumed();
    expect(unconsumed).toHaveLength(1);
    expect(unconsumed[0]!.msgId).toBe('msg-b');
  });

  it('returns empty array when all consumed', async () => {
    const now = Date.now();
    await inbox.put(entry('msg-a', now));
    await inbox.markConsumed('msg-a');
    expect(await inbox.unconsumed()).toHaveLength(0);
  });

  it('returns empty array when store is empty', async () => {
    expect(await inbox.unconsumed()).toHaveLength(0);
  });

  it('returns all entries when none consumed', async () => {
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      await inbox.put(entry(`msg-${i}`, now + i));
    }
    const unconsumed = await inbox.unconsumed();
    expect(unconsumed).toHaveLength(10);
  });
});

// ─── W6: evictExcess single-transaction (no race) ─────────────────────────────

describe('W6: Inbox.evictExcess single-transaction', () => {
  let inbox: Inbox;

  beforeEach(async () => {
    inbox = new Inbox('test-inbox-evict-race-' + Math.random(), 100);
    await inbox.open();
  });

  afterEach(() => inbox.close());

  it('evicts correct count to reach exactly maxEntries', async () => {
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      await inbox.put(entry(`msg-${i}`, now - (10 - i) * 1000));
    }
    const deleted = await inbox.evictExcess(4);
    expect(deleted).toBe(6);
    expect(await inbox.unconsumed()).toHaveLength(4);
  });

  it('returns 0 when already under cap', async () => {
    const now = Date.now();
    await inbox.put(entry('msg-a', now));
    expect(await inbox.evictExcess(10)).toBe(0);
  });

  it('handles maxEntries=0 (evict everything)', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      await inbox.put(entry(`msg-${i}`, now + i));
    }
    const deleted = await inbox.evictExcess(0);
    expect(deleted).toBe(5);
    expect(await inbox.unconsumed()).toHaveLength(0);
  });

  it('throws on negative maxEntries', async () => {
    await expect(inbox.evictExcess(-1)).rejects.toThrow('maxEntries must be >= 0');
  });
});
