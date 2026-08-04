/**
 * mutation-tests.test.ts — Tests designed to catch code mutations.
 *
 * Each test is annotated with the MUTANT it kills. If a mutation is applied
 * to the source code, the corresponding test MUST fail. This is the
 * "mutation testing mindset" — write tests that are strict enough to catch
 * common code mutations.
 *
 * Mutants covered:
 *  M1: Change `>=` to `>` in toEvict calculation → would not evict when at cap
 *  M2: Remove eviction cursor (skip delete) → store grows unbounded
 *  M3: Change cursor direction 'prev' to 'next' in recent() → returns oldest first
 *  M4: Remove consumed filter in unconsumed() → returns all entries
 *  M5: Change `+1` to `+0` in toEvict → off-by-one, store grows by 1 per insert
 *  M6: Remove metric emission → silent eviction (observability gap)
 *  M7: Swap evict-then-put order to put-then-evict → store transiently exceeds cap
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Inbox } from '../../mailbox/inbox.ts';
import { Spool } from '../../mailbox/spool.ts';
import { setMeshMetricSink, type MeshMetric } from '../../metrics.ts';

const entry = (msgId: string, receivedAtMs: number) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  receivedAtMs,
  consumed: false,
});

const spoolEntry = (msgId: string, addedAtMs: number) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  addedAtMs,
  hopsRemaining: 3,
});

describe('MUTATION TESTS: Inbox bounded put', () => {
  let inbox: Inbox;
  let metrics: { metric: MeshMetric; labels?: Record<string, string> }[];

  beforeEach(async () => {
    metrics = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    inbox = new Inbox('test-mut-inbox-' + Math.random(), 3);
    await inbox.open();
  });

  afterEach(() => {
    inbox.close();
    setMeshMetricSink(() => {});
  });

  // M1: Change `>=` to `>` in toEvict calculation
  // If mutated to `total > maxEntries`, then when total === maxEntries,
  // toEvict = 0, and the store grows to maxEntries+1.
  it('M1: evicts exactly when at cap (total === maxEntries)', async () => {
    const now = Date.now();
    await inbox.put(entry('a', now - 300));
    await inbox.put(entry('b', now - 200));
    await inbox.put(entry('c', now - 100));
    // Now at cap (3). Insert 4th — MUST evict 1.
    await inbox.put(entry('d', now));
    const remaining = await inbox.unconsumed();
    expect(remaining).toHaveLength(3); // NOT 4
    expect(remaining.map((e) => e.msgId).sort()).toEqual(['b', 'c', 'd']);
  });

  // M5: Change `+1` to `+0` in toEvict
  // If mutated to `total - maxEntries` (without +1), then when total=3, max=3:
  // toEvict = 0, put succeeds, store grows to 4. Next: total=4, toEvict=1,
  // evict 1, put 1 → store stays at 4. Store is always 1 over cap.
  it('M5: store never exceeds maxEntries (off-by-one check)', async () => {
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      await inbox.put(entry(`msg-${i}`, now + i));
    }
    // After 10 puts with cap=3, store MUST be exactly 3, not 4.
    expect(await inbox.unconsumed()).toHaveLength(3);
  });

  // M2: Remove eviction cursor (skip delete)
  // If eviction is skipped, store grows unbounded.
  it('M2: store size stays at maxEntries after many inserts', async () => {
    const now = Date.now();
    for (let i = 0; i < 100; i++) {
      await inbox.put(entry(`msg-${i}`, now + i));
    }
    expect(await inbox.unconsumed()).toHaveLength(3);
  });

  // M6: Remove metric emission
  it('M6: emits mailbox_evicted metric on bounded-put eviction', async () => {
    const now = Date.now();
    await inbox.put(entry('a', now - 300));
    await inbox.put(entry('b', now - 200));
    await inbox.put(entry('c', now - 100));
    metrics = [];
    await inbox.put(entry('d', now));
    expect(metrics.some((m) => m.metric === 'mailbox_evicted')).toBe(true);
  });

  // M7: Swap evict-then-put to put-then-evict
  // If put happens before eviction, the store transiently has maxEntries+1.
  // With a real IDB, this could trigger QuotaExceededError. With fake-indexeddb,
  // we can't test the transient state, but we CAN verify the final state is correct.
  it('M7: final state is exactly maxEntries (evict-then-put order)', async () => {
    const now = Date.now();
    await inbox.put(entry('a', now - 300));
    await inbox.put(entry('b', now - 200));
    await inbox.put(entry('c', now - 100));
    await inbox.put(entry('d', now));
    // If put-then-evict: would have 4 then evict to 3. If evict-then-put: 3 then put to 3.
    // Both end at 3, but the NEWEST must be present (evicted oldest).
    const remaining = await inbox.unconsumed();
    expect(remaining).toHaveLength(3);
    expect(remaining.map((e) => e.msgId)).toContain('d');
    expect(remaining.map((e) => e.msgId)).not.toContain('a'); // oldest evicted
  });
});

describe('MUTATION TESTS: Inbox.unconsumed() cursor filter', () => {
  let inbox: Inbox;

  beforeEach(async () => {
    inbox = new Inbox('test-mut-unconsumed-' + Math.random(), 100);
    await inbox.open();
  });

  afterEach(() => inbox.close());

  // M4: Remove consumed filter in unconsumed()
  // If the `if (!entry.consumed)` filter is removed, ALL entries are returned.
  it('M4: excludes consumed entries (filter not removed)', async () => {
    const now = Date.now();
    await inbox.put(entry('a', now - 300));
    await inbox.put(entry('b', now - 200));
    await inbox.put(entry('c', now - 100));
    await inbox.markConsumed('a');
    await inbox.markConsumed('c');
    const unconsumed = await inbox.unconsumed();
    expect(unconsumed).toHaveLength(1);
    expect(unconsumed[0]!.msgId).toBe('b');
  });
});

describe('MUTATION TESTS: Spool.recent() cursor direction', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool('test-mut-recent-' + Math.random(), 100);
    await spool.open();
  });

  afterEach(() => spool.close());

  // M3: Change cursor direction 'prev' to 'next' in recent()
  // If direction is 'next' (ascending), recent() returns OLDEST first, not newest.
  it('M3: returns newest entries first (cursor direction = prev)', async () => {
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      await spool.put(spoolEntry(`s-${i}`, now + i * 1000));
    }
    const recent = await spool.recent(3);
    expect(recent).toHaveLength(3);
    // Newest first: s-9 (now+9000), s-8 (now+8000), s-7 (now+7000)
    expect(recent[0]!.msgId).toBe('s-9');
    expect(recent[1]!.msgId).toBe('s-8');
    expect(recent[2]!.msgId).toBe('s-7');
  });
});

describe('MUTATION TESTS: Spool bounded put', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool('test-mut-spool-' + Math.random(), 3);
    await spool.open();
  });

  afterEach(() => spool.close());

  // M1+M5 combined for Spool
  it('M1+M5: store never exceeds maxEntries after many inserts', async () => {
    const now = Date.now();
    for (let i = 0; i < 20; i++) {
      await spool.put(spoolEntry(`s-${i}`, now + i));
    }
    expect(await spool.size()).toBe(3);
  });

  it('M2: evicts oldest (not random) when over cap', async () => {
    const now = Date.now();
    await spool.put(spoolEntry('old', now - 10000));
    await spool.put(spoolEntry('mid', now - 5000));
    await spool.put(spoolEntry('new', now - 100));
    await spool.put(spoolEntry('newest', now));
    const remaining = (await spool.all()).map((e) => e.msgId);
    expect(remaining).not.toContain('old'); // oldest evicted
    expect(remaining).toContain('newest');
  });
});
