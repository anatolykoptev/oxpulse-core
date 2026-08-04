/**
 * outbox-bounded.test.ts — S6: tests that outbox enqueue is bounded
 * and evicts oldest entries when the cap is exceeded.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Outbox, MESH_OUTBOX_MAX_ENTRIES, MAX_OUTBOX_ATTEMPTS } from '../outbox.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';

describe('S6: outbox bounded enqueue (issue #15)', () => {
  let outbox: Outbox;

  beforeEach(async () => {
    outbox = new Outbox(`test-outbox-bounded-${Date.now()}-${Math.random()}`);
    await outbox.open();
  });

  afterEach(() => {
    outbox.close();
  });

  // ── Test 1: enqueue under cap works normally ────────────────────────────
  it('enqueue under cap works normally', async () => {
    await outbox.enqueue({
      msgId: 'msg-1',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });
    expect(await outbox.size()).toBe(1);
  });

  // ── Test 2: evictExcess removes oldest entries ──────────────────────────
  it('M1: evictExcess removes oldest entries to enforce cap', async () => {
    // Insert 10 entries with increasing lastAttemptMs.
    for (let i = 0; i < 10; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: i * 1000,
      });
    }
    expect(await outbox.size()).toBe(10);

    // Evict to 5.
    const evicted = await outbox.evictExcess(5);
    expect(evicted).toBe(5);
    expect(await outbox.size()).toBe(5);

    // Verify the OLDEST 5 were removed (msg-0 through msg-4).
    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').getAll();
    const entries = await new Promise<unknown[]>((resolve) => {
      req.onsuccess = () => resolve(req.result as unknown[]);
    });
    const msgIds = (entries as { msgId: string }[]).map((e) => e.msgId).sort();
    expect(msgIds).toEqual(['msg-5', 'msg-6', 'msg-7', 'msg-8', 'msg-9']);
  });

  // ── Test 3: evictExcess with count under cap is a no-op ─────────────────
  it('evictExcess with count under cap is a no-op', async () => {
    await outbox.enqueue({
      msgId: 'msg-1',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });
    const evicted = await outbox.evictExcess(100);
    expect(evicted).toBe(0);
    expect(await outbox.size()).toBe(1);
  });

  // ── Test 4: evictExcess emits metric ────────────────────────────────────
  it('M2: evictExcess emits mailbox_evicted metric', async () => {
    const metrics: { metric: MeshMetric; labels?: Record<string, string> }[] = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    try {
      for (let i = 0; i < 5; i++) {
        await outbox.enqueue({
          msgId: `msg-${i}`,
          channelId: new Uint8Array([1, 2, 3, 4]),
          bundle: new Uint8Array([0xc9, 0x01]),
          lastAttemptMs: i * 1000,
        });
      }
      await outbox.evictExcess(2);
      const evictMetrics = metrics.filter((m) => m.metric === 'mailbox_evicted' && m.labels?.store === 'outbox');
      expect(evictMetrics).toHaveLength(1);
      expect(evictMetrics[0]!.labels?.count).toBe('3');
    } finally {
      setMeshMetricSink(() => {});
    }
  });

  // ── Test 5: size() returns correct count ────────────────────────────────
  it('size() returns correct entry count', async () => {
    expect(await outbox.size()).toBe(0);
    for (let i = 0; i < 5; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
      });
    }
    expect(await outbox.size()).toBe(5);
  });
});
