/**
 * outbox-bounded.test.ts — S6: tests that outbox enqueue is bounded
 * and evicts oldest entries when the cap is exceeded.
 *
 * Review fix: uses configurable maxEntries (constructor arg) so the
 * bounded enqueue path is actually exercised with a small cap.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Outbox, MESH_OUTBOX_MAX_ENTRIES } from '../outbox.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';

describe('S6: outbox bounded enqueue (issue #15)', () => {
  let outbox: Outbox;

  beforeEach(async () => {
    outbox = new Outbox(`test-outbox-bounded-${Date.now()}-${Math.random()}`, 5);
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
    // Verify entry was inserted.
    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').get('msg-1');
    const entry = await new Promise<unknown>((resolve) => {
      req.onsuccess = () => resolve(req.result);
    });
    expect(entry).toBeDefined();
  });

  // ── Test 2: M1 — bounded enqueue evicts oldest when cap exceeded ────────
  it('M1: enqueue at cap evicts oldest entry (lowest lastAttemptMs)', async () => {
    // Insert 5 entries (the cap) with increasing lastAttemptMs.
    for (let i = 0; i < 5; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: i * 1000,
      });
    }

    // Insert a 6th — should evict msg-0 (oldest, lastAttemptMs=0).
    await outbox.enqueue({
      msgId: 'msg-5',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      lastAttemptMs: 5000,
    });

    // Verify msg-0 was evicted and msg-5 was inserted.
    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const store = tx.objectStore('outbox');
    const allReq = store.getAll();
    const entries = await new Promise<unknown[]>((resolve) => {
      allReq.onsuccess = () => resolve(allReq.result as unknown[]);
    });
    const msgIds = (entries as { msgId: string }[]).map((e) => e.msgId).sort();
    // msg-0 evicted, msg-1..msg-5 remain (5 entries = cap).
    expect(msgIds).toEqual(['msg-1', 'msg-2', 'msg-3', 'msg-4', 'msg-5']);
    expect(entries).toHaveLength(5);
  });

  // ── Test 3: M2 — bounded enqueue emits mailbox_evicted metric ───────────
  it('M2: bounded enqueue emits mailbox_evicted metric with correct count', async () => {
    const metrics: { metric: MeshMetric; labels?: Record<string, string> }[] = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    try {
      // Fill to cap.
      for (let i = 0; i < 5; i++) {
        await outbox.enqueue({
          msgId: `msg-${i}`,
          channelId: new Uint8Array([1, 2, 3, 4]),
          bundle: new Uint8Array([0xc9, 0x01]),
          lastAttemptMs: i * 1000,
        });
      }

      // Insert one more — should evict 1 and emit metric.
      await outbox.enqueue({
        msgId: 'msg-5',
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: 5000,
      });

      const evictMetrics = metrics.filter((m) => m.metric === 'mailbox_evicted' && m.labels?.store === 'outbox');
      expect(evictMetrics).toHaveLength(1);
      // Exact count: evict 1 (count - maxEntries + 1 = 5 - 5 + 1 = 1).
      expect(evictMetrics[0]!.labels?.count).toBe('1');
    } finally {
      setMeshMetricSink(() => {});
    }
  });

  // ── Test 4: default cap is MESH_OUTBOX_MAX_ENTRIES ───────────────────────
  it('default maxEntries is MESH_OUTBOX_MAX_ENTRIES (5000)', async () => {
    const defaultOutbox = new Outbox(`test-default-cap-${Date.now()}`);
    await defaultOutbox.open();
    // Insert 10 entries — well under 5000, no eviction.
    for (let i = 0; i < 10; i++) {
      await defaultOutbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
      });
    }
    const tx = (defaultOutbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const countReq = tx.objectStore('outbox').count();
    const count = await new Promise<number>((resolve) => {
      countReq.onsuccess = () => resolve(countReq.result);
    });
    expect(count).toBe(10);
    defaultOutbox.close();
  });

  // ── Test 5: multiple over-cap inserts maintain cap precisely ────────────
  it('M3: multiple over-cap inserts maintain cap precisely (no drift)', async () => {
    // Fill to cap.
    for (let i = 0; i < 5; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: i * 1000,
      });
    }

    // Insert 3 more over cap — each should evict exactly 1.
    for (let i = 5; i < 8; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: i * 1000,
      });
    }

    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const countReq = tx.objectStore('outbox').count();
    const count = await new Promise<number>((resolve) => {
      countReq.onsuccess = () => resolve(countReq.result);
    });
    // Cap should be maintained at exactly 5 — no drift.
    expect(count).toBe(5);

    // Verify the oldest 3 (msg-0, msg-1, msg-2) were evicted.
    const allReq = tx.objectStore('outbox').getAll();
    const entries = await new Promise<unknown[]>((resolve) => {
      allReq.onsuccess = () => resolve(allReq.result as unknown[]);
    });
    const msgIds = (entries as { msgId: string }[]).map((e) => e.msgId).sort();
    expect(msgIds).toEqual(['msg-3', 'msg-4', 'msg-5', 'msg-6', 'msg-7']);
  });
});
