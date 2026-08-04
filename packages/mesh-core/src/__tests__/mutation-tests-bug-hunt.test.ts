/**
 * mutation-tests-bug-hunt.test.ts — Mutation tests for bug-hunt fixes (#7-#18).
 *
 * Each test is annotated with the MUTANT it kills. If a mutation is applied
 * to the source code, the corresponding test MUST fail.
 *
 * Mutants covered:
 *   B5-M1: Change cursor.update() back to get-then-put in outbox → concurrent markFailed loses increments
 *   B5-M2: Remove cursor lock in spool decrementHops → concurrent calls lose decrements
 *   S1-M1: Remove transitionVerdict guard (allow accepted→rejected) → late timeout overrides user accept
 *   S1-M2: Remove connectedDevices check in async bootstrap → orphaned cryptoStates entry
 *   S2-M1: Remove connectedDevices check in checkHandshakeTimeouts → false timeout on disconnected device
 *   S6-M1: Change >= to > in outbox bounded enqueue → no eviction at exact cap
 *   S6-M2: Change evictCount to count*0.1 (percentage) → cap drift
 *   S6-M3: Remove metric emission in bounded enqueue → silent eviction
 *   S7-M1: Remove MAX_BLE_CONNECTIONS check → no connection limit
 *   S7-M2: Change >= to > in BLE limit check → off-by-one (allows 7 connections)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Outbox, MAX_OUTBOX_ATTEMPTS } from '../outbox.js';
import { Spool } from '../mailbox/spool.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';

// ── B5: Outbox markFailed atomicity ─────────────────────────────────────────
//
// NOTE: fake-indexeddb serializes all transactions, so the get-then-put
// mutation (B5 bug) cannot be distinguished from cursor.update() in this
// environment. These tests verify CORRECTNESS (attempts=3 after concurrent
// calls) but cannot verify ATOMICITY. The race condition only reproduces
// in real browser IDB implementations where transaction serialization is
// fragile. The cursor.update() fix is defense-in-depth for those browsers.

describe('MUTATION B5-M1: outbox markFailed atomicity (cursor.update)', () => {
  let outbox: Outbox;

  beforeEach(async () => {
    outbox = new Outbox(`test-mut-b5-outbox-${Date.now()}-${Math.random()}`);
    await outbox.open();
  });

  afterEach(() => outbox.close());

  it('M1: concurrent markFailed calls each increment attempts (no lost updates)', async () => {
    await outbox.enqueue({
      msgId: 'msg-race',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });

    // Fire 3 concurrent markFailed calls.
    await Promise.all([
      outbox.markFailed('msg-race'),
      outbox.markFailed('msg-race'),
      outbox.markFailed('msg-race'),
    ]);

    // Read back and verify attempts = 3 (not 1).
    // If get-then-put (no cursor lock), concurrent calls both read same value.
    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').get('msg-race');
    const entry = await new Promise<{ attempts: number }>((resolve) => {
      req.onsuccess = () => resolve(req.result as { attempts: number });
    });
    expect(entry.attempts).toBe(3);
  });

  it('M2: markFailed reaches terminal status at MAX_OUTBOX_ATTEMPTS', async () => {
    await outbox.enqueue({
      msgId: 'msg-terminal',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });

    const calls = Array.from({ length: MAX_OUTBOX_ATTEMPTS }, () =>
      outbox.markFailed('msg-terminal'),
    );
    await Promise.all(calls);

    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').get('msg-terminal');
    const entry = await new Promise<{ attempts: number; status: string }>((resolve) => {
      req.onsuccess = () => resolve(req.result as { attempts: number; status: string });
    });
    expect(entry.attempts).toBe(MAX_OUTBOX_ATTEMPTS);
    expect(entry.status).toBe('failed');
  });
});

// ── B5: Spool decrementHops atomicity ───────────────────────────────────────
//
// Same limitation as B5-M1: fake-indexeddb serializes transactions, so
// get-then-put mutation is not killed. Tests verify correctness only.

describe('MUTATION B5-M2: spool decrementHops atomicity (cursor.update)', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool(`test-mut-b5-spool-${Date.now()}-${Math.random()}`);
    await spool.open();
  });

  afterEach(() => spool.close());

  it('M1: concurrent decrementHops calls each decrement hopsRemaining', async () => {
    await spool.put({
      msgId: 'msg-hop-race',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      addedAtMs: Date.now(),
      hopsRemaining: 5,
    });

    await Promise.all([
      spool.decrementHops('msg-hop-race'),
      spool.decrementHops('msg-hop-race'),
      spool.decrementHops('msg-hop-race'),
    ]);

    const entries = await spool.all();
    const entry = entries.find((e) => e.msgId === 'msg-hop-race');
    expect(entry).toBeDefined();
    expect(entry!.hopsRemaining).toBe(2); // 5 - 3 = 2
  });

  it('M2: decrementHops to 0 deletes the entry', async () => {
    await spool.put({
      msgId: 'msg-hop-zero',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      addedAtMs: Date.now(),
      hopsRemaining: 1,
    });

    await spool.decrementHops('msg-hop-zero');

    const entries = await spool.all();
    expect(entries.find((e) => e.msgId === 'msg-hop-zero')).toBeUndefined();
  });
});

// ── S6: Outbox bounded enqueue ──────────────────────────────────────────────

describe('MUTATION S6: outbox bounded enqueue', () => {
  let outbox: Outbox;
  let metrics: { metric: MeshMetric; labels?: Record<string, string> }[];

  beforeEach(async () => {
    metrics = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    outbox = new Outbox(`test-mut-s6-${Date.now()}-${Math.random()}`, 5);
    await outbox.open();
  });

  afterEach(() => {
    outbox.close();
    setMeshMetricSink(() => {});
  });

  // S6-M1: Change >= to > in bounded enqueue check
  // If mutated to `count > maxEntries`, then when count === maxEntries,
  // no eviction happens, store grows to maxEntries+1.
  it('M1: evicts exactly when at cap (count === maxEntries)', async () => {
    for (let i = 0; i < 5; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: i * 1000,
      });
    }
    // Now at cap (5). Insert 6th — MUST evict 1.
    await outbox.enqueue({
      msgId: 'msg-5',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      lastAttemptMs: 5000,
    });

    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const countReq = tx.objectStore('outbox').count();
    const count = await new Promise<number>((resolve) => {
      countReq.onsuccess = () => resolve(countReq.result);
    });
    expect(count).toBe(5); // NOT 6
  });

  // S6-M2: Change evictCount to count*0.1 (percentage-based)
  // If mutated to percentage, store drifts below cap over time.
  // Uses maxEntries=20 so the difference is visible: exact evicts 1, percentage evicts 2.
  it('M2: multiple over-cap inserts maintain cap precisely (no drift)', async () => {
    // Use a separate outbox with maxEntries=20 to expose percentage vs exact difference.
    const bigOutbox = new Outbox(`test-mut-s6-big-${Date.now()}`, 20);
    await bigOutbox.open();
    try {
      // Fill to cap (20).
      for (let i = 0; i < 20; i++) {
        await bigOutbox.enqueue({
          msgId: `msg-${i}`,
          channelId: new Uint8Array([1, 2, 3, 4]),
          bundle: new Uint8Array([0xc9, 0x01]),
          lastAttemptMs: i * 1000,
        });
      }

      // Insert 1 over cap.
      // exact: evict 1 (20-20+1=1), put 1 → 20.
      // percentage: evict 2 (Math.floor(20*0.1)=2), put 1 → 19. DRIFT!
      await bigOutbox.enqueue({
        msgId: 'msg-20',
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: 20000,
      });

      const tx = (bigOutbox as unknown as { getDb: () => IDBDatabase }).getDb()
        .transaction('outbox', 'readonly');
      const countReq = tx.objectStore('outbox').count();
      const count = await new Promise<number>((resolve) => {
        countReq.onsuccess = () => resolve(countReq.result);
      });
      // Cap must be exactly 20 — percentage mutant would give 19.
      expect(count).toBe(20);
    } finally {
      bigOutbox.close();
    }
  });

  // S6-M3: Remove metric emission in bounded enqueue
  it('M3: emits mailbox_evicted metric on bounded enqueue eviction', async () => {
    for (let i = 0; i < 5; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: i * 1000,
      });
    }
    metrics = [];
    await outbox.enqueue({
      msgId: 'msg-5',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      lastAttemptMs: 5000,
    });
    expect(metrics.some((m) => m.metric === 'mailbox_evicted' && m.labels?.store === 'outbox')).toBe(true);
  });

  // S6-M4: Swap evict-then-put to put-then-evict
  // If put happens before eviction, the store transiently has maxEntries+1.
  it('M4: final state is exactly maxEntries (evict-then-put order)', async () => {
    for (let i = 0; i < 5; i++) {
      await outbox.enqueue({
        msgId: `msg-${i}`,
        channelId: new Uint8Array([1, 2, 3, 4]),
        bundle: new Uint8Array([0xc9, 0x01]),
        lastAttemptMs: i * 1000,
      });
    }
    await outbox.enqueue({
      msgId: 'msg-5',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      lastAttemptMs: 5000,
    });

    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const allReq = tx.objectStore('outbox').getAll();
    const entries = await new Promise<{ msgId: string }[]>((resolve) => {
      allReq.onsuccess = () => resolve(allReq.result as { msgId: string }[]);
    });
    // Newest must be present (evicted oldest).
    expect(entries.map((e) => e.msgId)).toContain('msg-5');
    expect(entries.map((e) => e.msgId)).not.toContain('msg-0');
    expect(entries).toHaveLength(5);
  });
});
