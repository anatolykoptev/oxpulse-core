/**
 * spool-race.test.ts — B5: tests that concurrent decrementHops calls
 * are atomic — hopsRemaining decrements correctly, not lost.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Spool, MESH_SPOOL_DB_NAME } from '../mailbox/spool.js';

describe('B5: spool decrementHops atomicity (issue #9)', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool(`test-spool-race-${Date.now()}-${Math.random()}`);
    await spool.open();
  });

  afterEach(() => {
    spool.close();
  });

  // ── Test 1: concurrent decrementHops — hops decrement correctly ─────────
  it('M1: concurrent decrementHops calls each decrement hopsRemaining', async () => {
    await spool.put({
      msgId: 'msg-hop-race',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      addedAtMs: Date.now(),
      hopsRemaining: 5,
    });

    // Fire 3 concurrent decrementHops calls.
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

  // ── Test 2: decrementHops to 0 deletes the entry ────────────────────────
  it('decrementHops to 0 deletes the entry atomically', async () => {
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

  // ── Test 3: concurrent decrementHops to 0 — only one survives, rest no-op ─
  it('concurrent decrementHops when hops=1 → entry deleted, no negative hops', async () => {
    await spool.put({
      msgId: 'msg-hop-concurrent-zero',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      addedAtMs: Date.now(),
      hopsRemaining: 1,
    });

    // Fire 3 concurrent decrementHops — only first should succeed, rest no-op.
    await Promise.all([
      spool.decrementHops('msg-hop-concurrent-zero'),
      spool.decrementHops('msg-hop-concurrent-zero'),
      spool.decrementHops('msg-hop-concurrent-zero'),
    ]);

    const entries = await spool.all();
    expect(entries.find((e) => e.msgId === 'msg-hop-concurrent-zero')).toBeUndefined();
  });

  // ── Test 4: decrementHops on non-existent msgId is a no-op ──────────────
  it('decrementHops on non-existent msgId resolves without error', async () => {
    await expect(spool.decrementHops('nonexistent')).resolves.toBeUndefined();
  });

  // ── Test 5: sequential decrementHops ────────────────────────────────────
  it('sequential decrementHops calls decrement correctly', async () => {
    await spool.put({
      msgId: 'msg-hop-seq',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
      addedAtMs: Date.now(),
      hopsRemaining: 3,
    });

    await spool.decrementHops('msg-hop-seq');
    await spool.decrementHops('msg-hop-seq');

    const entries = await spool.all();
    const entry = entries.find((e) => e.msgId === 'msg-hop-seq');
    expect(entry).toBeDefined();
    expect(entry!.hopsRemaining).toBe(1);
  });
});
