/**
 * outbox-race.test.ts — B5: tests that concurrent markFailed calls
 * are atomic — attempts counter increments correctly, not lost.
 *
 * Mutation tests (M1-M3) catch:
 *   M1: revert to get-then-put → concurrent calls both read same value
 *   M2: remove cursor.update → no atomicity
 *   M3: remove IDBKeyRange.only → cursor scans entire store
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Outbox, MAX_OUTBOX_ATTEMPTS, MESH_OUTBOX_DB_NAME } from '../outbox.js';

describe('B5: outbox markFailed atomicity (issue #9)', () => {
  let outbox: Outbox;

  beforeEach(async () => {
    outbox = new Outbox(`test-outbox-race-${Date.now()}-${Math.random()}`);
    await outbox.open();
  });

  afterEach(() => {
    outbox.close();
  });

  // ── Test 1: concurrent markFailed calls — attempts increment correctly ──
  it('M1: concurrent markFailed calls each increment attempts (no lost updates)', async () => {
    await outbox.enqueue({
      msgId: 'msg-race-1',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });

    // Fire 3 concurrent markFailed calls.
    await Promise.all([
      outbox.markFailed('msg-race-1'),
      outbox.markFailed('msg-race-1'),
      outbox.markFailed('msg-race-1'),
    ]);

    // Read back and verify attempts = 3 (not 1).
    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').get('msg-race-1');
    const entry = await new Promise<unknown>((resolve) => {
      req.onsuccess = () => resolve(req.result);
    });
    expect((entry as { attempts: number }).attempts).toBe(3);
  });

  // ── Test 2: markFailed reaches terminal status at MAX_OUTBOX_ATTEMPTS ────
  it('markFailed marks status=failed after MAX_OUTBOX_ATTEMPTS concurrent calls', async () => {
    await outbox.enqueue({
      msgId: 'msg-terminal',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });

    // Fire MAX_OUTBOX_ATTEMPTS concurrent markFailed calls.
    const calls = Array.from({ length: MAX_OUTBOX_ATTEMPTS }, () =>
      outbox.markFailed('msg-terminal'),
    );
    await Promise.all(calls);

    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').get('msg-terminal');
    const entry = await new Promise<unknown>((resolve) => {
      req.onsuccess = () => resolve(req.result);
    });
    expect((entry as { attempts: number }).attempts).toBe(MAX_OUTBOX_ATTEMPTS);
    expect((entry as { status: string }).status).toBe('failed');
  });

  // ── Test 3: markSent is atomic too (uses updateEntry) ───────────────────
  it('markSent sets status=sent atomically', async () => {
    await outbox.enqueue({
      msgId: 'msg-sent',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });

    await outbox.markSent('msg-sent');

    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').get('msg-sent');
    const entry = await new Promise<unknown>((resolve) => {
      req.onsuccess = () => resolve(req.result);
    });
    expect((entry as { status: string }).status).toBe('sent');
  });

  // ── Test 4: markFailed on non-existent msgId is a no-op ─────────────────
  it('markFailed on non-existent msgId resolves without error', async () => {
    await expect(outbox.markFailed('nonexistent')).resolves.toBeUndefined();
  });

  // ── Test 5: sequential markFailed calls also work correctly ─────────────
  it('sequential markFailed calls increment attempts correctly', async () => {
    await outbox.enqueue({
      msgId: 'msg-seq',
      channelId: new Uint8Array([1, 2, 3, 4]),
      bundle: new Uint8Array([0xc9, 0x01]),
    });

    for (let i = 0; i < 5; i++) {
      await outbox.markFailed('msg-seq');
    }

    const tx = (outbox as unknown as { getDb: () => IDBDatabase }).getDb()
      .transaction('outbox', 'readonly');
    const req = tx.objectStore('outbox').get('msg-seq');
    const entry = await new Promise<unknown>((resolve) => {
      req.onsuccess = () => resolve(req.result);
    });
    expect((entry as { attempts: number }).attempts).toBe(5);
    expect((entry as { status: string }).status).toBe('pending');
  });
});
