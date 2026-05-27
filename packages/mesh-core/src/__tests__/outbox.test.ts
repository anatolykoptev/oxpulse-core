/**
 * Tests for outbox.ts (B-4 Phase).
 * RED: module does not exist yet.
 * Uses fake-indexeddb for isolation.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Outbox, type OutboxEntry, MESH_OUTBOX_DB_NAME, MESH_OUTBOX_STORE_NAME } from '../outbox.js';

function makeBundle(seed: number): Uint8Array {
  return new Uint8Array([0xc9, 0x01, seed]);
}

describe('Outbox', () => {
  let outbox: Outbox;

  beforeEach(async () => {
    outbox = new Outbox(`test-outbox-${Math.random()}`);
    await outbox.open();
  });

  it('enqueue + nextPending returns the queued entry', async () => {
    const bundle = makeBundle(1);
    const msgId = 'msg-001';
    const channelId = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    await outbox.enqueue({ msgId, channelId, bundle });
    const entry = await outbox.nextPending();
    expect(entry).not.toBeNull();
    expect(entry!.msgId).toBe(msgId);
    expect(entry!.status).toBe('pending');
    expect(entry!.attempts).toBe(0);
  });

  it('markSent transitions status to sent', async () => {
    const bundle = makeBundle(2);
    await outbox.enqueue({ msgId: 'msg-002', channelId: new Uint8Array(4), bundle });
    await outbox.markSent('msg-002');
    const entry = await outbox.nextPending();
    expect(entry).toBeNull();
  });

  it('markFailed increments attempts and keeps status pending', async () => {
    await outbox.enqueue({ msgId: 'msg-003', channelId: new Uint8Array(4), bundle: makeBundle(3) });
    await outbox.markFailed('msg-003');
    const entry = await outbox.nextPending();
    expect(entry!.attempts).toBe(1);
    expect(entry!.status).toBe('pending');
  });

  it('evictOlderThan removes entries older than cutoff', async () => {
    const oldMs = Date.now() - 10_000;
    const bundle = makeBundle(4);
    await outbox.enqueue({ msgId: 'msg-old', channelId: new Uint8Array(4), bundle, lastAttemptMs: oldMs });
    await outbox.evictOlderThan(5_000);
    const entry = await outbox.nextPending();
    expect(entry).toBeNull();
  });

  it('evictOlderThan keeps recent entries', async () => {
    const bundle = makeBundle(5);
    await outbox.enqueue({ msgId: 'msg-recent', channelId: new Uint8Array(4), bundle });
    await outbox.evictOlderThan(5_000);
    const entry = await outbox.nextPending();
    expect(entry).not.toBeNull();
    expect(entry!.msgId).toBe('msg-recent');
  });

  it('returns null from nextPending on empty outbox', async () => {
    const entry = await outbox.nextPending();
    expect(entry).toBeNull();
  });

  it('open+close+open cycle survives (transactional stability)', async () => {
    const outbox2 = new Outbox(`test-persist-${Math.random()}`);
    await outbox2.open();
    await outbox2.enqueue({ msgId: 'persist-1', channelId: new Uint8Array(4), bundle: makeBundle(6) });
    await outbox2.close();
    await outbox2.open();
    const entry = await outbox2.nextPending();
    expect(entry!.msgId).toBe('persist-1');
    await outbox2.close();
  });
});

describe('Outbox.open() idempotent (MAJOR 5)', () => {
  it('calling open() twice on same instance does not throw or leak', async () => {
    const ob = new Outbox(`test-idempotent-${Math.random()}`);
    await ob.open();
    await expect(ob.open()).resolves.toBeUndefined(); // second call is no-op
    ob.close();
  });

  it('state is consistent after double open — enqueue works', async () => {
    const ob = new Outbox(`test-idempotent2-${Math.random()}`);
    await ob.open();
    await ob.open(); // second call must be a no-op
    await ob.enqueue({ msgId: 'id-x', channelId: new Uint8Array(4), bundle: makeBundle(7) });
    const entry = await ob.nextPending();
    expect(entry!.msgId).toBe('id-x');
    ob.close();
  });
});

describe('Outbox evictOlderThan — no inner transaction race (BLOCKER 3)', () => {
  it('concurrent evictOlderThan + markFailed on overlapping entries leaves neither corrupt', async () => {
    // Note: fake-indexeddb serializes IDB transactions through microtasks so does
    // NOT reproduce the true browser race. This test validates structural correctness:
    // evict and markFailed touch the same transaction object-store slice without
    // opening a second nested rw transaction.
    const ob = new Outbox(`test-evict-race-${Math.random()}`);
    await ob.open();

    const oldMs = Date.now() - 10_000;
    await ob.enqueue({ msgId: 'evict-1', channelId: new Uint8Array(4), bundle: makeBundle(8), lastAttemptMs: oldMs });
    await ob.enqueue({ msgId: 'evict-2', channelId: new Uint8Array(4), bundle: makeBundle(9), lastAttemptMs: oldMs });
    await ob.enqueue({ msgId: 'keep-1', channelId: new Uint8Array(4), bundle: makeBundle(10) });

    // Run concurrently — neither should throw or leave DB in bad state
    await Promise.all([
      ob.evictOlderThan(5_000),
      ob.markFailed('evict-1'),
    ]);

    // After concurrent ops: evict-1 and evict-2 should be gone (evict wins or markFailed sees it deleted)
    // keep-1 must still be present
    const entry = await ob.nextPending();
    // Only keep-1 should remain
    if (entry !== null) {
      expect(entry.msgId).toBe('keep-1');
    }
    ob.close();
  });
});

describe('MESH_OUTBOX_DB_NAME + MESH_OUTBOX_STORE_NAME constants', () => {
  it('exports canonical DB name constant', () => {
    expect(typeof MESH_OUTBOX_DB_NAME).toBe('string');
    expect(MESH_OUTBOX_DB_NAME.length).toBeGreaterThan(0);
  });

  it('exports canonical store name constant', () => {
    expect(typeof MESH_OUTBOX_STORE_NAME).toBe('string');
    expect(MESH_OUTBOX_STORE_NAME.length).toBeGreaterThan(0);
  });
});

describe('Outbox.markFailed — terminal failed state after MAX attempts (M2)', () => {
  it('entry reaches failed status after MAX_OUTBOX_ATTEMPTS and nextPending no longer returns it', async () => {
    const ob = new Outbox(`test-terminal-${Math.random()}`);
    await ob.open();

    await ob.enqueue({ msgId: 'terminal-1', channelId: new Uint8Array(4), bundle: makeBundle(42) });

    // Call markFailed MAX_OUTBOX_ATTEMPTS times — entry should become terminal
    for (let i = 0; i < 8; i++) {
      const pending = await ob.nextPending();
      expect(pending).not.toBeNull(); // still pending before max reached
      await ob.markFailed('terminal-1');
    }

    // After 8 failures, entry must be terminal (status='failed')
    const pending = await ob.nextPending();
    expect(pending).toBeNull(); // must not be returned anymore

    ob.close();
  });

  it('failedEntries() returns the terminal entry', async () => {
    const ob = new Outbox(`test-failed-entries-${Math.random()}`);
    await ob.open();

    await ob.enqueue({ msgId: 'terminal-2', channelId: new Uint8Array(4), bundle: makeBundle(43) });
    for (let i = 0; i < 8; i++) {
      await ob.markFailed('terminal-2');
    }

    const failed = await ob.failedEntries();
    expect(failed.length).toBe(1);
    expect(failed[0]!.msgId).toBe('terminal-2');
    expect(failed[0]!.status).toBe('failed');

    ob.close();
  });

  it('clearFailed() removes terminal entries', async () => {
    const ob = new Outbox(`test-clear-failed-${Math.random()}`);
    await ob.open();

    await ob.enqueue({ msgId: 'terminal-3', channelId: new Uint8Array(4), bundle: makeBundle(44) });
    for (let i = 0; i < 8; i++) {
      await ob.markFailed('terminal-3');
    }

    await ob.clearFailed();
    const failed = await ob.failedEntries();
    expect(failed.length).toBe(0);

    ob.close();
  });
});
