import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Inbox } from '../../mailbox/inbox.ts';
import { Spool } from '../../mailbox/spool.ts';

// ─── Inbox.evictExcess ────────────────────────────────────────────────────────

const inboxSample = (msgId: string, receivedAtMs: number) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  receivedAtMs,
  consumed: false,
});

describe('Inbox.evictExcess', () => {
  let inbox: Inbox;

  beforeEach(async () => {
    inbox = new Inbox('test-inbox-evict-' + Math.random());
    await inbox.open();
  });

  afterEach(() => inbox.close());

  it('returns 0 when store is at or below cap', async () => {
    // Insert 3 entries, cap = 5 → nothing to evict
    const now = Date.now();
    await inbox.put(inboxSample('msg-a', now - 300));
    await inbox.put(inboxSample('msg-b', now - 200));
    await inbox.put(inboxSample('msg-c', now - 100));
    const deleted = await inbox.evictExcess(5);
    expect(deleted).toBe(0);
    expect(await inbox.unconsumed()).toHaveLength(3);
  });

  it('evicts oldest entries when store exceeds cap', async () => {
    const now = Date.now();
    // Insert 7 entries; cap = 4 → 3 oldest should be evicted
    for (let i = 1; i <= 7; i++) {
      await inbox.put(inboxSample(`msg-${i}`, now - (8 - i) * 1000));
    }
    const deleted = await inbox.evictExcess(4);
    expect(deleted).toBe(3);
    const remaining = await inbox.unconsumed();
    expect(remaining).toHaveLength(4);
    // Oldest 3 (msg-1, msg-2, msg-3) evicted; newest 4 remain
    const remainingIds = remaining.map((e) => e.msgId).sort();
    expect(remainingIds).toEqual(['msg-4', 'msg-5', 'msg-6', 'msg-7']);
  });

  it('evicts oldest-first (lower receivedAtMs goes first)', async () => {
    const now = Date.now();
    await inbox.put(inboxSample('newest', now - 100));
    await inbox.put(inboxSample('oldest', now - 10000));
    await inbox.put(inboxSample('middle', now - 5000));
    // cap = 1, so 2 oldest deleted
    await inbox.evictExcess(1);
    const remaining = await inbox.unconsumed();
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!.msgId).toBe('newest');
  });

  it('throws if maxEntries is negative', async () => {
    await expect(inbox.evictExcess(-1)).rejects.toThrow('maxEntries must be >= 0');
  });
});

// ─── Spool.evictExcess ────────────────────────────────────────────────────────

const spoolSample = (msgId: string, addedAtMs: number) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  addedAtMs,
  hopsRemaining: 3,
});

describe('Spool.evictExcess', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool('test-spool-evict-' + Math.random());
    await spool.open();
  });

  afterEach(() => spool.close());

  it('returns 0 when store is at or below cap', async () => {
    const now = Date.now();
    await spool.put(spoolSample('s-a', now - 300));
    await spool.put(spoolSample('s-b', now - 200));
    const deleted = await spool.evictExcess(5);
    expect(deleted).toBe(0);
    expect(await spool.size()).toBe(2);
  });

  it('evicts oldest entries when store exceeds cap', async () => {
    const now = Date.now();
    for (let i = 1; i <= 6; i++) {
      await spool.put(spoolSample(`s-${i}`, now - (7 - i) * 1000));
    }
    const deleted = await spool.evictExcess(3);
    expect(deleted).toBe(3);
    expect(await spool.size()).toBe(3);
    const remaining = (await spool.all()).map((e) => e.msgId).sort();
    expect(remaining).toEqual(['s-4', 's-5', 's-6']);
  });

  it('evicts oldest-first (lower addedAtMs goes first)', async () => {
    const now = Date.now();
    await spool.put(spoolSample('newest', now - 100));
    await spool.put(spoolSample('oldest', now - 10000));
    await spool.put(spoolSample('middle', now - 5000));
    await spool.evictExcess(1);
    const remaining = await spool.all();
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!.msgId).toBe('newest');
  });

  it('throws if maxEntries is negative', async () => {
    await expect(spool.evictExcess(-1)).rejects.toThrow('maxEntries must be >= 0');
  });
});
