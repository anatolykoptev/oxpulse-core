import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Inbox, MESH_INBOX_DB_NAME, MESH_INBOX_STORE_NAME } from '../../mailbox/inbox.ts';

const sample = (msgId: string, ageMs = 0) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  receivedAtMs: Date.now() - ageMs,
  consumed: false,
});

describe('Inbox', () => {
  let inbox: Inbox;

  beforeEach(async () => {
    inbox = new Inbox('test-inbox-' + Math.random());
    await inbox.open();
  });

  afterEach(() => inbox.close());

  it('stores and retrieves a received bundle', async () => {
    await inbox.put(sample('msg-1'));
    const all = await inbox.unconsumed();
    expect(all).toHaveLength(1);
    expect(all[0]!.msgId).toBe('msg-1');
    expect(all[0]!.consumed).toBe(false);
  });

  it('marks consumed and excludes from unconsumed()', async () => {
    await inbox.put(sample('msg-2'));
    await inbox.markConsumed('msg-2');
    expect(await inbox.unconsumed()).toHaveLength(0);
  });

  it('evicts entries older than TTL', async () => {
    const old = sample('msg-old', 8 * 24 * 60 * 60 * 1000); // 8 days
    const fresh = sample('msg-fresh', 1 * 60 * 60 * 1000); // 1 hour
    await inbox.put(old);
    await inbox.put(fresh);
    await inbox.evictOlderThan(7 * 24 * 60 * 60 * 1000); // 7 day TTL
    const remaining = await inbox.unconsumed();
    expect(remaining.map((e) => e.msgId)).toEqual(['msg-fresh']);
  });

  it('exports canonical store names', () => {
    expect(MESH_INBOX_DB_NAME).toBe('mesh-router-inbox');
    expect(MESH_INBOX_STORE_NAME).toBe('inbox');
  });

  it('put is idempotent on msgId (latest wins)', async () => {
    await inbox.put(sample('msg-dup'));
    await inbox.put({ ...sample('msg-dup'), consumed: true });
    const all = await inbox.unconsumed();
    expect(all).toHaveLength(0); // most recent marks consumed=true, hidden from unconsumed()
  });
});
