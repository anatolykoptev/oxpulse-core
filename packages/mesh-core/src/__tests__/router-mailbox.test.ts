import { describe, it, expect, vi, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';

// Must mock transport BEFORE importing router (vi.mock is hoisted).
let capturedOnFrame: ((peerIdHex: string, frame: Uint8Array) => void) | null = null;

vi.mock('../transport.js', () => ({
  meshState: { peers: [], advertising: false, scanning: false, error: null },
  sendFrame: vi.fn(async () => {}),
  onFrame: vi.fn((cb: (peerIdHex: string, frame: Uint8Array) => void) => {
    capturedOnFrame = cb;
    return () => {};
  }),
}));

vi.mock('../online-bridge.js', () => ({
  bridgeSend: vi.fn(async () => ({ ok: true as const, seq: 1 })),
}));

vi.mock('../token-client.js', () => ({
  getToken: vi.fn(async () => 'fake.jwt.token'),
}));

vi.mock('../dedupe.js', () => {
  const seenSet = new Set<string>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return {
    DedupeCache: function DedupeCache(this: any) {
      this.hasSeen = (channelId: string, msgId: string) => seenSet.has(`${channelId}:${msgId}`);
      this.markSeen = (channelId: string, msgId: string) => { seenSet.add(`${channelId}:${msgId}`); };
      this.clear = () => { seenSet.clear(); };
    },
  };
});

import { onIncoming } from '../router.js';
import { Inbox } from '../mailbox/inbox.ts';
import { BloomDedup } from '../mailbox/dedup-bloom.ts';
import { onFrame } from '../transport.js';

// Build a synthetic frame matching mesh-bundle-v1 wire layout used by router:
// msgId at byte 34..50 (16 B), channelIdHash at byte 55..59 (4 B). Other fields
// can be arbitrary because the dedupe path only reads those slices.
function makeFrame(msgIdHex: string, channelIdHex: string): Uint8Array {
  const f = new Uint8Array(125 + 1500);
  f[0] = 0xc9; // MAGIC
  f[1] = 0x01; // VERSION
  // msgId at 34..50 (pad short hex with leading zeros)
  const msgPadded = msgIdHex.padStart(32, '0');
  for (let i = 0; i < 16; i++) f[34 + i] = parseInt(msgPadded.substr(i * 2, 2), 16);
  // channelId at 55..59
  const chanPadded = channelIdHex.padStart(8, '0');
  for (let i = 0; i < 4; i++) f[55 + i] = parseInt(chanPadded.substr(i * 2, 2), 16);
  return f;
}

describe('Router mailbox integration', () => {
  beforeEach(() => {
    capturedOnFrame = null;
    vi.mocked(onFrame).mockImplementation((cb) => {
      capturedOnFrame = cb;
      return () => {};
    });
  });

  it('puts a newly received bundle into the inbox', async () => {
    const inbox = new Inbox('test-inbox-' + Math.random());
    await inbox.open();
    const bloom = new BloomDedup({ dbName: 'test-bloom-' + Math.random() });
    await bloom.open();

    const handler = vi.fn();
    const unsub = onIncoming({ handler, inbox, bloom });

    expect(capturedOnFrame).not.toBeNull();
    const msgId = '0102030405060708090a0b0c0d0e0f10';
    const channelId = 'aabbccdd';
    capturedOnFrame!('peer-1', makeFrame(msgId, channelId));

    // Inbox put is async — yield a microtask cycle.
    await Promise.resolve();
    await Promise.resolve();

    const entries = await inbox.unconsumed();
    expect(entries.map((e) => e.msgId)).toContain(msgId);
    expect(bloom.hasSeen(msgId)).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);

    unsub();
    inbox.close();
    bloom.close();
  });

  it('drops a duplicate (Bloom hit) before inbox.put', async () => {
    const inbox = new Inbox('test-inbox-' + Math.random());
    await inbox.open();
    const bloom = new BloomDedup({ dbName: 'test-bloom-' + Math.random() });
    await bloom.open();

    const msgId = 'deadbeefcafebabe0123456789abcdef';
    bloom.markSeen(msgId);

    const putSpy = vi.spyOn(inbox, 'put');
    const handler = vi.fn();
    const unsub = onIncoming({ handler, inbox, bloom });

    capturedOnFrame!('peer-1', makeFrame(msgId, 'aabbccdd'));
    await Promise.resolve();

    expect(putSpy).not.toHaveBeenCalled();
    expect(handler).not.toHaveBeenCalled();

    unsub();
    inbox.close();
    bloom.close();
  });

  it('works without mailbox args (backward compat)', () => {
    const handler = vi.fn();
    const unsub = onIncoming({ handler });
    expect(capturedOnFrame).not.toBeNull();
    capturedOnFrame!('peer-1', makeFrame('11', '22'));
    expect(handler).toHaveBeenCalledTimes(1);
    unsub();
  });
});
