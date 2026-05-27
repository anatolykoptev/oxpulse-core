/**
 * Tests for router.ts (B-4 Phase).
 * RED: module does not exist yet.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';

// Mock BLE transport before importing router
vi.mock('../transport.js', () => ({
  meshState: { peers: [], advertising: false, scanning: false, error: null },
  sendFrame: vi.fn(async () => {}),
  onFrame: vi.fn(() => () => {}),
}));

// Mock online-bridge
vi.mock('../online-bridge.js', () => ({
  bridgeSend: vi.fn(async () => ({ ok: true as const, seq: 1 })),
}));

// Mock token-client
vi.mock('../token-client.js', () => ({
  getToken: vi.fn(async () => 'fake.jwt.token'),
  _resetCache: vi.fn(),
  clearTokens: vi.fn(),
  clearTokensForIdentity: vi.fn(),
}));

// Mock dedupe to track calls
vi.mock('../dedupe.js', () => {
  const seenSet = new Set<string>();
  // Must use `function` (not arrow) so `new DedupeCache()` works as constructor
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    DedupeCache: function DedupeCache(this: any) {
      this.hasSeen = (channelId: string, msgId: string) => seenSet.has(`${channelId}:${msgId}`);
      this.markSeen = (channelId: string, msgId: string) => { seenSet.add(`${channelId}:${msgId}`); };
      this.clear = () => { seenSet.clear(); };
    },
  };
});

import { routeOutgoing, onIncoming, type RouteResult } from '../router.js';
import { meshState, sendFrame, onFrame } from '../transport.js';
import { bridgeSend } from '../online-bridge.js';

const CHANNEL_ID = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
const MSG_ID_HEX = 'aabbccdd00112233aabbccdd00112233';

function makeBundle(): Uint8Array {
  return new Uint8Array([0xc9, 0x01, 0x02, 0x03]);
}

function setMeshState(overrides: Partial<typeof meshState>) {
  Object.assign(meshState, overrides);
}

beforeEach(() => {
  vi.clearAllMocks(); // clear call counts + reset mock implementations to defaults
  vi.restoreAllMocks();
  setMeshState({ peers: [], advertising: false, scanning: false, error: null });
  vi.stubGlobal('navigator', { onLine: false });
  // Re-wire default mock behaviors after clearAllMocks resets them
  vi.mocked(bridgeSend).mockResolvedValue({ ok: true as const, seq: 1 });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('routeOutgoing — strategy table', () => {
  it('online only (no BLE peers) → calls bridgeSend', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [] });
    const mockBridge = vi.mocked(bridgeSend);
    mockBridge.mockResolvedValue({ ok: true, seq: 1 });

    const bundle = makeBundle();
    const result = await routeOutgoing(
      { bundle, msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );
    expect(result.strategy).toBe('online');
    expect(mockBridge).toHaveBeenCalledOnce();
  });

  it('offline with BLE peers → strategy is ble', async () => {
    vi.stubGlobal('navigator', { onLine: false });
    setMeshState({ peers: [{ idHex: 'aabb', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() }] });

    const bundle = makeBundle();
    const result = await routeOutgoing(
      { bundle, msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );
    expect(result.strategy).toBe('ble');
  });

  it('online + BLE peers → strategy is online+ble (dual)', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [{ idHex: 'aabb', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() }] });
    vi.mocked(bridgeSend).mockResolvedValue({ ok: true, seq: 2 });

    const bundle = makeBundle();
    const result = await routeOutgoing(
      { bundle, msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );
    expect(result.strategy).toBe('online+ble');
  });

  it('neither online nor BLE → strategy is queued', async () => {
    vi.stubGlobal('navigator', { onLine: false });
    setMeshState({ peers: [] });

    const bundle = makeBundle();
    const result = await routeOutgoing(
      { bundle, msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );
    expect(result.strategy).toBe('queued');
  });

  it('queued path uses the passed-in msgId (not re-parsed from bundle bytes)', async () => {
    vi.stubGlobal('navigator', { onLine: false });
    setMeshState({ peers: [] });

    const bundle = makeBundle(); // 4 bytes only — would error if re-parsed at offset 34
    const specificMsgId = 'deadbeef01020304deadbeef01020304';
    const result = await routeOutgoing(
      { bundle, msgId: specificMsgId, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );
    expect(result.strategy).toBe('queued');
    // No throw = msgId was used as-is, not re-parsed from bundle bytes
  });
});

describe('routeOutgoing — dual mode parallel send (MAJOR 3)', () => {
  it('online+ble mode sends to bridge and BLE concurrently (both called)', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    const peer = { idHex: 'peer1', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() };
    setMeshState({ peers: [peer] });
    vi.mocked(bridgeSend).mockResolvedValue({ ok: true, seq: 3 });
    const mockSendFrame = vi.mocked(sendFrame);
    mockSendFrame.mockResolvedValue(undefined);

    const bundle = makeBundle();
    await routeOutgoing(
      { bundle, msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );

    expect(vi.mocked(bridgeSend)).toHaveBeenCalledOnce();
    expect(mockSendFrame).toHaveBeenCalledWith('peer1', bundle);
  });
});

describe('routeOutgoing — atomic snapshot (MAJOR 6)', () => {
  it('captures online/peers state once at start, not re-read mid-await', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [] });
    vi.mocked(bridgeSend).mockResolvedValue({ ok: true, seq: 1 });

    const bundle = makeBundle();
    const result = await routeOutgoing(
      { bundle, msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );
    expect(result.strategy).toBe('online');
  });
});

describe('onIncoming (MAJOR 4)', () => {
  it('returns an unsubscribe function', () => {
    const unsub = onIncoming({ handler: () => {} });
    expect(typeof unsub).toBe('function');
    unsub();
  });

  // B2 fix: frames must be ≥125 bytes so slice(34,50) and slice(55,59) hit real data.
  // Helper: build a minimal valid-looking frame (125 bytes, no body).
  // offset 0: magic, offset 1: version, offset 2..34: senderPubkey,
  // offset 34..50: msgId, offset 54: ttlHops, offset 55..59: channelIdHash.
  function makeFrame(opts: {
    sender?: Uint8Array;   // 32 bytes, default all-0x01
    msgId?: Uint8Array;    // 16 bytes, default all-0x02
    channelId?: Uint8Array; // 4 bytes, default [0x12,0x34,0x56,0x78]
  } = {}): Uint8Array {
    const frame = new Uint8Array(125); // 61 header + 0 body + 64 sig
    frame[0] = 0xc9; // MAGIC
    frame[1] = 0x01; // VERSION
    const sender = opts.sender ?? new Uint8Array(32).fill(0x01);
    const msgId  = opts.msgId  ?? new Uint8Array(16).fill(0x02);
    const chanId = opts.channelId ?? new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    frame.set(sender, 2);
    frame.set(msgId, 34);
    frame.set(chanId, 55);
    return frame;
  }

  it('B2: frames with same sender but DIFFERENT msgId both reach handler (two passes)', () => {
    // RED: current router uses frame.slice(0,20) which never includes msgId bytes.
    // After fix (slice(34,50)) the two msgIds differ → two unique dedupe keys.
    const handler = vi.fn();
    const mockOnFrame = vi.mocked(onFrame);
    let ble: ((id: string, f: Uint8Array) => void) | undefined;
    mockOnFrame.mockImplementation((cb) => { ble = cb; return () => {}; });
    onIncoming({ handler });

    const sender = new Uint8Array(32).fill(0x01);
    const chanId = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const frame1 = makeFrame({ sender, msgId: new Uint8Array(16).fill(0xaa), channelId: chanId });
    const frame2 = makeFrame({ sender, msgId: new Uint8Array(16).fill(0xbb), channelId: chanId });
    // bytes 0..34 identical; bytes 34..50 differ

    ble!('peer1', frame1);
    ble!('peer2', frame2);
    expect(handler).toHaveBeenCalledTimes(2); // both must reach handler
  });

  it('B2: frames with same msgId but DIFFERENT channelId both reach handler (different channels)', () => {
    // Two bundles: same msgId, different channelId → independent dedupe namespaces.
    const handler = vi.fn();
    const mockOnFrame = vi.mocked(onFrame);
    let ble: ((id: string, f: Uint8Array) => void) | undefined;
    mockOnFrame.mockImplementation((cb) => { ble = cb; return () => {}; });
    onIncoming({ handler });

    const sender = new Uint8Array(32).fill(0x01);
    const msgId  = new Uint8Array(16).fill(0xcc);
    const frame1 = makeFrame({ sender, msgId, channelId: new Uint8Array([0x11, 0x22, 0x33, 0x44]) });
    const frame2 = makeFrame({ sender, msgId, channelId: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]) });

    ble!('peer1', frame1);
    ble!('peer2', frame2);
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('B2: frames with same msgId AND same channelId are suppressed — handler called once', () => {
    const handler = vi.fn();
    const mockOnFrame = vi.mocked(onFrame);
    let ble: ((id: string, f: Uint8Array) => void) | undefined;
    mockOnFrame.mockImplementation((cb) => { ble = cb; return () => {}; });
    onIncoming({ handler });

    const frame = makeFrame({ sender: new Uint8Array(32).fill(0x01),
                               msgId: new Uint8Array(16).fill(0xdd),
                               channelId: new Uint8Array([0x12, 0x34, 0x56, 0x78]) });
    ble!('peer1', frame);
    ble!('peer2', frame); // same frame — same msgId AND same channelId
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('accepts optional sseSubscribe and returns unsubscribe that calls SSE cleanup', () => {
    const sseCleanup = vi.fn();
    const sseSubscribe = vi.fn().mockReturnValue(sseCleanup);
    const unsub = onIncoming({ handler: () => {}, sseSubscribe });
    expect(sseSubscribe).toHaveBeenCalledOnce();
    unsub();
    expect(sseCleanup).toHaveBeenCalledOnce();
  });

  it('works without sseSubscribe (BLE-only path)', () => {
    expect(() => {
      const unsub = onIncoming({ handler: () => {} });
      unsub();
    }).not.toThrow();
  });
});
