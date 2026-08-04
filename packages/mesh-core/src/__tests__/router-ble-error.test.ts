/**
 * router-ble-error.test.ts — B4: tests that BLE failure in dual mode
 * downgrades strategy to 'online' (not false 'online+ble').
 *
 * Mutation tests (M1-M4) catch:
 *   M1: remove strategy downgrade → strategy stays 'online+ble' on BLE failure
 *   M2: remove emitMeshMetric → no ble_send_failed metric emitted
 *   M3: remove bleError assignment → bleError undefined (caller can't see failure)
 *   M4: remove .catch → unhandled rejection crashes routeOutgoing
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';

vi.mock('../transport.js', () => ({
  meshState: { peers: [], advertising: false, scanning: false, error: null },
  sendFrame: vi.fn(async () => {}),
  onFrame: vi.fn(() => () => {}),
}));

vi.mock('../online-bridge.js', () => ({
  bridgeSend: vi.fn(async () => ({ ok: true as const, seq: 1 })),
}));

vi.mock('../token-client.js', () => ({
  getToken: vi.fn(async () => 'fake.jwt.token'),
  _resetCache: vi.fn(),
  clearTokens: vi.fn(),
  clearTokensForIdentity: vi.fn(),
}));

vi.mock('../dedupe.js', () => {
  const seenSet = new Set<string>();
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    DedupeCache: function DedupeCache(this: any) {
      this.hasSeen = (channelId: string, msgId: string) => seenSet.has(`${channelId}:${msgId}`);
      this.markSeen = (channelId: string, msgId: string) => { seenSet.add(`${channelId}:${msgId}`); };
      this.clear = () => { seenSet.clear(); };
    },
  };
});

import { routeOutgoing } from '../router.js';
import { meshState, sendFrame } from '../transport.js';
import { bridgeSend } from '../online-bridge.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';

const CHANNEL_ID = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
const MSG_ID_HEX = 'aabbccdd00112233aabbccdd00112233';

function makeBundle(): Uint8Array {
  return new Uint8Array([0xc9, 0x01, 0x02, 0x03]);
}

function setMeshState(overrides: Partial<typeof meshState>) {
  Object.assign(meshState, overrides);
}

describe('B4: router dual-mode BLE error propagation (issue #8)', () => {
  let metrics: { metric: MeshMetric; labels?: Record<string, string> }[];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    setMeshState({ peers: [], advertising: false, scanning: false, error: null });
    vi.stubGlobal('navigator', { onLine: false });
    vi.mocked(bridgeSend).mockResolvedValue({ ok: true as const, seq: 1 });
    vi.mocked(sendFrame).mockResolvedValue(undefined);
    metrics = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
  });

  afterEach(() => {
    setMeshMetricSink(() => {});
    vi.restoreAllMocks();
  });

  // ── Test 1: BLE failure downgrades strategy to 'online' ─────────────────
  it('M1: BLE failure in dual mode → strategy = online (not online+ble)', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [{ idHex: 'peer1', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() }] });
    vi.mocked(bridgeSend).mockResolvedValue({ ok: true, seq: 2 });
    vi.mocked(sendFrame).mockRejectedValue(new Error('BLE GATT write timeout'));

    const result = await routeOutgoing(
      { bundle: makeBundle(), msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );

    // M1: if strategy downgrade is removed, this stays 'online+ble' (false success).
    expect(result.strategy).toBe('online');
    expect(result.bleError).toContain('BLE GATT write timeout');
  });

  // ── Test 2: BLE failure emits ble_send_failed metric ────────────────────
  it('M2: BLE failure emits ble_send_failed metric with reason label', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [{ idHex: 'peer1', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() }] });
    vi.mocked(sendFrame).mockRejectedValue(new Error('BLE GATT write timeout'));

    await routeOutgoing(
      { bundle: makeBundle(), msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );

    const failedMetrics = metrics.filter((m) => m.metric === 'ble_send_failed');
    expect(failedMetrics).toHaveLength(1);
    expect(failedMetrics[0]!.labels?.reason).toContain('BLE GATT write timeout');
  });

  // ── Test 3: BLE success keeps strategy = 'online+ble' ───────────────────
  it('happy path: BLE success in dual mode → strategy = online+ble', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [{ idHex: 'peer1', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() }] });
    vi.mocked(bridgeSend).mockResolvedValue({ ok: true, seq: 3 });
    vi.mocked(sendFrame).mockResolvedValue(undefined);

    const result = await routeOutgoing(
      { bundle: makeBundle(), msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );

    expect(result.strategy).toBe('online+ble');
    expect(result.bleError).toBeUndefined();
    // No ble_send_failed metric on happy path.
    expect(metrics.filter((m) => m.metric === 'ble_send_failed')).toHaveLength(0);
  });

  // ── Test 4: BLE error with non-Error throw (string) ─────────────────────
  it('M3: non-Error BLE failure still sets bleError string', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [{ idHex: 'peer1', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() }] });
    vi.mocked(sendFrame).mockRejectedValue('string error');

    const result = await routeOutgoing(
      { bundle: makeBundle(), msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
      { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
    );

    expect(result.strategy).toBe('online');
    expect(result.bleError).toBe('string error');
  });

  // ── Test 5: bridgeSend also fails → routeOutgoing rejects (not swallowed) ─
  it('both bridge and BLE fail → routeOutgoing rejects (bridge error not swallowed)', async () => {
    vi.stubGlobal('navigator', { onLine: true });
    setMeshState({ peers: [{ idHex: 'peer1', mac: '00:11:22:33:44:55', rssi: -70, lastSeenMs: Date.now() }] });
    vi.mocked(bridgeSend).mockRejectedValue(new Error('bridge 500'));
    vi.mocked(sendFrame).mockRejectedValue(new Error('BLE timeout'));

    await expect(
      routeOutgoing(
        { bundle: makeBundle(), msgId: MSG_ID_HEX, channelId: CHANNEL_ID },
        { geohash: 'gcpv', dayUtc: '2026-05-16', identityKey: 'user-a' },
      ),
    ).rejects.toThrow('bridge 500');
  });
});
