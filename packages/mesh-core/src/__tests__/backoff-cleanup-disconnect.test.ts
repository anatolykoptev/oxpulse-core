/**
 * backoff-cleanup-disconnect.test.ts — #44: backoff and backoffCounts Maps
 * must not retain entries for disconnected devices.
 *
 * In a high-churn environment, devices that fail to connect populate the
 * backoff/backoffCounts Maps. When the device disconnects (via the
 * connection-state listener), those entries must be cleared to prevent
 * unbounded memory growth.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { connectSpy, connListenerCb, scanCbRef } = vi.hoisted(() => ({
  connectSpy: vi.fn(async () => {}),
  connListenerCb: { current: null as ((ev: { deviceAddress: string; connected: boolean }) => void) | null },
  scanCbRef: { current: null as ((result: unknown) => void) | null },
}));

const OUR_PEER_ID = new Uint8Array(8).fill(0x11);
vi.mock('../peer-registry.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../peer-registry.js')>();
  return { ...orig, generatePeerId: () => OUR_PEER_ID };
});

vi.mock('@capacitor/core', () => ({
  registerPlugin: () => ({
    startAdvertising: vi.fn(async () => {}),
    stopAdvertising: vi.fn(async () => {}),
    startGattServer: vi.fn(async () => {}),
    stopGattServer: vi.fn(async () => {}),
    notifyTx: vi.fn(async () => {}),
    addListener: vi.fn((event: string, cb: unknown) => {
      if (event === 'connection') connListenerCb.current = cb as typeof connListenerCb.current;
      return { remove: async () => {} };
    }),
  }),
}));

vi.mock('@capacitor-community/bluetooth-le', () => ({
  BleClient: {
    initialize: vi.fn(async () => {}),
    requestLEScan: vi.fn(async (_opts: unknown, cb: (r: unknown) => void) => { scanCbRef.current = cb; }),
    stopLEScan: vi.fn(async () => {}),
    connect: connectSpy,
    writeWithoutResponse: vi.fn(async () => {}),
    startNotifications: vi.fn(async () => {}),
    stopNotifications: vi.fn(async () => {}),
    discoverServices: vi.fn(async () => []),
    requestMtu: vi.fn(async () => 247),
    getMtu: vi.fn(async () => 247),
    disconnect: vi.fn(async () => {}),
  },
}));

vi.mock('@oxpulse/identity', async () => {
  const { ed25519: ed, x25519: x } = await import('@noble/curves/ed25519.js');
  const edSk = ed.utils.randomSecretKey();
  const edPk = ed.getPublicKey(edSk);
  const xSk = ed.utils.toMontgomerySecret(edSk);
  const xPk = x.getPublicKey(xSk);
  const b64pk = (() => {
    let s = '';
    for (const b of edPk) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  })();
  return {
    getOrCreateDeviceIdentity: vi.fn(async () => ({
      publicKeyB64: b64pk, publicKey: {} as CryptoKey, privateKey: {} as CryptoKey, privateKeyBytes: edSk,
    })),
    getOrCreateX25519Keypair: vi.fn(async () => ({ publicKey: xPk, privateKey: {} as CryptoKey, privateKeyBytes: xSk })),
    dhX25519: vi.fn(async (remotePub: Uint8Array) => x.getSharedSecret(xSk, remotePub)),
    fromBase64url: (s: string): Uint8Array => {
      let str = s; const pad = str.length % 4;
      if (pad) str += '='.repeat(4 - pad);
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    },
  };
});

import { startMesh, stopMesh, meshState, _getBackoffSize, _getBackoffCountsSize, _resetTofuStore } from '../transport.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';

const PEER_ID_BYTES = new Uint8Array(8).fill(0x77);

function fakeSighting(deviceId: string) {
  return {
    device: { deviceId },
    rssi: -60,
    serviceData: { 'f0f10000-6f78-7075-6c73-65000000c8b1': new DataView(PEER_ID_BYTES.buffer) },
  };
}

async function drain(n = 30) {
  for (let i = 0; i < n; i++) await Promise.resolve();
  await new Promise(r => setTimeout(r, 50));
  for (let i = 0; i < n; i++) await Promise.resolve();
}

describe('#44: backoff/backoffMaps cleanup on disconnect', () => {
  beforeEach(() => {
    meshState.peers = []; meshState.advertising = false; meshState.scanning = false; meshState.error = null;
    connectSpy.mockClear();
    connListenerCb.current = null; scanCbRef.current = null;
    if (typeof localStorage !== 'undefined') localStorage.clear();
    _resetTofuStore();
  });

  afterEach(async () => {
    if (meshState.advertising || meshState.scanning) await stopMesh();
  });

  it('clears backoff/backoffCounts on connection-state listener disconnect (handler #2)', async () => {
    const metrics: { metric: MeshMetric; labels?: Record<string, string> }[] = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    try {
      // Make connect fail so backoff/backoffCounts get populated.
      connectSpy.mockRejectedValueOnce(new Error('connect failed'));
      connectSpy.mockRejectedValueOnce(new Error('connect failed'));

      await startMesh();

      // Fire sightings for two distinct devices — both fail to connect.
      scanCbRef.current?.(fakeSighting('dev-01'));
      scanCbRef.current?.(fakeSighting('dev-02'));
      await drain(40);

      // Backoff maps should now have entries for both failed devices.
      expect(_getBackoffSize()).toBe(2);
      expect(_getBackoffCountsSize()).toBe(2);

      // Simulate disconnect via the connection-state listener.
      connListenerCb.current?.({ deviceAddress: 'dev-01', connected: false });
      connListenerCb.current?.({ deviceAddress: 'dev-02', connected: false });
      await drain(20);

      // #44: backoff maps must NOT retain entries for disconnected devices.
      expect(_getBackoffSize()).toBe(0);
      expect(_getBackoffCountsSize()).toBe(0);

      // Metric must have been emitted for each cleared device.
      const cleared = metrics.filter(m => m.metric === 'backoff_cleared');
      expect(cleared).toHaveLength(2);
    } finally {
      setMeshMetricSink(() => {});
    }
  });

  it('does not emit backoff_cleared when no backoff entries existed', async () => {
    const metrics: { metric: MeshMetric }[] = [];
    setMeshMetricSink((metric) => metrics.push({ metric }));
    try {
      await startMesh();

      // Disconnect a device that never had backoff entries.
      connListenerCb.current?.({ deviceAddress: 'dev-never-failed', connected: false });
      await drain(10);

      const cleared = metrics.filter(m => m.metric === 'backoff_cleared');
      expect(cleared).toHaveLength(0);
    } finally {
      setMeshMetricSink(() => {});
    }
  });

  it('clears backoff/backoffCounts on connect() callback disconnect (handler #1)', async () => {
    const metrics: { metric: MeshMetric; labels?: Record<string, string> }[] = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    try {
      // First attempt fails → backoff populated.
      connectSpy.mockRejectedValueOnce(new Error('connect failed'));

      await startMesh();

      // Fire sighting — connect fails, backoff set.
      scanCbRef.current?.(fakeSighting('dev-cb'));
      await drain(40);

      expect(_getBackoffSize()).toBe(1);
      expect(_getBackoffCountsSize()).toBe(1);

      // Simulate disconnect via the connection-state listener (handler #2).
      connListenerCb.current?.({ deviceAddress: 'dev-cb', connected: false });
      await drain(20);

      expect(_getBackoffSize()).toBe(0);
      expect(_getBackoffCountsSize()).toBe(0);

      const cleared = metrics.filter(m => m.metric === 'backoff_cleared');
      expect(cleared).toHaveLength(1);
      expect(cleared[0]?.labels?.device).toBe('dev-cb');
    } finally {
      setMeshMetricSink(() => {});
    }
  });
});
