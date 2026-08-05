/**
 * backoff-cleanup-disconnect.test.ts — #44: backoff and backoffCounts Maps
 * must not retain entries for disconnected devices, BUT an armed retry window
 * must survive a disconnect event (F1, 2026-08-04 audit).
 *
 * In a high-churn environment, devices that fail to connect populate the
 * backoff/backoffCounts Maps. The #44 memory-leak concern (unbounded Map
 * growth) is addressed by clearing EXPIRED entries on disconnect and by the
 * 30s GC prune. An ARMED window (retryAt > now) is kept so that a device which
 * fails to connect and then emits a disconnect is NOT retried on the next scan
 * sighting — wiping an armed window is a hot reconnect loop that defeats
 * exponential backoff (the exact churn scenario #44 was filed about).
 *
 * F1 RED-on-revert: if clearBackoff is reverted to unconditionally delete both
 * Maps, the "armed window survives" assertions fail (size drops to 0).
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
import { waitFor, flushMicrotasks } from './_async-helpers.js';

const PEER_ID_BYTES = new Uint8Array(8).fill(0x77);

function fakeSighting(deviceId: string) {
  return {
    device: { deviceId },
    rssi: -60,
    serviceData: { 'f0f10000-6f78-7075-6c73-65000000c8b1': new DataView(PEER_ID_BYTES.buffer) },
  };
}

// ── Deterministic settle helpers (issue #58) ───────────────────────────────
// Replaces the fixed wall-clock `drain()`. Only Date is faked (setTimeout and
// performance stay real), so waitFor's polling + real-timer fallback works.
// The connect-failure → backoff-arming chain is microtask-based; the disconnect
// handler (clearBackoff) is synchronous.

/** Wait for backoff and backoffCounts Maps to reach the given sizes. */
async function awaitBackoff(backoff: number, counts: number): Promise<void> {
  await waitFor(
    () => _getBackoffSize() === backoff && _getBackoffCountsSize() === counts,
    `backoff size=${backoff}, backoffCounts size=${counts}`,
  );
}

describe('#44: backoff/backoffMaps cleanup on disconnect (F1: armed window survives)', () => {
  beforeEach(() => {
    meshState.peers = []; meshState.advertising = false; meshState.scanning = false; meshState.error = null;
    connectSpy.mockClear();
    connListenerCb.current = null; scanCbRef.current = null;
    if (typeof localStorage !== 'undefined') localStorage.clear();
    _resetTofuStore();
    // Fake only Date, so we can advance past the 5s backoff window to test the
    // expired-entry clear path without disturbing anything else.
    //
    // Do NOT widen this to a bare vi.useFakeTimers(): that fakes `performance`
    // as well, and waitFor's deadline is measured with performance.now(), so it
    // would never arrive and the suite would hang rather than fail. waitFor
    // captures the real timer and clock at module load precisely so a narrow
    // toFake list like this one stays safe.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(0));
  });

  afterEach(async () => {
    vi.useRealTimers();
    if (meshState.advertising || meshState.scanning) await stopMesh();
  });

  it('keeps an ARMED backoff window across a disconnect, then clears it once expired (handler #2)', async () => {
    const metrics: { metric: MeshMetric; labels?: Record<string, string> }[] = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    try {
      // Two devices fail to connect -> 5s backoff windows armed for both.
      connectSpy.mockRejectedValueOnce(new Error('connect failed'));
      connectSpy.mockRejectedValueOnce(new Error('connect failed'));

      await startMesh();

      scanCbRef.current?.(fakeSighting('dev-01'));
      scanCbRef.current?.(fakeSighting('dev-02'));
      await awaitBackoff(2, 2);

      expect(_getBackoffSize()).toBe(2);
      expect(_getBackoffCountsSize()).toBe(2);

      // Disconnect while windows are still armed (~0ms of 5s elapsed) —
      // F1: the armed windows MUST survive (no hot reconnect loop).
      // The disconnect handler (clearBackoff) is synchronous.
      connListenerCb.current?.({ deviceAddress: 'dev-01', connected: false });
      connListenerCb.current?.({ deviceAddress: 'dev-02', connected: false });
      await flushMicrotasks();

      expect(_getBackoffSize(), 'armed backoff window was wiped by disconnect').toBe(2);
      expect(_getBackoffCountsSize(), 'armed backoffCounts was wiped by disconnect').toBe(2);
      // Nothing was actually removed -> metric must NOT fire (honest semantics).
      const clearedWhileArmed = metrics.filter(m => m.metric === 'backoff_cleared');
      expect(clearedWhileArmed).toHaveLength(0);

      // Advance past the 5s window — entries are now expired.
      vi.setSystemTime(new Date(6_000));

      // Disconnect again — expired entries are cleared (#44 memory-leak fix).
      connListenerCb.current?.({ deviceAddress: 'dev-01', connected: false });
      connListenerCb.current?.({ deviceAddress: 'dev-02', connected: false });
      await awaitBackoff(0, 0);

      expect(_getBackoffSize()).toBe(0);
      expect(_getBackoffCountsSize()).toBe(0);
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
      // The disconnect handler is synchronous; flush microtasks to let any
      // pending work from startMesh quiesce before asserting.
      connListenerCb.current?.({ deviceAddress: 'dev-never-failed', connected: false });
      await flushMicrotasks();

      const cleared = metrics.filter(m => m.metric === 'backoff_cleared');
      expect(cleared).toHaveLength(0);
    } finally {
      setMeshMetricSink(() => {});
    }
  });

  it('keeps an ARMED backoff window across a connect() callback disconnect, then clears once expired (handler #1)', async () => {
    const metrics: { metric: MeshMetric; labels?: Record<string, string> }[] = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
    try {
      // First attempt fails -> 5s backoff window armed.
      connectSpy.mockRejectedValueOnce(new Error('connect failed'));

      await startMesh();

      scanCbRef.current?.(fakeSighting('dev-cb'));
      await awaitBackoff(1, 1);

      expect(_getBackoffSize()).toBe(1);
      expect(_getBackoffCountsSize()).toBe(1);

      // Disconnect via the connection-state listener (handler #2 path, same
      // clearBackoff call). Window still armed -> MUST survive.
      connListenerCb.current?.({ deviceAddress: 'dev-cb', connected: false });
      await flushMicrotasks();

      expect(_getBackoffSize(), 'armed backoff window was wiped by disconnect').toBe(1);
      expect(_getBackoffCountsSize()).toBe(1);
      expect(metrics.filter(m => m.metric === 'backoff_cleared')).toHaveLength(0);

      // Advance past the 5s window -> expired -> cleared on next disconnect.
      vi.setSystemTime(new Date(6_000));
      connListenerCb.current?.({ deviceAddress: 'dev-cb', connected: false });
      await awaitBackoff(0, 0);

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
