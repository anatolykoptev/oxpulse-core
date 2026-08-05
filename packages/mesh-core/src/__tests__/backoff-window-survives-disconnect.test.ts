/**
 * AUDIT (falsifying test for fix #52 / issue #44).
 *
 * Invariant: a connect failure arms an exponential backoff window
 * (5s -> 15s -> 60s). A subsequent DISCONNECT event for that device must
 * NOT wipe that window — otherwise a device that fails to connect and then
 * emits a disconnect event is retried on the very next scan sighting,
 * which is a hot reconnect loop and defeats the backoff entirely.
 *
 * Fix #52 (clearBackoff on disconnect) deletes both `backoff` and
 * `backoffCounts` from BOTH disconnect handlers, with no regard for whether
 * a backoff window is currently armed.
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
      if (pad) str += "=".repeat(4 - pad);
      const binary = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    },
  };
});

import { startMesh, stopMesh, meshState, _getBackoffSize, _resetTofuStore } from '../transport.js';

const PEER_ID_BYTES = new Uint8Array(8).fill(0x77);
const DEV = 'dev-backoff-window';

function fakeSighting(deviceId: string) {
  return {
    device: { deviceId },
    rssi: -60,
    serviceData: { 'f0f10000-6f78-7075-6c73-65000000c8b1': new DataView(PEER_ID_BYTES.buffer) },
  };
}

async function drain(n = 30) {
  for (let i = 0; i < n; i++) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 50));
  for (let i = 0; i < n; i++) await Promise.resolve();
}

describe('AUDIT #44/#52: backoff window must survive a disconnect event', () => {
  beforeEach(() => {
    meshState.peers = []; meshState.advertising = false; meshState.scanning = false; meshState.error = null;
    connectSpy.mockReset();
    connListenerCb.current = null; scanCbRef.current = null;
    if (typeof localStorage !== 'undefined') localStorage.clear();
    _resetTofuStore();
  });

  afterEach(async () => {
    if (meshState.advertising || meshState.scanning) await stopMesh();
  });

  it('does not retry a backed-off device after a disconnect event wipes the window', async () => {
    connectSpy.mockRejectedValue(new Error('connect failed'));
    await startMesh();
    await drain();

    // 1st sighting -> connect attempted -> fails -> 5s backoff window armed.
    scanCbRef.current?.(fakeSighting(DEV));
    await drain();
    expect(connectSpy).toHaveBeenCalledTimes(1);
    expect(_getBackoffSize()).toBe(1);

    // 2nd sighting while still inside the 5s window -> must be skipped.
    scanCbRef.current?.(fakeSighting(DEV));
    await drain();
    expect(connectSpy).toHaveBeenCalledTimes(1);

    // A disconnect event arrives for the same device. The backoff window is
    // still armed (only ~0.1s of 5s elapsed) and MUST survive.
    connListenerCb.current?.({ deviceAddress: DEV, connected: false });
    await drain();

    expect(_getBackoffSize(), 'backoff window was wiped by the disconnect handler').toBe(1);

    // 3rd sighting, still inside the original 5s window -> must still be skipped.
    scanCbRef.current?.(fakeSighting(DEV));
    await drain();
    expect(connectSpy, 'device was retried immediately — backoff defeated').toHaveBeenCalledTimes(1);
  });
});

describe('AUDIT #44/#52: the 30s GC prunes EXPIRED backoff entries', () => {
  beforeEach(() => {
    meshState.peers = []; meshState.advertising = false; meshState.scanning = false; meshState.error = null;
    connectSpy.mockReset();
    connListenerCb.current = null; scanCbRef.current = null;
    if (typeof localStorage !== 'undefined') localStorage.clear();
    _resetTofuStore();
  });

  afterEach(async () => {
    if (meshState.advertising || meshState.scanning) await stopMesh();
    vi.useRealTimers();
  });

  // clearBackoff now refuses to drop an ARMED window (F1). That leaves one way
  // for the Maps to grow without bound, which is issue #44's actual concern: a
  // device that fails to connect and then vanishes, never emitting a
  // post-expiry disconnect. The periodic prune on the existing 30s GC interval
  // is the ONLY thing that reclaims those entries, and nothing else covers it.
  //
  // Fake Date + setInterval only; drain() relies on a real setTimeout. Note
  // advanceTimersByTime also advances the mocked clock, so a single 30s tick
  // both expires the 5s window and fires the GC.
  it('reclaims an expired entry when the device never reconnects', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval'] });
    connectSpy.mockRejectedValue(new Error('connect failed'));

    await startMesh();
    await drain();

    scanCbRef.current?.(fakeSighting(DEV));
    await drain();
    expect(_getBackoffSize(), 'a failed connect must arm a backoff window').toBe(1);

    // 30s later: the 5s window has expired and the GC interval has fired.
    // No disconnect event ever arrived for this device.
    vi.advanceTimersByTime(30_000);
    await drain();

    expect(_getBackoffSize(), 'GC did not reclaim an EXPIRED window: Maps grow unbounded').toBe(0);
  });
});
