/**
 * cryptostates-disconnect-leak.test.ts — #91: a disconnect landing inside the
 * `await getLocalIdentity()` gap in `initiateHandshake` leaks a `cryptoStates`
 * entry that no reaper touches.
 *
 * The race: `initiateHandshake` opens with `await getLocalIdentity()` and only
 * registers its `cryptoStates` entry afterwards. It is called right after
 * `connectedDevices.set(deviceId, …)`. A disconnect firing inside that await
 * runs the disconnect callback, which deletes `connectedDevices[deviceId]` and
 * a `cryptoStates` entry that does not exist yet — then `initiateHandshake`
 * resumes and creates one for a device that is already gone. The retained
 * `CryptoState` holds a live `NoiseXxHandshake` (handshake key material) past
 * the connection it belonged to.
 *
 * This test drives the REAL race: a controllable identity gate suspends
 * `initiateHandshake` inside the `getLocalIdentity()` await. While it is
 * suspended, the disconnect callback fires. The gate then resolves and
 * `initiateHandshake` resumes — and must NOT create a `cryptoStates` entry for
 * the gone device.
 *
 * A second phase verifies the leaked entry does not come back by another route:
 * a reconnect with a rotated MAC (different deviceId) creates a fresh entry for
 * the new address, while the old address stays clean — no accumulation.
 *
 * Both phases are in one test because the identity provider is cached in
 * transport.ts after the first `getLocalIdentity()` call — only the first
 * handshake suspends on the gate, so the race can only be driven once per
 * module instance.
 *
 * #91 RED-on-revert (mutation): in transport.ts initiateHandshake, delete the
 * `if (!connectedDevices.has(deviceId)) return;` guard added after the
 * `await getLocalIdentity()` line. With the guard gone, `initiateHandshake`
 * resumes and creates the entry for the disconnected device →
 * `_hasCryptoState(DEVICE_A)` is true → the `toBe(false)` assertion fails
 * (RED).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Hoisted mutable state + controllable identity gate ─────────────────────
const {
  disconnectSpy,
  writeRxSpy,
  txNotifyCb,
  rxListenerCb,
  connListenerCb,
  scanCbRef,
  identityGateRef,
} = vi.hoisted(() => ({
  disconnectSpy: vi.fn(async () => {}),
  writeRxSpy: vi.fn(async () => {}),
  txNotifyCb: { current: null as ((chunk: Uint8Array) => void) | null },
  rxListenerCb: { current: null as ((ev: { deviceAddress: string; data: string }) => void) | null },
  connListenerCb: { current: null as ((ev: { deviceAddress: string; connected: boolean }) => void) | null },
  scanCbRef: { current: null as ((result: unknown) => void) | null },
  /**
   * Controllable gate for getOrCreateDeviceIdentity. When set, the mock awaits
   * the promise before resolving — suspending initiateHandshake inside the
   * `await getLocalIdentity()` gap so the test can fire a disconnect there.
   * Set to null to let the identity resolve immediately (cached path).
   */
  identityGateRef: {
    current: null as null | { promise: Promise<void>; resolve: () => void },
  },
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
      if (event === 'rx') rxListenerCb.current = cb as typeof rxListenerCb.current;
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
    connect: vi.fn(async () => {}),
    writeWithoutResponse: writeRxSpy,
    startNotifications: vi.fn(async (_id: unknown, _svc: unknown, _char: unknown, cb: (data: DataView) => void) => {
      txNotifyCb.current = (chunk: Uint8Array) => cb(new DataView(chunk.buffer, 0, chunk.byteLength));
    }),
    stopNotifications: vi.fn(async () => {}),
    discoverServices: vi.fn(async () => []),
    requestMtu: vi.fn(async () => 247),
    getMtu: vi.fn(async () => 247),
    disconnect: disconnectSpy,
  },
}));

vi.mock('@oxpulse/identity', async () => {
  const { OpaquePrivateKey } = await import('../../../identity/src/opaque-private-key.js');
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
    getOrCreateDeviceIdentity: vi.fn(async () => {
      // Suspend inside the getLocalIdentity() await when a gate is armed.
      if (identityGateRef.current) await identityGateRef.current.promise;
      return {
        publicKeyB64: b64pk,
        publicKey: {} as CryptoKey,
        privateKey: {} as CryptoKey,
        privateKeySeed: new OpaquePrivateKey(edSk),
      };
    }),
    getOrCreateX25519Keypair: vi.fn(async () => ({ publicKey: xPk, privateKey: {} as CryptoKey, privateKeySeed: xSk })),
    dhX25519: vi.fn(async (remotePub: Uint8Array) => x.getSharedSecret(xSk, remotePub)),
    fromBase64url: (s: string): Uint8Array => {
      let str = s;
      const pad = str.length % 4;
      if (pad) str += '='.repeat(4 - pad);
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    },
  };
});

import { startMesh, stopMesh, meshState, _hasCryptoState, _resetTofuStore } from '../transport.js';
import { waitFor, flushMicrotasks } from './_async-helpers.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';

// ── Test constants ─────────────────────────────────────────────────────────
// Both peer-id bytes > OUR_PEER_ID (0x11) → our side is always the initiator,
// so initiateHandshake writes msg-1 right after creating the entry. This gives
// an observable signal (writeRxSpy) that the entry was created.
const PEER_ID_A = new Uint8Array(8).fill(0x77);
const PEER_ID_B = new Uint8Array(8).fill(0x88);
const DEVICE_A = 'peer-aa:bb:cc';
const DEVICE_B = 'peer-dd:ee:ff';
const SERVICE_UUID = 'f0f10000-6f78-7075-6c73-65000000c8b1';

function fakeSighting(deviceId: string, peerId: Uint8Array) {
  return {
    device: { deviceId },
    rssi: -60,
    serviceData: { [SERVICE_UUID]: new DataView(peerId.buffer) },
  };
}

/** Arm a fresh identity gate; returns its resolve function. */
function armIdentityGate(): () => void {
  let resolveFn: () => void = () => {};
  const promise = new Promise<void>((r) => { resolveFn = r; });
  identityGateRef.current = { promise, resolve: resolveFn };
  return resolveFn;
}

// ── Test suite ─────────────────────────────────────────────────────────────
describe('#91: cryptoStates entry leaks when a peer disconnects during the initiateHandshake await', () => {
  beforeEach(() => {
    meshState.peers = [];
    meshState.advertising = false;
    meshState.scanning = false;
    meshState.error = null;
    writeRxSpy.mockClear();
    disconnectSpy.mockClear();
    txNotifyCb.current = null;
    rxListenerCb.current = null;
    connListenerCb.current = null;
    scanCbRef.current = null;
    identityGateRef.current = null;
    if (typeof localStorage !== 'undefined') localStorage.clear();
    _resetTofuStore();
  });

  afterEach(async () => {
    identityGateRef.current = null;
    if (meshState.advertising || meshState.scanning) await stopMesh();
  });

  it('disconnect inside the getLocalIdentity await does not leak, and reconnect does not accumulate', async () => {
    // ── Phase 1: drive the real race for device A ──────────────────────────
    // Arm the gate so getOrCreateDeviceIdentity suspends, holding
    // initiateHandshake inside the `await getLocalIdentity()` gap.
    const resolveIdentity = armIdentityGate();

    const metrics: { metric: MeshMetric; labels?: Record<string, string> }[] = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));

    await startMesh();

    // Trigger the outbound connect path for device A.
    scanCbRef.current?.(fakeSighting(DEVICE_A, PEER_ID_A));

    // Wait until the scan handler has progressed past connectedDevices.set
    // and called initiateHandshake — which is now suspended on the identity
    // gate. meshState.peers populating proves registry.upsert ran, which is
    // synchronous with connectedDevices.set and immediately precedes the
    // initiateHandshake call.
    await waitFor(() => meshState.peers.length > 0, 'scan handler to register peer A');

    // initiateHandshake is suspended inside `await getLocalIdentity()`. Fire
    // the disconnect — the callback deletes connectedDevices[A] and
    // cryptoStates[A] (which does not exist yet).
    connListenerCb.current?.({ deviceAddress: DEVICE_A, connected: false });
    await flushMicrotasks();

    // Release initiateHandshake: resolve the identity gate so getLocalIdentity()
    // returns and initiateHandshake resumes. With the fix it re-checks
    // connectedDevices, sees A is gone, and bails before creating the entry.
    resolveIdentity();
    await flushMicrotasks();

    // No leaked CryptoState holding handshake key material for a gone device.
    expect(_hasCryptoState(DEVICE_A)).toBe(false);

    // #91 F1: the bail is observable. The responder path already emits for the
    // identical condition, so an operator asking how often BLE churn aborts a
    // handshake mid-bootstrap needs this side counted too. Asserted here because
    // a metric nobody reads is indistinguishable from one never emitted.
    const aborted = metrics.filter((m) => m.metric === 'handshake_init_aborted');
    expect(aborted, 'no handshake_init_aborted metric emitted for the bail').toHaveLength(1);
    expect(aborted[0]!.labels?.device, 'metric should name the device that vanished').toBe(DEVICE_A);

    // ── Phase 2: reconnect with a rotated MAC does not accumulate ──────────
    // The peer comes back with a different MAC (device B). The identity is now
    // cached, so getLocalIdentity() resolves synchronously — no gate needed.
    // initiateHandshake creates a fresh entry for B and writes msg-1.
    writeRxSpy.mockClear();
    scanCbRef.current?.(fakeSighting(DEVICE_B, PEER_ID_B));
    await waitFor(() => writeRxSpy.mock.calls.length > 0, 'initiateHandshake to send msg-1 for device B');

    // B has a legitimate entry; A does not — no accumulation across the
    // disconnect-during-handshake + MAC-rotation reconnect cycle.
    expect(_hasCryptoState(DEVICE_A)).toBe(false);
    expect(_hasCryptoState(DEVICE_B)).toBe(true);
  });
});
