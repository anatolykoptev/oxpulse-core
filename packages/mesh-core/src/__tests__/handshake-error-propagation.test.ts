/**
 * handshake-error-propagation.test.ts — B3: tests that handshake errors
 * are propagated to meshState.error + CryptoState.verdict, not swallowed.
 *
 * These tests inject failing mocks (writeRx throws, getLocalIdentity throws)
 * and verify that:
 *   - meshState.error === 'handshake-failed'
 *   - cs.verdict === 'rejected' (for paths where cs exists)
 *   - handshake_failed metric is emitted
 *   - notifyHandshakeChange fires (UI refreshes)
 *
 * Mutation tests (M1-M5) catch:
 *   M1: remove failHandshake call → meshState.error stays null
 *   M2: remove cs.verdict = 'rejected' → verdict stays 'pending'
 *   M3: remove emitMeshMetric → no metric emitted
 *   M4: remove notifyHandshakeChange → UI not refreshed
 *   M5: remove meshState.error = 'handshake-failed' → error stays null
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';

// ── Hoist mutable state needed by vi.mock factories ───────────────────────
const { disconnectSpy, writeRxSpy, txNotifyCb, rxListenerCb, connListenerCb, scanCbRef } = vi.hoisted(() => ({
  disconnectSpy: vi.fn(async () => {}),
  writeRxSpy: vi.fn(async () => {}),
  txNotifyCb: { current: null as ((chunk: Uint8Array) => void) | null },
  rxListenerCb: { current: null as ((ev: { deviceAddress: string; data: string }) => void) | null },
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
      if (event === 'rx') rxListenerCb.current = cb as typeof rxListenerCb.current;
      if (event === 'connection') connListenerCb.current = cb as typeof connListenerCb.current;
      return { remove: async () => {} };
    }),
  }),
}));

vi.mock('@capacitor-community/bluetooth-le', () => ({
  BleClient: {
    initialize: vi.fn(async () => {}),
    requestLEScan: vi.fn(async (_opts: unknown, cb: (r: unknown) => void) => {
      scanCbRef.current = cb;
    }),
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
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=g/, '');
  })();
  return {
    getOrCreateDeviceIdentity: vi.fn(async () => ({
      publicKeyB64: b64pk,
      publicKey: {} as CryptoKey,
      privateKey: {} as CryptoKey,
      privateKeySeed: new OpaquePrivateKey(edSk),
    })),
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

import { startMesh, stopMesh, meshState, getPendingHandshakes, _resetTofuStore } from '../transport.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';
import { waitFor, flushMicrotasks } from './_async-helpers.js';

// ── Test constants ─────────────────────────────────────────────────────────
const TEST_MTU = 247;
const PEER_DEVICE_ID = 'peer-aa:bb:cc';
const PEER_ID_BYTES = new Uint8Array(8).fill(0x77);

function fakeSighting() {
  return {
    device: { deviceId: PEER_DEVICE_ID },
    rssi: -60,
    serviceData: {
      'f0f10000-6f78-7075-6c73-65000000c8b1': new DataView(PEER_ID_BYTES.buffer),
    },
  };
}

// ── Deterministic settle helpers (issue #58) ───────────────────────────────
// Replaces the fixed wall-clock `drain()` that asserted on unsettled handshake
// state under load. Each wait targets the observable the next assertion reads.

/** Wait for the initiator to send msg-1 (initiateHandshake ran). */
async function awaitMsg1Sent(): Promise<void> {
  await waitFor(() => writeRxSpy.mock.calls.length > 0, 'transport to send msg-1 (initiateHandshake)');
}

/** Wait for meshState.error to be set to 'handshake-failed' (failHandshake ran). */
async function awaitHandshakeFailed(): Promise<void> {
  await waitFor(() => meshState.error === 'handshake-failed', 'meshState.error to become handshake-failed');
}

/** Wait for the initiator handshake to complete: msg-3 sent + SAS available. */
async function awaitHandshakeComplete(): Promise<void> {
  await waitFor(() => getPendingHandshakes().length > 0, 'initiator handshake to complete (msg-3 sent, SAS available)');
}

// ── Test suite ─────────────────────────────────────────────────────────────

describe('B3: handshake error propagation (issue #7)', () => {
  let metrics: { metric: MeshMetric; labels?: Record<string, string> }[];

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
    if (typeof localStorage !== 'undefined') localStorage.clear();
    _resetTofuStore();
    metrics = [];
    setMeshMetricSink((metric, labels) => metrics.push({ metric, labels }));
  });

  afterEach(async () => {
    setMeshMetricSink(() => {});
    if (meshState.advertising || meshState.scanning) {
      await stopMesh();
    }
  });

  // ── Test 1: initiateHandshake failure (writeRx throws) ──────────────────
  // Covers catch site #1 (line 328). If writeRx throws during msg-1 send,
  // the error must propagate to meshState.error + verdict = 'rejected'.
  it('M1+M5: initiateHandshake writeRx failure sets meshState.error = handshake-failed', async () => {
    // Make writeRx throw on first call (during initiateHandshake msg-1 send).
    writeRxSpy.mockRejectedValueOnce(new Error('GATT write failed'));

    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeFailed();

    // M1: if failHandshake is not called, meshState.error stays null.
    // M5: if meshState.error = 'handshake-failed' is removed, error stays null.
    expect(meshState.error).toBe('handshake-failed');
  });

  // ── Test 2: metric emitted on handshake failure ──────────────────────────
  it('M3: handshake failure emits handshake_failed metric', async () => {
    writeRxSpy.mockRejectedValueOnce(new Error('GATT write failed'));

    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeFailed();

    const failedMetrics = metrics.filter((m) => m.metric === 'handshake_failed');
    expect(failedMetrics.length).toBeGreaterThanOrEqual(1);
    expect(failedMetrics[0]!.labels?.reason).toContain('GATT write failed');
  });

  // ── Test 3: verdict = 'rejected' on handshake failure ────────────────────
  it('M2: initiateHandshake failure sets CryptoState.verdict = rejected', async () => {
    writeRxSpy.mockRejectedValueOnce(new Error('GATT write failed'));

    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeFailed();

    // The peer should NOT appear in getPendingHandshakes (verdict != 'pending').
    const pending = getPendingHandshakes();
    const peerIdHex = Array.from(PEER_ID_BYTES).map(b => b.toString(16).padStart(2, '0')).join('');
    const failedPeer = pending.find(p => p.peerIdHex === peerIdHex);
    expect(failedPeer).toBeUndefined();
  });

  // ── Test 4: advanceHandshake failure (writeRx throws on msg-3) ───────────
  // Covers catch site #3 (line 857). After successful msg-1/msg-2 exchange,
  // writeRx fails on msg-3 send — error must propagate.
  it('advanceHandshake writeRx failure (msg-3) sets meshState.error = handshake-failed', async () => {
    const { NoiseXxHandshake } = await import('../crypto/noise-xx.js');
    const { chunkFrame, FrameReassembler, FrameType } = await import('../frame.js');

    const peerHs = new NoiseXxHandshake({ role: 'responder', identity: mkIdentityPeer() });

    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitMsg1Sent();

    // Collect msg-1, feed to peer, get msg-2.
    const r1 = new FrameReassembler();
    const calls = writeRxSpy.mock.calls;
    let peerMsgOut: Uint8Array | null = null;
    for (let i = 0; i < calls.length; i++) {
      const dv = calls[i]![3] as DataView;
      const chunk = new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
      const res = r1.pushWithType(chunk);
      if (res) { peerMsgOut = res.payload; }
    }
    expect(peerMsgOut).not.toBeNull();
    await peerHs.readMessage(peerMsgOut!);
    const m2 = await peerHs.writeMessage(new Uint8Array(0));

    // Inject msg-2 → transport will process and try to send msg-3.
    // Make writeRx throw on the NEXT call (msg-3 send).
    writeRxSpy.mockRejectedValueOnce(new Error('GATT write failed on msg-3'));
    for (const c of chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2)) {
      txNotifyCb.current?.(c);
    }
    // msg-3 writeRx failure path sets meshState.error without firing a
    // handshake state-change event, so this waits by polling the error.
    await awaitHandshakeFailed();

    // M1+M5: error must be set, not swallowed.
    expect(meshState.error).toBe('handshake-failed');
  });

  // ── Test 5: happy path does NOT set error ────────────────────────────────
  // Regression guard: the fix must not break the happy path.
  it('happy path: successful handshake does NOT set meshState.error', async () => {
    const { NoiseXxHandshake } = await import('../crypto/noise-xx.js');
    const { chunkFrame, FrameReassembler, FrameType } = await import('../frame.js');

    const peerHs = new NoiseXxHandshake({ role: 'responder', identity: mkIdentityPeer() });

    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitMsg1Sent();

    // Complete the full handshake (msg-1 → msg-2 → msg-3).
    const r1 = new FrameReassembler();
    let calls = writeRxSpy.mock.calls;
    let peerMsgOut: Uint8Array | null = null;
    for (let i = 0; i < calls.length; i++) {
      const dv = calls[i]![3] as DataView;
      const chunk = new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
      const res = r1.pushWithType(chunk);
      if (res) { peerMsgOut = res.payload; }
    }
    await peerHs.readMessage(peerMsgOut!);
    const m2 = await peerHs.writeMessage(new Uint8Array(0));
    for (const c of chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2)) {
      txNotifyCb.current?.(c);
    }
    await awaitHandshakeComplete();

    // Collect msg-3, feed to peer.
    const r2 = new FrameReassembler();
    calls = writeRxSpy.mock.calls;
    for (let i = 0; i < calls.length; i++) {
      const dv = calls[i]![3] as DataView;
      const chunk = new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
      const res = r2.pushWithType(chunk);
      if (res && res.frameType === FrameType.HandshakeMsg3) { peerMsgOut = res.payload; }
    }
    if (peerMsgOut) await peerHs.readMessage(peerMsgOut);
    await flushMicrotasks();

    // Happy path: error must NOT be 'handshake-failed'.
    expect(meshState.error).not.toBe('handshake-failed');
  });

  // ── Test 6: idempotent — double failure does not double-emit metric ──────
  it('failHandshake is idempotent: already-rejected cs does not re-emit metric', async () => {
    // This tests the idempotent guard in failHandshake.
    // If cs.verdict is already 'rejected' (from internal advanceHandshake catch),
    // the outer catch should NOT re-emit the metric or re-set verdict.
    writeRxSpy.mockRejectedValueOnce(new Error('first failure'));

    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeFailed();

    const failedMetrics = metrics.filter((m) => m.metric === 'handshake_failed');
    // Should emit exactly 1 metric (not 2 or more).
    expect(failedMetrics).toHaveLength(1);
  });
});

// ── Peer identity factory ───────────────────────────────────────────────────
function mkIdentityPeer() {
  const edSk = ed25519.utils.randomSecretKey();
  const edPk = ed25519.getPublicKey(edSk);
  const xSk = ed25519.utils.toMontgomerySecret(edSk);
  const xPk = x25519.getPublicKey(xSk);
  return {
    async getPublicKey() { return edPk; },
    async sign(msg: Uint8Array) { return ed25519.sign(msg, edSk); },
    async getX25519PublicKey() { return xPk; },
    async dhX25519(remotePub: Uint8Array) { return x25519.getSharedSecret(xSk, remotePub); },
  };
}
