/**
 * handshake-failures-reset.test.ts — #46: verifies that CryptoState.handshakeFailures
 * is reset to 0 when a handshake completes successfully (session established).
 *
 * Invariant: handshakeFailures counts protocol violations within a single handshake
 * attempt, NOT across the lifetime of a CryptoState. Without the reset, 2 prior
 * failures + a later re-handshake violation would cause premature permanent rejection.
 *
 * The test uses a controllable NoiseXxHandshake mock to inject failures at precise
 * points in the handshake flow, while exercising the REAL advanceHandshake code path
 * (counter increment, reset logic, metric emission) in transport.ts.
 *
 * RED when the fix is removed: without `cs.handshakeFailures = 0` on session
 * establishment, the counter stays at 2 after the successful handshake, and the
 * 3rd failure increments it to 3 → premature rejection.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Hoist mutable state + controllable handshake class ────────────────────
// vi.mock factories are hoisted above all top-level code, so the
// ControllableHandshake class must live inside vi.hoisted to be in scope.
const { disconnectSpy, writeRxSpy, txNotifyCb, rxListenerCb, connListenerCb, scanCbRef, handshakeRef, ControllableHandshake } = vi.hoisted(() => {
  // ── Controllable NoiseXxHandshake mock ─────────────────────────────────────
  // Replaces the real NoiseXxHandshake so we can inject failures at precise points
  // without corrupting internal cipher state (which the real impl does on partial
  // readMessage processing). The REAL advanceHandshake code in transport.ts is
  // exercised — only the Noise library dependency is mocked.
  class ControllableHandshake {
    role: 'initiator' | 'responder';
    msgIdx = 0;
    // Queue of outcomes for each readMessage call: 'ok' | 'fail' | 'noise_state'.
    // 'fail' throws a plain Error (protocol violation → increments handshakeFailures).
    // 'noise_state' throws NoiseStateError (out-of-state → silently dropped).
    readQueue: ('ok' | 'fail' | 'noise_state')[] = [];
    readCallCount = 0;

    constructor(opts: { role: 'initiator' | 'responder'; identity: unknown }) {
      this.role = opts.role;
    }

    async readMessage(_payload: Uint8Array): Promise<Uint8Array> {
      const outcome = this.readQueue[this.readCallCount++] ?? 'ok';
      if (outcome === 'fail') throw new Error('protocol violation (corrupt payload)');
      if (outcome === 'noise_state') {
        // NoiseStateError is imported lazily to avoid circular mock issues.
        const { NoiseStateError } = await import('../crypto/noise-xx.js');
        throw new NoiseStateError('out of state');
      }
      this.msgIdx++;
      return new Uint8Array(0);
    }

    async writeMessage(_payload: Uint8Array): Promise<Uint8Array> {
      this.msgIdx++;
      // Return non-empty dummy bytes so chunkFrame doesn't throw on "empty payload".
      return new Uint8Array(32);
    }

    isComplete(): boolean {
      return this.msgIdx >= 3;
    }

    split(): { sendKey: Uint8Array; recvKey: Uint8Array } {
      return { sendKey: new Uint8Array(32), recvKey: new Uint8Array(32) };
    }

    sas(): string {
      return '12345';
    }

    peerStaticPublicKey(): Uint8Array | null {
      return new Uint8Array(32);
    }
  }

  return {
    disconnectSpy: vi.fn(async () => {}),
    writeRxSpy: vi.fn(async () => {}),
    txNotifyCb: { current: null as ((chunk: Uint8Array) => void) | null },
    rxListenerCb: { current: null as ((ev: { deviceAddress: string; data: string }) => void) | null },
    connListenerCb: { current: null as ((ev: { deviceAddress: string; connected: boolean }) => void) | null },
    scanCbRef: { current: null as ((result: unknown) => void) | null },
    // Reference to the controllable handshake instance created by the mock factory.
    handshakeRef: { current: null as ControllableHandshake | null },
    ControllableHandshake,
  };
});

// ── Peer-id mock — force initiator role (our peerId < PEER_ID_BYTES) ──────
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
      publicKeyB64: b64pk,
      publicKey: {} as CryptoKey,
      privateKey: {} as CryptoKey,
      privateKeyBytes: edSk,
    })),
    getOrCreateX25519Keypair: vi.fn(async () => ({ publicKey: xPk, privateKey: {} as CryptoKey, privateKeyBytes: xSk })),
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

// Mock NoiseXxHandshake with our controllable class; keep real NoiseStateError.
vi.mock('../crypto/noise-xx.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../crypto/noise-xx.js')>();
  return {
    ...orig,
    NoiseXxHandshake: class extends ControllableHandshake {
      constructor(opts: { role: 'initiator' | 'responder'; identity: unknown }) {
        super(opts);
        handshakeRef.current = this as unknown as typeof handshakeRef.current;
      }
    },
  };
});

import {
  startMesh,
  stopMesh,
  meshState,
  getPendingHandshakes,
  _resetTofuStore,
  _getHandshakeFailures,
} from '../transport.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';
import { chunkFrame, FrameType } from '../frame.js';
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
// Replaces the fixed wall-clock `drain()`. Each wait targets the observable
// the next assertion reads: handshakeFailures counter or getPendingHandshakes.

/** Wait for initiateHandshake to run (ControllableHandshake instance created). */
async function awaitHandshakeStarted(): Promise<void> {
  await waitFor(() => handshakeRef.current !== null, 'initiateHandshake to create a CryptoState');
}

/** Wait for handshakeFailures to reach exactly `n` for PEER_DEVICE_ID. */
async function awaitFailures(n: number): Promise<void> {
  await waitFor(
    () => _getHandshakeFailures(PEER_DEVICE_ID) === n,
    `handshakeFailures to reach ${n}`,
  );
}

/** Wait for the handshake to complete (SAS available) and counter reset to 0. */
async function awaitHandshakeCompleteReset(): Promise<void> {
  await waitFor(
    () => getPendingHandshakes().length > 0 && _getHandshakeFailures(PEER_DEVICE_ID) === 0,
    'handshake to complete (SAS available) and handshakeFailures reset to 0',
  );
}

/** Inject a handshake msg-2 frame from "peer" toward transport. */
function injectMsg2() {
  const payload = new Uint8Array([0x42]); // dummy — mock ignores payload content
  const chunks = chunkFrame(payload, TEST_MTU, FrameType.HandshakeMsg2);
  for (const c of chunks) {
    txNotifyCb.current?.(c);
  }
}

// ── Test suite ─────────────────────────────────────────────────────────────
describe('#46: handshakeFailures reset on successful handshake (issue #46)', () => {
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
    handshakeRef.current = null;
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

  // ── Core invariant: counter reset to 0 on successful handshake ──────────
  it('handshakeFailures reset to 0 after 2 failures + successful handshake', async () => {
    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeStarted();

    // Transport (initiator) sent msg-1; NoiseXxHandshake mock was created.
    expect(handshakeRef.current).not.toBeNull();
    const hs = handshakeRef.current!;

    // Queue: 2 failures, then success (completes the handshake).
    hs.readQueue = ['fail', 'fail', 'ok'];

    // Inject msg-2 #1 → readMessage throws Error → handshakeFailures=1.
    injectMsg2();
    await awaitFailures(1);
    expect(_getHandshakeFailures(PEER_DEVICE_ID)).toBe(1);

    // Inject msg-2 #2 → readMessage throws Error → handshakeFailures=2.
    injectMsg2();
    await awaitFailures(2);
    expect(_getHandshakeFailures(PEER_DEVICE_ID)).toBe(2);

    // Inject msg-2 #3 → readMessage succeeds → transport sends msg-3 →
    // isComplete() → split → session established → handshakeFailures reset to 0.
    injectMsg2();
    await awaitHandshakeCompleteReset();

    // Core assertion: counter must be 0 after successful handshake.
    // RED without fix: counter stays at 2.
    expect(_getHandshakeFailures(PEER_DEVICE_ID)).toBe(0);

    // Session must be established (handshake completed).
    const pending = getPendingHandshakes();
    expect(pending.length).toBeGreaterThan(0);
    expect(pending[0]!.sas).toBe('12345');
  });

  // ── Metric: handshake_failures_reset emitted on reset ───────────────────
  it('handshake_failures_reset metric emitted when counter is reset', async () => {
    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeStarted();

    const hs = handshakeRef.current!;
    hs.readQueue = ['fail', 'fail', 'ok'];

    // 2 failures.
    injectMsg2();
    await awaitFailures(1);
    injectMsg2();
    await awaitFailures(2);
    expect(_getHandshakeFailures(PEER_DEVICE_ID)).toBe(2);

    // Successful handshake → reset.
    injectMsg2();
    await awaitHandshakeCompleteReset();

    const resetMetrics = metrics.filter((m) => m.metric === 'handshake_failures_reset');
    expect(resetMetrics.length).toBeGreaterThanOrEqual(1);
    expect(resetMetrics[0]!.labels?.device).toBe(PEER_DEVICE_ID);
  });

  // ── No premature rejection: 3rd failure after reset does not reject ─────
  it('3rd failure after reset does NOT cause premature rejection', async () => {
    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeStarted();

    const hs = handshakeRef.current!;
    // Queue: 2 failures, success (handshake completes, counter reset), then 1 more failure.
    hs.readQueue = ['fail', 'fail', 'ok', 'fail'];

    // 2 failures.
    injectMsg2();
    await awaitFailures(1);
    injectMsg2();
    await awaitFailures(2);
    expect(_getHandshakeFailures(PEER_DEVICE_ID)).toBe(2);

    // Successful handshake → counter reset to 0.
    injectMsg2();
    await awaitHandshakeCompleteReset();
    expect(_getHandshakeFailures(PEER_DEVICE_ID)).toBe(0);

    // 3rd failure (after reset) → counter goes to 1, NOT 3.
    // Without fix: counter was 2, this makes it 3 → premature rejection.
    injectMsg2();
    await awaitFailures(1);

    // With fix: counter is 1 (not 3), no rejection.
    expect(_getHandshakeFailures(PEER_DEVICE_ID)).toBe(1);
    // No premature rejection — error must NOT be 'handshake-failed'.
    // RED without fix: counter goes to 3 → meshState.error = 'handshake-failed'.
    expect(meshState.error).not.toBe('handshake-failed');
  });

  // ── Regression: no reset metric when counter was already 0 ──────────────
  it('handshake_failures_reset NOT emitted when counter was already 0', async () => {
    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await awaitHandshakeStarted();

    const hs = handshakeRef.current!;
    // No failures — straight to success.
    hs.readQueue = ['ok'];

    injectMsg2();
    await waitFor(() => getPendingHandshakes().length > 0, 'handshake to complete (SAS available)');

    // Counter was 0 before handshake completion → no reset needed → no metric.
    const resetMetrics = metrics.filter((m) => m.metric === 'handshake_failures_reset');
    expect(resetMetrics).toHaveLength(0);
  });
});
