/**
 * inbound-connection-handshake.test.ts — F2 (2026-08-04 audit): an INBOUND
 * connection (a peer connecting TO our GATT server without us connecting
 * outbound to it) must be registered in `connectedDevices` so the responder
 * handshake guards in handleIncomingChunk / checkHandshakeTimeouts don't drop
 * every frame.
 *
 * Scenario: we connect outbound to a peer (registry entry created), the link
 * drops (connectedDevices + cryptoStates cleared, registry retains the peer),
 * then the peer reconnects INBOUND via the native `connection` listener with
 * `{ connected: true }`. The inbound listener must record the device in
 * connectedDevices. We then deliver a HandshakeMsg1 through the `rx` listener
 * (the GATT-server RX path — the path inbound peers use) and assert the
 * responder handshake actually starts: a CryptoState is created and NO
 * `handshake_frame_dropped` metric is emitted.
 *
 * F2 RED-on-revert (mutation): delete the `else { ... connectedDevices.set
 * ... }` branch added to the `connection` listener in transport.ts. With the
 * branch gone, `connectedDevices.has(deviceAddress)` is false at the
 * responder guard (transport.ts handleIncomingChunk) → `handshake_frame_dropped`
 * is emitted and no CryptoState is created → both assertions fail.
 *
 * Design note: the responder-bootstrap path looks the peer up in the registry
 * (`registry.list().find(p => p.mac === deviceAddress)`) BEFORE the
 * connectedDevices guard. A peer that was NEVER connected outbound has no
 * registry entry, so it never reaches the guard — making a strict
 * "never-outbound" test vacuous (it passes with the fix reverted). The test
 * therefore uses a prior outbound session that has since disconnected: the
 * peer is in the registry but NOT in connectedDevices at the moment of the
 * inbound event, which is the exact condition F2's guard fixes. The registry
 * gap for truly-never-outbound peers is a separate concern, out of F2's scope.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Hoist mutable state + controllable handshake class ────────────────────
const { disconnectSpy, writeRxSpy, txNotifyCb, rxListenerCb, connListenerCb, scanCbRef, handshakeRef, ControllableHandshake } = vi.hoisted(() => {
  class ControllableHandshake {
    role: 'initiator' | 'responder';
    msgIdx = 0;
    readQueue: ('ok' | 'fail' | 'noise_state')[] = [];
    readCallCount = 0;

    constructor(opts: { role: 'initiator' | 'responder'; identity: unknown }) {
      this.role = opts.role;
    }

    async readMessage(_payload: Uint8Array): Promise<Uint8Array> {
      const outcome = this.readQueue[this.readCallCount++] ?? 'ok';
      if (outcome === 'fail') throw new Error('protocol violation (corrupt payload)');
      if (outcome === 'noise_state') {
        const { NoiseStateError } = await import('../crypto/noise-xx.js');
        throw new NoiseStateError('out of state');
      }
      this.msgIdx++;
      return new Uint8Array(0);
    }

    async writeMessage(_payload: Uint8Array): Promise<Uint8Array> {
      this.msgIdx++;
      return new Uint8Array(32);
    }

    isComplete(): boolean { return this.msgIdx >= 3; }
    split(): { sendKey: Uint8Array; recvKey: Uint8Array } {
      return { sendKey: new Uint8Array(32), recvKey: new Uint8Array(32) };
    }
    sas(): string { return '12345'; }
    peerStaticPublicKey(): Uint8Array | null { return new Uint8Array(32); }
  }

  return {
    disconnectSpy: vi.fn(async () => {}),
    writeRxSpy: vi.fn(async () => {}),
    txNotifyCb: { current: null as ((chunk: Uint8Array) => void) | null },
    rxListenerCb: { current: null as ((ev: { deviceAddress: string; data: string }) => void) | null },
    connListenerCb: { current: null as ((ev: { deviceAddress: string; connected: boolean }) => void) | null },
    scanCbRef: { current: null as ((result: unknown) => void) | null },
    handshakeRef: { current: null as ControllableHandshake | null },
    ControllableHandshake,
  };
});

// ── Peer-id mock — force RESPONDER role (our peerId 0x11 > peer 0x01) ─────
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
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
  _resetTofuStore,
  _hasCryptoState,
} from '../transport.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';
import { chunkFrame, FrameType } from '../frame.js';
import { waitFor, flushMicrotasks } from './_async-helpers.js';

// ── Test constants ─────────────────────────────────────────────────────────
const TEST_MTU = 247;
const PEER_DEVICE_ID = 'peer-inbound-aa:bb:cc';
// Peer peerId (0x01) < our peerId (0x11) → we are the RESPONDER.
const PEER_ID_BYTES = new Uint8Array(8).fill(0x01);

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
// the next assertion reads: _hasCryptoState or the metrics sink.

/** Wait for a CryptoState to exist (or not) for the given device. */
async function awaitCryptoState(deviceId: string, present: boolean): Promise<void> {
  await waitFor(
    () => _hasCryptoState(deviceId) === present,
    present
      ? `CryptoState to be created for ${deviceId}`
      : `CryptoState to be cleared for ${deviceId}`,
  );
}

/** Inject a HandshakeMsg1 frame from the peer via the GATT-server RX path. */
function injectMsg1ViaRx(deviceAddress: string) {
  const payload = new Uint8Array([0x42]); // dummy — mock ignores payload content
  const chunks = chunkFrame(payload, TEST_MTU, FrameType.HandshakeMsg1);
  for (const c of chunks) {
    let s = '';
    for (const b of c) s += String.fromCharCode(b);
    rxListenerCb.current?.({ deviceAddress, data: btoa(s) });
  }
}

// ── Test suite ─────────────────────────────────────────────────────────────
describe('F2: inbound connection registers in connectedDevices so responder handshake starts', () => {
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

  it('an inbound ({connected:true}) connection lets the responder handshake start (no frame dropped)', async () => {
    await startMesh();
    await flushMicrotasks();

    // 1. Outbound connect succeeds → peer registered + connectedDevices set +
    //    initiateHandshake creates a responder CryptoState (no msg-1 sent).
    scanCbRef.current?.(fakeSighting());
    await awaitCryptoState(PEER_DEVICE_ID, true);

    // 2. The link drops. connectedDevices + cryptoStates are cleared; the
    //    registry retains the peer (30s GC).
    connListenerCb.current?.({ deviceAddress: PEER_DEVICE_ID, connected: false });
    await awaitCryptoState(PEER_DEVICE_ID, false);
    expect(_hasCryptoState(PEER_DEVICE_ID)).toBe(false);

    // 3. The peer reconnects INBOUND via the native connection listener. This
    //    is the path F2 fixes: the device is NOT in connectedDevices here.
    //    The connection listener sets connectedDevices synchronously; flush
    //    microtasks so the entry is visible before we inject the frame.
    connListenerCb.current?.({ deviceAddress: PEER_DEVICE_ID, connected: true });
    await flushMicrotasks();

    // 4. Deliver a HandshakeMsg1 through the GATT-server RX listener (the path
    //    inbound peers use). The responder-bootstrap guard checks
    //    connectedDevices.has(deviceAddress) — without F2 this drops the frame.
    //    The responder-bootstrap path awaits getLocalIdentity() (async IDB),
    //    then creates a CryptoState and advances the handshake — wait on that.
    injectMsg1ViaRx(PEER_DEVICE_ID);
    await awaitCryptoState(PEER_DEVICE_ID, true);

    // Core assertions — observable state, not log strings.
    // (a) The responder handshake actually started: a CryptoState was created.
    expect(_hasCryptoState(PEER_DEVICE_ID), 'no CryptoState created — responder handshake did not start').toBe(true);
    // (b) NO handshake_frame_dropped metric was emitted (the guard passed).
    const dropped = metrics.filter((m) => m.metric === 'handshake_frame_dropped');
    expect(dropped, 'handshake frame was dropped by the connectedDevices guard').toHaveLength(0);
  });
});
