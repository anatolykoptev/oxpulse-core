/**
 * never-outbound-responder-handshake.test.ts — #59: a peer that has NEVER
 * connected outbound (no registry entry, no prior outbound session) must still
 * be able to complete a responder handshake when it connects inbound to our
 * GATT server.
 *
 * This is the case that `inbound-connection-handshake.test.ts` (F2) deliberately
 * could NOT cover: F2 uses a previously-outbound peer (registry entry exists),
 * because a strictly-never-outbound peer never reached the connectedDevices
 * guard under test — it was blocked one step earlier by the `if (peerId && peer)`
 * registry-lookup condition in `handleIncomingChunk`.
 *
 * Scenario: start mesh (scan + advertise). Do NOT fire the scan callback — the
 * peer is never seen outbound, so no registry entry is created. The peer
 * connects INBOUND via the native `connection` listener with
 * `{ connected: true }` (F2 registers it in connectedDevices). We then deliver
 * a HandshakeMsg1 through the `rx` listener (the GATT-server RX path inbound
 * peers use) and assert the responder handshake actually starts: a CryptoState
 * is created and NO `handshake_frame_dropped` metric is emitted.
 *
 * #59 RED-on-revert (mutation): in transport.ts handleIncomingChunk, restore
 * the guard from `if (peerId)` back to `if (peerId && peer)` and the role
 * computation from `peer ? roleFor(...) : 'responder'` back to
 * `roleFor(peerId, peerIdBytes)`. With the registry lookup required again,
 * `peer` is undefined for a never-outbound peer → the bootstrap block is
 * skipped → no CryptoState is created → the `_hasCryptoState` assertion fails.
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

// ── Peer-id mock — force a known ourPeerId so `peerId` is set after startMesh ─
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

// ── Test constants ─────────────────────────────────────────────────────────
const TEST_MTU = 247;
// A device address that was NEVER seen via scan → no registry entry.
const PEER_DEVICE_ID = 'peer-never-outbound-dd:ee:ff';

async function drain(n = 30) {
  for (let i = 0; i < n; i++) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 50));
  for (let i = 0; i < n; i++) await Promise.resolve();
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
describe('#59: never-outbound peer (no registry entry) can start responder handshake', () => {
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

  it('an inbound-only peer with NO registry entry starts the responder handshake (no frame dropped)', async () => {
    await startMesh();
    await drain();

    // 1. Do NOT fire the scan callback — the peer is never seen outbound.
    //    There is no registry entry for PEER_DEVICE_ID.

    // 2. The peer connects INBOUND via the native connection listener.
    //    F2 registers it in connectedDevices.
    connListenerCb.current?.({ deviceAddress: PEER_DEVICE_ID, connected: true });
    await drain(30);

    // 3. Deliver a HandshakeMsg1 through the GATT-server RX listener (the path
    //    inbound peers use). Without #59's fix, the `if (peerId && peer)`
    //    guard blocks this — `peer` is undefined (no registry entry) and the
    //    frame is silently dropped with a console.warn.
    injectMsg1ViaRx(PEER_DEVICE_ID);
    await drain(60);

    // Core assertions — observable state, not log strings.
    // (a) The responder handshake actually started: a CryptoState was created.
    expect(_hasCryptoState(PEER_DEVICE_ID), 'no CryptoState created — responder handshake did not start').toBe(true);
    // (b) NO handshake_frame_dropped metric was emitted (the guard passed).
    const dropped = metrics.filter((m) => m.metric === 'handshake_frame_dropped');
    expect(dropped, 'handshake frame was dropped').toHaveLength(0);
  });
});
