/**
 * sendframe-inbound-only-peer.test.ts — #82: sendFrame throws for an accepted
 * inbound-only peer.
 *
 * #80 let a never-outbound peer complete a responder handshake and surface in
 * `getPendingHandshakes()` for SAS verification. But `sendFrame` resolves the
 * peer through the registry (`registry.list().find(p => p.idHex === peerIdHex)`),
 * and `registry.upsert` is called in exactly ONE place — the outbound scan
 * callback. An inbound-only peer never gets a registry entry, so after the user
 * accepts it, `sendFrame` still throws. The channel is half-open; the missing
 * half is the one the user just explicitly authorised.
 *
 * This test drives the WHOLE arc in one case: inbound-only peer with no registry
 * entry → connection event → handshake completes (msg1 in, msg2 out, msg3 in) →
 * `getPendingHandshakes` surfaces it → `acceptPeer` → `sendFrame` — and asserts
 * the frame is actually WRITTEN (the GATT write spy), not merely that no
 * exception escaped. A test that only asserts "does not throw" would pass
 * against a `sendFrame` that silently returns.
 *
 * #82 RED-on-revert (mutation): in transport.ts sendFrame, restore the original
 * `if (!peer) throw new Error(\`sendFrame: unknown peer ${peerIdHex}\`);`
 * immediately after the registry lookup (delete the cryptoStates fallback).
 * With the registry lookup required again, `peer` is undefined for an
 * inbound-only peer → sendFrame throws → the `expect(writeRxSpy).toHaveBeenCalled()`
 * assertion fails (RED).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Hoist mutable state + controllable handshake class ────────────────────
const { disconnectSpy, writeRxSpy, txNotifyCb, rxListenerCb, connListenerCb, scanCbRef, handshakeRef, ControllableHandshake } = vi.hoisted(() => {
  class ControllableHandshake {
    role: 'initiator' | 'responder';
    msgIdx = 0;

    constructor(opts: { role: 'initiator' | 'responder'; identity: unknown }) {
      this.role = opts.role;
    }

    async readMessage(_payload: Uint8Array): Promise<Uint8Array> {
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
  sendFrame,
  acceptPeer,
  getPendingHandshakes,
  _resetTofuStore,
} from '../transport.js';
import { setMeshMetricSink, type MeshMetric } from '../metrics.js';
import { chunkFrame, FrameType } from '../frame.js';

// ── Test constants ─────────────────────────────────────────────────────────
const TEST_MTU = 247;
// A device address that was NEVER seen via scan → no registry entry.
const PEER_DEVICE_ID = 'peer-inbound-only-aa:bb:cc';

async function drain(n = 30) {
  for (let i = 0; i < n; i++) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 50));
  for (let i = 0; i < n; i++) await Promise.resolve();
}

/** Inject a handshake frame from the peer via the GATT-server RX path. */
function injectHandshakeFrame(deviceAddress: string, frameType: number) {
  const payload = new Uint8Array([0x42]); // dummy — mock ignores payload content
  const chunks = chunkFrame(payload, TEST_MTU, frameType);
  for (const c of chunks) {
    let s = '';
    for (const b of c) s += String.fromCharCode(b);
    rxListenerCb.current?.({ deviceAddress, data: btoa(s) });
  }
}

// ── Test suite ─────────────────────────────────────────────────────────────
describe('#82: sendFrame reaches an accepted inbound-only peer (no registry entry)', () => {
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

  it('inbound-only peer: handshake completes → acceptPeer → sendFrame writes the frame', async () => {
    await startMesh();
    await drain();

    // 1. Do NOT fire the scan callback — the peer is never seen outbound.
    //    There is NO registry entry for PEER_DEVICE_ID.

    // 2. The peer connects INBOUND via the native connection listener.
    connListenerCb.current?.({ deviceAddress: PEER_DEVICE_ID, connected: true });
    await drain(30);

    // 3. Deliver HandshakeMsg1 — responder bootstrap creates a CryptoState,
    //    reads msg-1, writes msg-2 (out via writeRx spy).
    injectHandshakeFrame(PEER_DEVICE_ID, FrameType.HandshakeMsg1);
    await drain(60);

    // 4. Deliver HandshakeMsg3 — responder reads msg-3, handshake completes
    //    (split → session, sas, verdict stays pending, notify).
    injectHandshakeFrame(PEER_DEVICE_ID, FrameType.HandshakeMsg3);
    await drain(60);

    // 5. The peer surfaces in getPendingHandshakes with the MAC-fallback idHex.
    const pending = getPendingHandshakes();
    expect(pending, 'no pending handshake surfaced').toHaveLength(1);
    expect(pending[0]!.peerIdHex, 'pending peerIdHex should be the MAC fallback').toBe(PEER_DEVICE_ID);
    expect(pending[0]!.sas, 'sas should be set after handshake completion').toBeTruthy();

    // 6. The user accepts the peer after SAS verification.
    acceptPeer(PEER_DEVICE_ID);
    await drain(10);

    // 7. sendFrame to the accepted inbound-only peer. Against current code this
    //    throws (registry miss). After the fix it must resolve AND write.
    //    Clear the spy first so we isolate the sendFrame write from the
    //    handshake's msg-2 write that happened during step 4.
    writeRxSpy.mockClear();
    const frame = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    await expect(sendFrame(PEER_DEVICE_ID, frame)).resolves.toBeUndefined();
    await drain(10);

    // 8. Observable: the frame was actually WRITTEN via the GATT write spy —
    //    not merely that no exception escaped. A sendFrame that silently
    //    returned would fail this assertion. writeRx (gatt-channel) forwards to
    //    BleClient.writeWithoutResponse(deviceId, serviceUUID, charUUID, DataView),
    //    so the device address is arg 0 and the chunk bytes are the DataView at
    //    arg 3.
    expect(writeRxSpy, 'sendFrame did not write any chunk to the GATT characteristic').toHaveBeenCalled();
    expect(
      writeRxSpy.mock.calls.every((call) => call[0] === PEER_DEVICE_ID),
      'writeRx called for a different device address',
    ).toBe(true);

    // The written chunk must be a SessionData frame (frame_type nibble === 3),
    // proving the encrypted session payload — not a stray handshake chunk —
    // was emitted.
    const firstDataView = writeRxSpy.mock.calls[0]![3] as DataView;
    expect((firstDataView.getUint8(1) >> 4) & 0x0f, 'written frame is not SessionData').toBe(FrameType.SessionData);
  });
});
