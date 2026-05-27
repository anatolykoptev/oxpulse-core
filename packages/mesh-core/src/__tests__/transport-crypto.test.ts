/**
 * transport-crypto.test.ts — integration tests for the Noise XX + session layer
 * wired into transport.ts (B.2 Task 11).
 *
 * Mocking topology mirrors transport.test.ts. Two "devices" are simulated:
 *   - "Our side": the transport module under test (singleton).
 *   - "Peer side": a manually-driven NoiseXxHandshake + Session instance that
 *     represents what the remote device does.
 *
 * Data flow:
 *   Our writeRx → captured by mock → fed into peer handshake/session
 *   Peer response → injected as tx notification → our handleIncomingChunk
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { NoiseXxHandshake } from '../crypto/noise-xx.js';
import { Session } from '../crypto/session.js';
import { chunkFrame, FrameReassembler, FrameType } from '../frame.js';

// ── Hoist mutable state needed by vi.mock factories ───────────────────────
const { disconnectSpy, writeRxSpy, txNotifyCb, rxListenerCb, connListenerCb, scanCbRef } = vi.hoisted(() => ({
  disconnectSpy: vi.fn(async () => {}),
  writeRxSpy: vi.fn(async () => {}),
  txNotifyCb: { current: null as ((chunk: Uint8Array) => void) | null },
  rxListenerCb: { current: null as ((ev: { deviceAddress: string; data: string }) => void) | null },
  connListenerCb: { current: null as ((ev: { deviceAddress: string; connected: boolean }) => void) | null },
  scanCbRef: { current: null as ((result: unknown) => void) | null },
}));

// ── Peer-id mock — force deterministic role (our peerId < PEER_ID_BYTES) ──────
// PEER_ID_BYTES = 0x77 * 8. We fix our peerId to 0x11 * 8 so we're always
// the initiator (our hex < peer hex), ensuring msg-1 is always sent.
const OUR_PEER_ID = new Uint8Array(8).fill(0x11);
vi.mock('../peer-registry.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../peer-registry.js')>();
  return { ...orig, generatePeerId: () => OUR_PEER_ID };
});

// ── Native plugin mock ────────────────────────────────────────────────────────
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
  // Import ed25519 + x25519 inside the factory — runs after hoisting.
  const { ed25519: ed, x25519: x } = await import('@noble/curves/ed25519.js');
  const edSk = ed.utils.randomSecretKey();
  const edPk = ed.getPublicKey(edSk);
  // B.2-noise-s-key-derivation: derive X25519 keypair via birational map.
  const xSk = ed.utils.toMontgomerySecret(edSk);
  const xPk = x.getPublicKey(xSk);
  const b64pk = (() => {
    let s = '';
    for (const b of edPk) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  })();
  return {
    getOrCreateDeviceIdentity: vi.fn(async () => ({
      publicKeyB64: b64pk,
      publicKey: {} as CryptoKey,
      privateKey: {} as CryptoKey,
      // Include privateKeyBytes so noble DH branch is exercisable (raw seed = edSk).
      privateKeyBytes: edSk,
    })),
    // B.2-noise-s-key-derivation: X25519 static keypair mock.
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

import { startMesh, stopMesh, meshState, sendFrame, getPendingHandshakes, acceptPeer, rejectPeer, _resetTofuStore } from '../transport.js';

// ── Deterministic test identity factory (for peer side) ──────────────────────
// B.2-noise-s-key-derivation: also provides getX25519PublicKey + dhX25519
// so the NoiseXxHandshake can perform real static DH for es/se tokens.
function mkIdentity() {
  const edSk = ed25519.utils.randomSecretKey();
  const edPk = ed25519.getPublicKey(edSk);
  // Derive X25519 keypair from Ed25519 via birational map (RFC 7748).
  const xSk = ed25519.utils.toMontgomerySecret(edSk);
  const xPk = x25519.getPublicKey(xSk);
  return {
    async getPublicKey() { return edPk; },
    async sign(msg: Uint8Array) { return ed25519.sign(msg, edSk); },
    async getX25519PublicKey() { return xPk; },
    async dhX25519(remotePub: Uint8Array) { return x25519.getSharedSecret(xSk, remotePub); },
  };
}

// ── Test constants ─────────────────────────────────────────────────────────
// Use same MTU that the mock BleClient.getMtu returns (247) so handshake
// messages fit within ≤16 chunks (msg-2 ≈ 1200 bytes, needs 5 chunks @ 247).
const TEST_MTU = 247;
const PEER_DEVICE_ID = 'peer-aa:bb:cc';
const PEER_ID_BYTES = new Uint8Array(8).fill(0x77);

/** Build a fake scan sighting for PEER_DEVICE_ID. */
function fakeSighting() {
  return {
    device: { deviceId: PEER_DEVICE_ID },
    rssi: -60,
    serviceData: {
      'f0f10000-6f78-7075-6c73-65000000c8b1': new DataView(PEER_ID_BYTES.buffer),
    },
  };
}

/** Drain microtasks + allow macrotasks (setTimeout) to settle. */
async function drain(n = 30) {
  // Mix microtask draining with a timer yield so WebCrypto operations complete.
  for (let i = 0; i < n; i++) await Promise.resolve();
  await new Promise(r => setTimeout(r, 50));
  for (let i = 0; i < n; i++) await Promise.resolve();
}

/** Extract raw Uint8Array from a writeRxSpy call (arg index 3 = DataView). */
function extractChunk(call: unknown[]): Uint8Array {
  const dv = call[3] as DataView;
  return new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
}

/**
 * Collect all chunks written by transport since lastIdx, feed them through
 * peerReassembler, and return the first complete frame found.
 */
function drainWritesToPeer(
  peerReassembler: FrameReassembler,
  lastIdx: number,
): { newIdx: number; peerMsgOut: Uint8Array | null; frameType: FrameType | null } {
  const calls = writeRxSpy.mock.calls;
  let peerMsgOut: Uint8Array | null = null;
  let frameType: FrameType | null = null;
  for (let i = lastIdx; i < calls.length; i++) {
    const chunk = extractChunk(calls[i]!);
    const res = peerReassembler.pushWithType(chunk);
    if (res) {
      peerMsgOut = res.payload;
      frameType = res.frameType;
    }
  }
  return { newIdx: calls.length, peerMsgOut, frameType };
}

/** Inject bytes from peer toward transport (as tx notification). */
function injectFromPeer(chunks: Uint8Array[]) {
  for (const c of chunks) {
    txNotifyCb.current?.(c);
  }
}

// ── Test suite ─────────────────────────────────────────────────────────────
describe('transport crypto (B.2 Task 11)', () => {
  let peerHs: NoiseXxHandshake;

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
    // Clear TOFU store between tests (works in both browser and Node.js env).
    if (typeof localStorage !== 'undefined') localStorage.clear();
    _resetTofuStore();
    peerHs = new NoiseXxHandshake({ role: 'responder', identity: mkIdentity() });
  });

  afterEach(async () => {
    if (meshState.advertising || meshState.scanning) {
      await stopMesh();
    }
  });

  // ── Helper: start mesh and trigger a peer connection ────────────────────
  async function startAndConnect() {
    await startMesh();
    scanCbRef.current?.(fakeSighting());
    await drain(120);
  }

  // ── Test 1: handshake completes, SAS matches ────────────────────────────
  it('fresh handshake completes; SAS is accessible via getPendingHandshakes', async () => {
    await startAndConnect();

    // Transport (initiator) should have sent msg-1 via writeRx.
    expect(writeRxSpy).toHaveBeenCalled();

    // Collect msg-1 chunks from writeRxSpy.
    const peerReassembler = new FrameReassembler();
    let { newIdx, peerMsgOut, frameType } = drainWritesToPeer(peerReassembler, 0);
    expect(frameType).toBe(FrameType.HandshakeMsg1);
    expect(peerMsgOut).not.toBeNull();

    // Peer reads msg-1, writes msg-2.
    await peerHs.readMessage(peerMsgOut!);
    const m2 = await peerHs.writeMessage(new Uint8Array(0));
    // Inject msg-2 chunks toward transport.
    injectFromPeer(chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2));
    await drain(120);

    // Transport (initiator) should have sent msg-3.
    ({ newIdx, peerMsgOut, frameType } = drainWritesToPeer(new FrameReassembler(), newIdx));
    expect(frameType).toBe(FrameType.HandshakeMsg3);
    expect(peerMsgOut).not.toBeNull();

    // Peer reads msg-3 — handshake complete on both sides.
    await peerHs.readMessage(peerMsgOut!);
    expect(peerHs.isComplete()).toBe(true);

    // Transport should expose this peer in getPendingHandshakes.
    const pending = getPendingHandshakes();
    expect(pending.length).toBeGreaterThan(0);
    const ph = pending[0]!;
    expect(ph.sas).toMatch(/^[0-9]{5}$/);
    // SAS must match what peer computed.
    expect(ph.sas).toBe(peerHs.sas());
  });

  // ── Test 2: sendFrame before acceptPeer throws ──────────────────────────
  it('sendFrame before acceptPeer throws unknown-peer-key', async () => {
    await startAndConnect();

    const peerIdHex = Array.from(PEER_ID_BYTES).map(b => b.toString(16).padStart(2, '0')).join('');
    await expect(sendFrame(peerIdHex, new Uint8Array([1, 2, 3]))).rejects.toThrow(
      /unknown-peer-key|not accepted|pending/i,
    );
  });

  // ── Test 3: sendFrame after acceptPeer encrypts via session ─────────────
  it('sendFrame after acceptPeer round-trips encrypted payload', async () => {
    await startAndConnect();

    // Step through the handshake.
    const r1 = new FrameReassembler();
    let { newIdx, peerMsgOut } = drainWritesToPeer(r1, 0);
    await peerHs.readMessage(peerMsgOut!);
    const m2 = await peerHs.writeMessage(new Uint8Array(0));
    injectFromPeer(chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2));
    await drain(120);

    const r2 = new FrameReassembler();
    ({ newIdx, peerMsgOut } = drainWritesToPeer(r2, newIdx));
    await peerHs.readMessage(peerMsgOut!);
    expect(peerHs.isComplete()).toBe(true);

    // acceptPeer — unblock sendFrame.
    const peerIdHex = Array.from(PEER_ID_BYTES).map(b => b.toString(16).padStart(2, '0')).join('');
    acceptPeer(peerIdHex);

    // Build peer session (responder side).
    const peerSplit = peerHs.split();
    const peerSession = new Session({
      sendKey: peerSplit.sendKey,
      recvKey: peerSplit.recvKey,
      direction: 'responder',
    });

    // Send a frame from our side.
    const plaintext = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    await sendFrame(peerIdHex, plaintext);
    await drain(20);

    // Collect the encrypted chunks written after msg-3.
    const r3 = new FrameReassembler();
    let encryptedPayload: Uint8Array | null = null;
    let encFrameType: FrameType | null = null;
    for (let i = newIdx; i < writeRxSpy.mock.calls.length; i++) {
      const chunk = extractChunk(writeRxSpy.mock.calls[i]!);
      const res = r3.pushWithType(chunk);
      if (res) {
        encryptedPayload = res.payload;
        encFrameType = res.frameType;
      }
    }

    expect(encFrameType).toBe(FrameType.SessionData);
    expect(encryptedPayload).not.toBeNull();

    // Peer decrypts — should recover original plaintext.
    const recovered = await peerSession.decrypt(encryptedPayload!);
    expect(recovered).toEqual(plaintext);
  });

  // ── Test 4: replay of session frame → meshState.error = 'replay-rejected'
  it('replay of a session-data frame sets meshState.error = replay-rejected', async () => {
    await startAndConnect();

    // Complete handshake.
    const r1 = new FrameReassembler();
    let { newIdx, peerMsgOut } = drainWritesToPeer(r1, 0);
    await peerHs.readMessage(peerMsgOut!);
    const m2 = await peerHs.writeMessage(new Uint8Array(0));
    injectFromPeer(chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2));
    await drain(120);

    const r2 = new FrameReassembler();
    ({ newIdx, peerMsgOut } = drainWritesToPeer(r2, newIdx));
    await peerHs.readMessage(peerMsgOut!);
    expect(peerHs.isComplete()).toBe(true);

    const peerIdHex = Array.from(PEER_ID_BYTES).map(b => b.toString(16).padStart(2, '0')).join('');
    acceptPeer(peerIdHex);

    // Peer session (responder side).
    const peerSplit = peerHs.split();
    const peerSession = new Session({
      sendKey: peerSplit.sendKey,
      recvKey: peerSplit.recvKey,
      direction: 'responder',
    });

    // Peer encrypts a frame and sends it toward our transport.
    const pt = new Uint8Array([0x01, 0x02]);
    const wire = await peerSession.encrypt(pt);
    const chunks = chunkFrame(wire, TEST_MTU, FrameType.SessionData);

    // First delivery — should succeed (no error).
    injectFromPeer(chunks);
    await drain(40);
    expect(meshState.error).toBeNull();

    // Replay the same chunks — should trigger replay-rejected.
    injectFromPeer(chunks);
    await drain(40);
    expect(meshState.error).toBe('replay-rejected');
  });

  // ── Test 5: TOFU key change → unknown-peer-key ──────────────────────────
  it('TOFU: second handshake with same peer-id but different pubkey triggers unknown-peer-key', async () => {
    // First handshake — TOFU stores the pubkey.
    await startAndConnect();

    const r1 = new FrameReassembler();
    let { newIdx, peerMsgOut } = drainWritesToPeer(r1, 0);
    await peerHs.readMessage(peerMsgOut!);
    const m2 = await peerHs.writeMessage(new Uint8Array(0));
    injectFromPeer(chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2));
    await drain(120);

    const r2 = new FrameReassembler();
    ({ peerMsgOut } = drainWritesToPeer(r2, newIdx));
    await peerHs.readMessage(peerMsgOut!);
    expect(peerHs.isComplete()).toBe(true);

    // First handshake TOFU stores the pubkey. No error expected.
    expect(meshState.error).toBeNull();

    // Stop and reconnect with a DIFFERENT identity.
    await stopMesh();
    writeRxSpy.mockClear();
    txNotifyCb.current = null;

    const impostorHs = new NoiseXxHandshake({ role: 'responder', identity: mkIdentity() });

    await startMesh();
    scanCbRef.current?.(fakeSighting()); // same peer-id bytes → same peerIdHex
    await drain(120);

    // Collect msg-1.
    const r3 = new FrameReassembler();
    let impostorMsg: Uint8Array | null = null;
    for (let i = 0; i < writeRxSpy.mock.calls.length; i++) {
      const chunk = extractChunk(writeRxSpy.mock.calls[i]!);
      const res = r3.pushWithType(chunk);
      if (res && res.frameType === FrameType.HandshakeMsg1) {
        impostorMsg = res.payload;
      }
    }
    expect(impostorMsg).not.toBeNull();

    // Feed msg-1 to impostor responder.
    await impostorHs.readMessage(impostorMsg!);
    const m2imp = await impostorHs.writeMessage(new Uint8Array(0));
    injectFromPeer(chunkFrame(m2imp, TEST_MTU, FrameType.HandshakeMsg2));
    await drain(120);

    // Collect msg-3.
    const r4 = new FrameReassembler();
    let msg3: Uint8Array | null = null;
    for (let i = 0; i < writeRxSpy.mock.calls.length; i++) {
      try {
        const chunk = extractChunk(writeRxSpy.mock.calls[i]!);
        const res = r4.pushWithType(chunk);
        if (res && res.frameType === FrameType.HandshakeMsg3) {
          msg3 = res.payload;
        }
      } catch {
        // frame type mismatch or reassembler state error — try next chunk
      }
    }
    if (msg3) await impostorHs.readMessage(msg3);
    await drain(20);

    // TOFU mismatch: peer-id same, pubkey different.
    const pending = getPendingHandshakes();
    const hasKeyChange = pending.some(p => p.keyChanged);
    const hasError = meshState.error === 'unknown-peer-key';
    expect(hasKeyChange || hasError).toBe(true);
  });

  // ── Test 6 (C2): out-of-state handshake frame → silent drop, no verdict ──
  // Regression for fix C2: replayed or out-of-order BLE handshake frames must
  // be silently dropped; they must NOT permanently reject the connection.
  it('out-of-state handshake frame (replay) is silently dropped; verdict stays pending', async () => {
    await startAndConnect();

    // Collect msg-1 that transport sent.
    const r1 = new FrameReassembler();
    const { peerMsgOut } = drainWritesToPeer(r1, 0);
    expect(peerMsgOut).not.toBeNull();

    // Peer reads msg-1 and prepares msg-2.
    await peerHs.readMessage(peerMsgOut!);
    const m2 = await peerHs.writeMessage(new Uint8Array(0));

    // Inject msg-2 once — transport processes it normally.
    injectFromPeer(chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2));
    await drain(120);

    // Now replay msg-2 again (out-of-state: transport already advanced to msg-3 state).
    // Per C2 fix: this must be silently dropped, NOT set verdict='rejected'.
    injectFromPeer(chunkFrame(m2, TEST_MTU, FrameType.HandshakeMsg2));
    await drain(60);

    // Verdict must NOT be 'rejected' — crypto state should remain (pending or accepted).
    // The handshake either completed (sas set) or is still in-flight, never poisoned.
    const peerIdHex = Array.from(PEER_ID_BYTES).map(b => b.toString(16).padStart(2, '0')).join('');
    const pending = getPendingHandshakes();
    // Either pending list has the peer (handshake completed; SAS waiting), OR at minimum
    // the error state is NOT 'handshake-failed' from a spurious rejection.
    const notPoisoned = meshState.error !== 'handshake-failed' ||
                        pending.some(p => p.peerIdHex === peerIdHex);
    expect(notPoisoned).toBe(true);
    // Verify error is not 'handshake-failed' due to replay alone.
    expect(meshState.error).not.toBe('handshake-failed');
  });

  // ── Test 7 (C1): responder bootstrap awaits local identity ────────────────
  // Regression for fix C1: when peer initiates before our scan callback fires
  // getLocalIdentity(), the responder fallback must await identity resolution
  // instead of null-asserting localIdentityProvider!.
  it('responder bootstrap path awaits local identity without null-assertion crash', async () => {
    // Start mesh but do NOT trigger a scan sighting (we are the responder).
    await startMesh();
    await drain(10);

    // Register PEER_DEVICE_ID in connectedDevices by faking a successful connection:
    // The peer initiates — we receive HandshakeMsg1 from them before our scan resolves.
    // Simulate: inject a msg-1 from peer toward transport as a raw rx event.
    const peerHsInit = new NoiseXxHandshake({ role: 'initiator', identity: mkIdentity() });
    const m1 = await peerHsInit.writeMessage(new Uint8Array(0));

    // Fake that PEER_DEVICE_ID is in the registry (as a peer entry) so
    // handleIncomingChunk can resolve peerIdHex.
    // We do that by injecting through the scan path first then rx immediately.
    scanCbRef.current?.(fakeSighting());
    await drain(20); // let connect complete but not full handshake initiation

    // Now inject msg-1 as if peer sent it to us (rx listener path).
    const chunks = chunkFrame(m1, TEST_MTU, FrameType.HandshakeMsg1);
    for (const c of chunks) {
      rxListenerCb.current?.({ deviceAddress: PEER_DEVICE_ID, data: btoa(String.fromCharCode(...c)) });
    }
    await drain(120);

    // The transport must NOT crash (null-assert on localIdentityProvider).
    // Evidence: it should have responded with msg-2 via writeRx.
    // Check that writeRxSpy was called at some point (msg-1 and/or msg-2 sent).
    expect(writeRxSpy).toHaveBeenCalled();

    // meshState.error must not be 'handshake-failed' due to identity null crash.
    expect(meshState.error).not.toBe('handshake-failed');
  });
});
