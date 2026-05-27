/**
 * handshake-timeout.test.ts — B.2-handshake-timeout
 *
 * Verifies that a pending CryptoState whose handshakeStartedAt is more than
 * HANDSHAKE_TIMEOUT_MS ago transitions to verdict='rejected' when the
 * timeout-check interval fires.
 *
 * Strategy: use vi.useFakeTimers with shouldAdvanceTime:false, drive the
 * timer tick manually via vi.advanceTimersByTime, and use only
 * Promise.resolve() microtask drains (not real setTimeout).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Hoist spy refs ───────────────────────────────────────────────────────────
const { scanCbRefT, connectSpy } = vi.hoisted(() => ({
  scanCbRefT: { current: null as ((result: unknown) => void) | null },
  connectSpy: vi.fn(async (_id: unknown, _onDisconnect: unknown) => {}),
}));

vi.mock('@capacitor/core', () => ({
  registerPlugin: () => ({
    startAdvertising: vi.fn(async () => {}),
    stopAdvertising: vi.fn(async () => {}),
    startGattServer: vi.fn(async () => {}),
    stopGattServer: vi.fn(async () => {}),
    notifyTx: vi.fn(async () => {}),
    addListener: vi.fn((_event: string, _cb: unknown) => ({ remove: async () => {} })),
  }),
}));

vi.mock('@capacitor-community/bluetooth-le', () => ({
  BleClient: {
    initialize: vi.fn(async () => {}),
    requestLEScan: vi.fn(async (_opts: unknown, cb: (r: unknown) => void) => {
      scanCbRefT.current = cb;
    }),
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
  // B.2-noise-s-key-derivation: provide X25519 keypair in mock.
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
    getOrCreateX25519Keypair: vi.fn(async () => ({ publicKey: xPk, privateKey: {} as CryptoKey, privateKeyBytes: xSk })),
    dhX25519: vi.fn(async (remotePub: Uint8Array) => x.getSharedSecret(xSk, remotePub)),
    fromBase64url: (s: string): Uint8Array => {
      let str = s;
      const pad = str.length % 4;
      if (pad) str += '='.repeat(4 - pad);
      const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    },
  };
});

// Our peerId = 0x11*8 so we are the initiator (smaller = initiator).
// We use initiator role so that startMesh sends msg-1 and creates a CryptoState.
const OUR_PEER_ID = new Uint8Array(8).fill(0x11);
vi.mock('../peer-registry.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../peer-registry.js')>();
  return { ...orig, generatePeerId: () => OUR_PEER_ID };
});

import { startMesh, stopMesh, meshState, _resetTofuStore } from '../transport.js';

async function drainMicrotasks(n = 50) {
  for (let i = 0; i < n; i++) await Promise.resolve();
}

describe('B.2-handshake-timeout', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    meshState.peers = [];
    meshState.advertising = false;
    meshState.scanning = false;
    meshState.error = null;
    scanCbRefT.current = null;
    connectSpy.mockClear();
    _resetTofuStore();
  });

  afterEach(async () => {
    vi.useRealTimers();
    if (meshState.advertising || meshState.scanning) {
      await stopMesh();
    }
  });

  it('rejects a pending handshake after HANDSHAKE_TIMEOUT_MS with no response', async () => {
    await startMesh();
    await drainMicrotasks();

    // Peer is larger id (0x77*8 > 0x11*8) → we are initiator, peer is responder.
    // We send msg-1 but peer never replies → handshake stays pending.
    const peerDeviceId = 'dev-timeout:77';
    const peerIdBytes = new Uint8Array(8).fill(0x77);
    const serviceData = {
      'f0f10000-6f78-7075-6c73-65000000c8b1': new DataView(peerIdBytes.buffer),
    };

    scanCbRefT.current?.({ device: { deviceId: peerDeviceId }, rssi: -60, serviceData });
    await drainMicrotasks(80); // allow connect + initiateHandshake to settle

    // meshState.error should not be handshake-failed yet — timeout not elapsed.
    expect(meshState.error).not.toBe('handshake-failed');

    // Advance fake clock past HANDSHAKE_TIMEOUT_MS (15000ms) + interval (5000ms) = 20001ms.
    vi.advanceTimersByTime(20_001);
    await drainMicrotasks(20);

    expect(meshState.error).toBe('handshake-failed');
  });
});
