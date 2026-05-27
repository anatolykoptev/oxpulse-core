/**
 * Tests for composeMeshWrap / peelMeshWrap (Phase 3 T1).
 *
 * Wire-format notes:
 *   - Outer frame: mesh-bundle-v1 (magic 0xC9). No flags byte in outer header.
 *   - Body is a mesh-wrap-v1 envelope (body[0]=MESH_WRAP_MAGIC=0xAE,
 *     body[1]=flags byte, body[2..] = envelopeBytes).
 *   - isSealed1to1 = flags bit 0 of body[1].
 *   - channelIdHash = SHA-256(recipientX25519Pub)[0..4].
 *
 * ADR followup: outer mesh-bundle header has no flags field (Phase B spec v1
 * is frozen). The is_sealed_1to1 bit MUST live in the mesh-wrap body header
 * (body[1] flags), not in mesh-bundle outer header — wire format extension
 * of the outer bundle requires operator design review. This body-level flag
 * is grep-auditable via MESH_WRAP_FLAG_SEALED_1TO1 constant.
 */

import { describe, it, expect } from 'vitest';
import {
  composeMeshWrap,
  peelMeshWrap,
  MESH_WRAP_MAGIC,
  MESH_WRAP_FLAG_SEALED_1TO1,
} from './wrap.js';
import { MESH_BUNDLE_MAGIC_V1 } from '@oxpulse/wire-codec';
// These match the non-exported constants in mesh-bundle.ts
const MESH_BUNDLE_HEADER_FIXED_LEN = 61;
const MESH_WRAP_BODY_HEADER_LEN_TEST = 2; // magic + flags

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/** Deterministic Ed25519 keypair from @noble/curves for tests. */
async function makeTestKeys(): Promise<{ privKey: Uint8Array; pubKey: Uint8Array }> {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const privKey = new Uint8Array(32);
  privKey[0] = 0x42; // deterministic non-zero
  privKey[1] = 0x13;
  const pubKey = ed25519.getPublicKey(privKey);
  return { privKey, pubKey };
}

/** Fake signEd25519 using @noble/curves — matches real crypto. */
function makeSigner(privKey: Uint8Array): (msg: Uint8Array) => Promise<Uint8Array> {
  return async (msg: Uint8Array): Promise<Uint8Array> => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    return ed25519.sign(msg, privKey);
  };
}

const FAKE_RECIPIENT_X25519_PUB = new Uint8Array(32).fill(0xab);
const FAKE_MSG_ID = new Uint8Array(16).fill(0x01);
const FAKE_ENVELOPE = new Uint8Array(128).fill(0x4f); // arbitrary 128-byte envelope payload

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

describe('composeMeshWrap / peelMeshWrap round-trip', () => {
  it('peeled envelopeBytes equals composed input', async () => {
    const { privKey, pubKey } = await makeTestKeys();
    const bundle = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: FAKE_RECIPIENT_X25519_PUB,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });
    const peeled = peelMeshWrap(bundle);
    expect(peeled.envelopeBytes).toEqual(FAKE_ENVELOPE);
  });

  it('peeled msgId equals input msgId', async () => {
    const { privKey, pubKey } = await makeTestKeys();
    const bundle = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: FAKE_RECIPIENT_X25519_PUB,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });
    const peeled = peelMeshWrap(bundle);
    expect(peeled.msgId).toEqual(FAKE_MSG_ID);
  });

  it('peeled senderEd25519Pub equals input senderEd25519Pub', async () => {
    const { privKey, pubKey } = await makeTestKeys();
    const bundle = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: FAKE_RECIPIENT_X25519_PUB,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });
    const peeled = peelMeshWrap(bundle);
    expect(peeled.senderEd25519Pub).toEqual(pubKey);
  });

  it('isSealed1to1=false round-trips correctly', async () => {
    const { privKey, pubKey } = await makeTestKeys();
    const bundle = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: FAKE_RECIPIENT_X25519_PUB,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });
    const peeled = peelMeshWrap(bundle);
    expect(peeled.isSealed1to1).toBe(false);
  });

  it('isSealed1to1=true round-trips correctly', async () => {
    const { privKey, pubKey } = await makeTestKeys();
    const bundle = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: FAKE_RECIPIENT_X25519_PUB,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: true,
    });
    const peeled = peelMeshWrap(bundle);
    expect(peeled.isSealed1to1).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// channelIdHash derivation
// ---------------------------------------------------------------------------

describe('channelIdHash', () => {
  it('is deterministic: SHA-256(recipientX25519Pub)[0..4]', async () => {
    const { sha256 } = await import('@noble/hashes/sha2.js');
    const { privKey, pubKey } = await makeTestKeys();

    const expectedHash = sha256(FAKE_RECIPIENT_X25519_PUB).slice(0, 4);

    const bundle = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: FAKE_RECIPIENT_X25519_PUB,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });
    const peeled = peelMeshWrap(bundle);
    expect(peeled.channelIdHash).toEqual(expectedHash);
  });

  it('different recipientX25519Pub → different channelIdHash', async () => {
    const { privKey, pubKey } = await makeTestKeys();
    const pub1 = new Uint8Array(32).fill(0x11);
    const pub2 = new Uint8Array(32).fill(0x22);

    const bundle1 = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: pub1,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });
    const bundle2 = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: pub2,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });

    const h1 = peelMeshWrap(bundle1).channelIdHash;
    const h2 = peelMeshWrap(bundle2).channelIdHash;
    expect(h1).not.toEqual(h2);
  });
});

// ---------------------------------------------------------------------------
// Rejection: bad magic / too short
// ---------------------------------------------------------------------------

describe('peelMeshWrap input validation', () => {
  it('rejects input not starting with 0xC9 magic', () => {
    const bad = new Uint8Array(200).fill(0x00);
    bad[0] = 0xde; // wrong magic
    expect(() => peelMeshWrap(bad)).toThrow();
  });

  it('rejects input shorter than minimum bundle size', () => {
    // min = MESH_BUNDLE_HEADER_FIXED_LEN(61) + 0 body + MESH_BUNDLE_SIG_LEN(64) = 125
    const tooShort = new Uint8Array(100).fill(0xc9);
    expect(() => peelMeshWrap(tooShort)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Tampered envelope — peel still succeeds (sig verification is outer layer)
// ---------------------------------------------------------------------------

describe('tampered envelope bytes', () => {
  it('peel succeeds even if envelopeBytes were tampered (sig validation is caller concern)', async () => {
    const { privKey, pubKey } = await makeTestKeys();
    const bundle = await composeMeshWrap({
      envelopeBytes: FAKE_ENVELOPE,
      recipientX25519Pub: FAKE_RECIPIENT_X25519_PUB,
      senderEd25519Pub: pubKey,
      signEd25519: makeSigner(privKey),
      msgId: FAKE_MSG_ID,
      tsMsOffset: 0,
      isSealed1to1: false,
    });

    // Tamper a body byte (envelope content area — after mesh-bundle header + wrap header)
    const tampered = new Uint8Array(bundle);
    // body starts at MESH_BUNDLE_HEADER_FIXED_LEN, wrap header is 2 bytes (magic+flags)
    const envelopeStart = MESH_BUNDLE_HEADER_FIXED_LEN + MESH_WRAP_BODY_HEADER_LEN_TEST;
    tampered[envelopeStart] ^= 0xff; // flip a bit in envelope content

    // peelMeshWrap only reads structure — does not validate Ed25519 sig
    const peeled = peelMeshWrap(tampered);
    // envelopeBytes should differ from original (tampering visible)
    expect(peeled.envelopeBytes).not.toEqual(FAKE_ENVELOPE);
    // but peel itself did not throw
    expect(peeled.msgId).toEqual(FAKE_MSG_ID);
  });
});

// ---------------------------------------------------------------------------
// Constant exports sanity
// ---------------------------------------------------------------------------

describe('exported constants', () => {
  it('MESH_WRAP_MAGIC is defined and non-zero', () => {
    expect(MESH_WRAP_MAGIC).toBeDefined();
    expect(MESH_WRAP_MAGIC).not.toBe(0);
  });

  it('MESH_WRAP_FLAG_SEALED_1TO1 is bit 0', () => {
    expect(MESH_WRAP_FLAG_SEALED_1TO1).toBe(0x01);
  });
});
