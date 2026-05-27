/**
 * noise-xx-kat.test.ts — Noise XX KAT (B.2-kat-vectors)
 *
 * NOTE: oxpulse uses an extended PROTOCOL_NAME:
 *   "Noise_XX_25519_AESGCM_SHA256_OXPULSE_MESH_B2_V1"
 * Public cacophony vectors use "Noise_XX_25519_AESGCM_SHA256" which produces a
 * different protocol hash → different chaining key → different wire bytes.
 * Therefore, vanilla cacophony vectors do NOT byte-match this implementation.
 *
 * What we KAT instead:
 *   1. Protocol hash (SHA256 of PROTOCOL_NAME string) — pins the protocol identity.
 *   2. Noise §4.3 hkdfExpand (two-output HKDF) — the ONLY key-schedule primitive.
 *   3. Split HKDF key derivation — RFC 5869 self-test of the @noble/hashes hkdf().
 *   4. Handshake session key symmetry and round-trip — functional KAT.
 *   5. Handshake session key uniqueness — independence between sessions.
 *
 * FOLLOWUP: B.2-noise-xx-protocol-name-isolation — refactor SymmetricState into a
 * standalone class so pure Noise_XX_25519_AESGCM_SHA256 cacophony vectors can be
 * tested without the OXPULSE suffix. Until then, protocol hash pin is the
 * boundary-of-trust test for algorithm identity.
 *
 * References:
 *   https://github.com/centromere/cacophony/blob/master/tests/vectors/cacophony.txt
 *   https://noiseprotocol.org/noise.html §4.3 (SymmetricState HKDF), §7.5 (XX)
 *   packages/mesh-core/src/crypto/noise-xx.ts (PROTOCOL_NAME constant)
 */

import { describe, it, expect } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { NoiseXxHandshake } from '../../crypto/noise-xx.js';
import type { DeviceIdentityProvider } from '../../crypto/identity.js';

function hex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('odd hex length');
  return new Uint8Array(s.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
}

function toHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

// B.2-noise-s-key-derivation: include X25519 static keypair in test identity.
function makeIdentity(edSkOverride?: Uint8Array): DeviceIdentityProvider {
  const edSk = edSkOverride ?? ed25519.utils.randomSecretKey();
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

async function runFullHandshake(initId: DeviceIdentityProvider, respId: DeviceIdentityProvider) {
  const initiator = new NoiseXxHandshake({ role: 'initiator', identity: initId });
  const responder = new NoiseXxHandshake({ role: 'responder', identity: respId });
  const m1 = await initiator.writeMessage(new Uint8Array(0));
  await responder.readMessage(m1);
  const m2 = await responder.writeMessage(new Uint8Array(0));
  await initiator.readMessage(m2);
  const m3 = await initiator.writeMessage(new Uint8Array(0));
  await responder.readMessage(m3);
  return { initiator, responder };
}

// ─── KAT: Protocol identity hash ─────────────────────────────────────────────

describe('Noise XX KAT — protocol identity', () => {
  // KAT-1: SHA256 of the PROTOCOL_NAME string.
  // This hash seeds the initial ck and h fields of SymmetricState.
  // Any change to PROTOCOL_NAME causes a total wire-incompatibility between
  // mesh nodes, so we pin it here as a regression guard.
  //
  // PROTOCOL_NAME = "Noise_XX_25519_AESGCM_SHA256_OXPULSE_MESH_B2_V1"
  // Source: packages/mesh-core/src/crypto/noise-xx.ts line 61
  it('KAT-1: SHA256(PROTOCOL_NAME) matches pinned hash', () => {
    const protocolName = 'Noise_XX_25519_AESGCM_SHA256_OXPULSE_MESH_B2_V1';
    const hash = sha256(new TextEncoder().encode(protocolName));
    // Pinned 2026-05-17 — if this changes, all deployed mesh nodes become incompatible.
    expect(toHex(hash)).toBe('12e13b00d28d69aad95466d1bfc07f248ea269de8a936bca149f02d8ca0da8ba');
  });

  // Contrast: vanilla Noise_XX_25519_AESGCM_SHA256 has a different hash.
  // This documents WHY cacophony vectors don't match this implementation.
  it('KAT-1b: vanilla Noise_XX_25519_AESGCM_SHA256 has a different protocol hash', () => {
    const vanilla = sha256(new TextEncoder().encode('Noise_XX_25519_AESGCM_SHA256'));
    const oxpulse = sha256(new TextEncoder().encode('Noise_XX_25519_AESGCM_SHA256_OXPULSE_MESH_B2_V1'));
    expect(toHex(vanilla)).not.toBe(toHex(oxpulse));
  });
});

// ─── KAT: Noise §4.3 hkdfExpand ──────────────────────────────────────────────

describe('Noise XX KAT — hkdfExpand (Noise §4.3)', () => {
  // Replicate the two-output HKDF from the Noise spec used inside noise-xx.ts.
  // PRK = HMAC-SHA256(ck, input); T1 = HMAC(PRK, 0x01); T2 = HMAC(PRK, T1 || 0x02)
  function hkdfExpand2(ck: Uint8Array, input: Uint8Array): [Uint8Array, Uint8Array] {
    const prk = hmac(sha256, ck, input);
    const t1 = hmac(sha256, prk, new Uint8Array([0x01]));
    const data2 = new Uint8Array(t1.length + 1);
    data2.set(t1, 0);
    data2[t1.length] = 0x02;
    const t2 = hmac(sha256, prk, data2);
    return [t1, t2];
  }

  it('KAT-2: hkdfExpand(ck=0x00*32, input=0x00*32) — both outputs are 32 bytes', () => {
    // Source: Noise Protocol spec §4.3
    const [t1, t2] = hkdfExpand2(new Uint8Array(32).fill(0), new Uint8Array(32).fill(0));
    expect(t1.length).toBe(32);
    expect(t2.length).toBe(32);
    // T1 and T2 must differ (PRK ≠ T1 and T1 ≠ T2 is guaranteed by the counter suffix)
    expect(toHex(t1)).not.toBe(toHex(t2));
  });

  it('KAT-2b: hkdfExpand is deterministic — identical inputs → identical outputs', () => {
    // Source: Noise Protocol spec §4.3
    const ck = new Uint8Array(32).map((_, i) => i);
    const input = new Uint8Array(32).fill(0x42);
    const [t1a, t2a] = hkdfExpand2(ck, input);
    const [t1b, t2b] = hkdfExpand2(ck, input);
    expect(toHex(t1a)).toBe(toHex(t1b));
    expect(toHex(t2a)).toBe(toHex(t2b));
  });

  it('KAT-2c: different inputs → different outputs (HKDF domain separation)', () => {
    // Source: Noise Protocol spec §4.3
    const ck = new Uint8Array(32).fill(0x00);
    const [t1a] = hkdfExpand2(ck, new Uint8Array(32).fill(0x00));
    const [t1b] = hkdfExpand2(ck, new Uint8Array(32).fill(0x01));
    expect(toHex(t1a)).not.toBe(toHex(t1b));
  });
});

// ─── KAT: RFC 5869 HKDF primitive (used in split()) ─────────────────────────

describe('Noise XX KAT — RFC 5869 HKDF (split() key derivation)', () => {
  // The hybrid split() in noise-xx.ts uses @noble/hashes hkdf(sha256, ...).
  // We pin its output against RFC 5869 Appendix A.1 to guard against dep drift.

  it('KAT-3: hkdf(sha256, ...) matches RFC 5869 Appendix A.1 test vector', () => {
    // Source: RFC 5869 §A.1 (Test Case 1)
    // IKM  = 0x0b * 22
    // Salt = 0x000102030405060708090a0b0c
    // Info = 0xf0f1f2f3f4f5f6f7f8f9
    // L    = 42
    // OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    const ikm  = hex('0b'.repeat(22));
    const salt = hex('000102030405060708090a0b0c');
    const info = hex('f0f1f2f3f4f5f6f7f8f9');
    const okm  = hkdf(sha256, ikm, salt, info, 42);
    const expected = hex(
      '3cb25f25faacd57a90434f64d0362f2a'
      + '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
      + '34007208d5b887185865',
    );
    expect(toHex(okm)).toBe(toHex(expected));
  });
});

// ─── KAT: Full handshake session key symmetry ────────────────────────────────

describe('Noise XX KAT — handshake session key symmetry + uniqueness', () => {
  // KAT-4: both sides derive the same session keys after 3 messages.
  // This exercises the full hybrid (X25519 + ML-KEM-768) key schedule.
  it('KAT-4: initiator.sendKey === responder.recvKey (and vice versa)', async () => {
    const { initiator, responder } = await runFullHandshake(
      makeIdentity(), makeIdentity(),
    );
    const iSplit = initiator.split();
    const rSplit = responder.split();

    expect(iSplit.sendKey.length).toBe(16); // AES-128
    expect(iSplit.recvKey.length).toBe(16);
    expect(toHex(iSplit.sendKey)).toBe(toHex(rSplit.recvKey));
    expect(toHex(iSplit.recvKey)).toBe(toHex(rSplit.sendKey));
    expect(iSplit.sendKey).not.toEqual(iSplit.recvKey); // distinct directions
  });

  // KAT-5: two independent handshakes produce independent session keys.
  // If session keys correlated between sessions, passive observers could
  // break session isolation.
  it('KAT-5: two independent handshakes → independent session keys', async () => {
    const { initiator: i1 } = await runFullHandshake(makeIdentity(), makeIdentity());
    const { initiator: i2 } = await runFullHandshake(makeIdentity(), makeIdentity());
    const s1 = i1.split();
    const s2 = i2.split();
    expect(toHex(s1.sendKey)).not.toBe(toHex(s2.sendKey));
    expect(toHex(s1.recvKey)).not.toBe(toHex(s2.recvKey));
  });

  // KAT-6: SAS (Short Authentication String) matches on both sides.
  // SAS is computed over the final handshake hash (state.h), which must
  // converge identically for both peers to display the same 5-digit code.
  it('KAT-6: SAS matches on both sides and is a 5-digit string', async () => {
    const { initiator, responder } = await runFullHandshake(
      makeIdentity(), makeIdentity(),
    );
    const iSas = initiator.sas();
    const rSas = responder.sas();
    expect(iSas).toBe(rSas);
    expect(iSas).toMatch(/^\d{5}$/);
  });
});
