/**
 * mlkem768-kat.test.ts — ML-KEM-768 FIPS 203 Known Answer Tests (B.2-kat-vectors)
 *
 * Vectors produced by @noble/post-quantum ml_kem768 with fixed seeds.
 * The @noble/post-quantum library implements FIPS 203 ML-KEM-768 deterministically
 * when both keygen(seed) and encapsulate(pk, msg) are given fixed inputs.
 *
 * Source: @noble/post-quantum v0.6.x keygen/encapsulate deterministic API.
 * Expected values generated 2026-05-17 via:
 *   ml_kem768.keygen(seed)            → { publicKey, secretKey }
 *   ml_kem768.encapsulate(pk, msg)    → { cipherText, sharedSecret }
 *   ml_kem768.decapsulate(ct, sk)     → sharedSecret
 *
 * Purpose: regression guard against silent algorithmic drift when
 * @noble/post-quantum is upgraded (e.g. 0.5→0.6→future). Any change in
 * these byte strings signals a breaking algorithm change that could silently
 * corrupt all in-flight mesh sessions.
 *
 * Key lengths (FIPS 203 §2.4, ML-KEM-768):
 *   Public key:    1184 bytes
 *   Secret key:    2400 bytes
 *   Ciphertext:    1088 bytes
 *   Shared secret:   32 bytes
 *
 * Note: we pin the first 32 bytes of pk/ct rather than the full blob to keep
 * the file readable. The shared secret (32 bytes) is pinned in full as it is
 * the security-critical output.
 */

import { describe, it, expect } from 'vitest';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

function hex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('odd hex length');
  return new Uint8Array(s.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
}

function toHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

// ─── Vector 1: seed = 0x00 * 64, encap msg = 0x00 * 32 ───────────────────────
// Generated with: @noble/post-quantum v0.6.x, Node 22, 2026-05-17
const VEC1 = {
  seed:     '00'.repeat(64),
  msg:      '00'.repeat(32),
  // First 32 bytes of public key
  pkPrefix: '254a797885c63b1440aa389c65340ef33520cc039aa8d749ae7095ba8485a244',
  // Full shared secret (the security-critical 32-byte output)
  ss:       'b4d29cd55bab43e16554b74b9098cdfce583996c968bcd2cfd1ad9455e351fbf',
  // First 32 bytes of ciphertext
  ctPrefix: '1708d1877e99d8910d48df9625973d7954e187b29405a4ccad6d287becda3121',
};

// ─── Vector 2: seed = 0xAA55 repeating, encap msg = 0xFF * 32 ────────────────
// Generated with: @noble/post-quantum v0.6.x, Node 22, 2026-05-17
const VEC2 = {
  seed:     'aa55'.repeat(32),
  msg:      'ff'.repeat(32),
  pkPrefix: '634cb21b6c6c21cb86e093098ed77c76728dea1b8e00e58776623e0819463c84',
  ss:       '57fdf4f85090e42409662016c9decd64707d19a13ad435ce57a4aceec9710e44',
  ctPrefix: '496ea9ea39dfafe93cfeb1cacd3b8e4fce2dfedfaf49068dafc3270be85d07cc',
};

// ─── Vector 3: seed = sequential 0x01..0x40, encap msg = 0xAB * 32 ───────────
// Generated with: @noble/post-quantum v0.6.x, Node 22, 2026-05-17
const VEC3 = {
  // seed[i] = i+1 for i in 0..63
  seed: Array.from({ length: 64 }, (_, i) => (i + 1).toString(16).padStart(2, '0')).join(''),
  msg:      'ab'.repeat(32),
  pkPrefix: '659717deb2b867fc2397dc212cf0ab35e57477f79502573f6cf6b41b58904abc',
  ss:       '7d8f89afda3d1ee9df06dbfceec9611ee0bfce941620ec0e202d6e6ad52dd1e4',
  ctPrefix: '59206fb773d8715a5b54efa7e0dd38200cdef40c9f52f26843fcc2b4771a22bd',
};

describe('ML-KEM-768 FIPS 203 KAT vectors (@noble/post-quantum)', () => {
  // ─── Keygen KAT ───────────────────────────────────────────────────────────

  it('VEC1: keygen(seed=0x00*64) → deterministic public key prefix', () => {
    const { publicKey } = ml_kem768.keygen(hex(VEC1.seed));
    expect(publicKey.length).toBe(1184);
    expect(toHex(publicKey.slice(0, 32))).toBe(VEC1.pkPrefix);
  });

  it('VEC2: keygen(seed=0xAA55*32) → deterministic public key prefix', () => {
    const { publicKey } = ml_kem768.keygen(hex(VEC2.seed));
    expect(publicKey.length).toBe(1184);
    expect(toHex(publicKey.slice(0, 32))).toBe(VEC2.pkPrefix);
  });

  it('VEC3: keygen(seed=0x01..0x40) → deterministic public key prefix', () => {
    const { publicKey } = ml_kem768.keygen(hex(VEC3.seed));
    expect(publicKey.length).toBe(1184);
    expect(toHex(publicKey.slice(0, 32))).toBe(VEC3.pkPrefix);
  });

  // ─── Encap KAT ────────────────────────────────────────────────────────────

  it('VEC1: encapsulate(pk, msg=0x00*32) → deterministic sharedSecret + ct prefix', () => {
    const { publicKey } = ml_kem768.keygen(hex(VEC1.seed));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, hex(VEC1.msg));
    expect(cipherText.length).toBe(1088);
    expect(sharedSecret.length).toBe(32);
    expect(toHex(sharedSecret)).toBe(VEC1.ss);
    expect(toHex(cipherText.slice(0, 32))).toBe(VEC1.ctPrefix);
  });

  it('VEC2: encapsulate(pk, msg=0xFF*32) → deterministic sharedSecret + ct prefix', () => {
    const { publicKey } = ml_kem768.keygen(hex(VEC2.seed));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, hex(VEC2.msg));
    expect(cipherText.length).toBe(1088);
    expect(sharedSecret.length).toBe(32);
    expect(toHex(sharedSecret)).toBe(VEC2.ss);
    expect(toHex(cipherText.slice(0, 32))).toBe(VEC2.ctPrefix);
  });

  it('VEC3: encapsulate(pk, msg=0xAB*32) → deterministic sharedSecret + ct prefix', () => {
    const { publicKey } = ml_kem768.keygen(hex(VEC3.seed));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, hex(VEC3.msg));
    expect(cipherText.length).toBe(1088);
    expect(sharedSecret.length).toBe(32);
    expect(toHex(sharedSecret)).toBe(VEC3.ss);
    expect(toHex(cipherText.slice(0, 32))).toBe(VEC3.ctPrefix);
  });

  // ─── Decap KAT ────────────────────────────────────────────────────────────

  it('VEC1: decapsulate(ct, sk) → recovers encap sharedSecret', () => {
    const { publicKey, secretKey } = ml_kem768.keygen(hex(VEC1.seed));
    const { cipherText, sharedSecret: encapSs } = ml_kem768.encapsulate(publicKey, hex(VEC1.msg));
    const decapSs = ml_kem768.decapsulate(cipherText, secretKey);
    expect(toHex(decapSs)).toBe(toHex(encapSs));
    expect(toHex(decapSs)).toBe(VEC1.ss); // must match the pinned KAT value
  });

  it('VEC2: decapsulate(ct, sk) → recovers encap sharedSecret', () => {
    const { publicKey, secretKey } = ml_kem768.keygen(hex(VEC2.seed));
    const { cipherText, sharedSecret: encapSs } = ml_kem768.encapsulate(publicKey, hex(VEC2.msg));
    const decapSs = ml_kem768.decapsulate(cipherText, secretKey);
    expect(toHex(decapSs)).toBe(toHex(encapSs));
    expect(toHex(decapSs)).toBe(VEC2.ss);
  });

  it('VEC3: decapsulate(ct, sk) → recovers encap sharedSecret', () => {
    const { publicKey, secretKey } = ml_kem768.keygen(hex(VEC3.seed));
    const { cipherText, sharedSecret: encapSs } = ml_kem768.encapsulate(publicKey, hex(VEC3.msg));
    const decapSs = ml_kem768.decapsulate(cipherText, secretKey);
    expect(toHex(decapSs)).toBe(toHex(encapSs));
    expect(toHex(decapSs)).toBe(VEC3.ss);
  });

  // ─── Implicit rejection (FIPS 203 §7.3) ─────────────────────────────────

  it('implicit rejection: wrong sk → different ss, not an exception (FIPS 203 §7.3)', () => {
    // ML-KEM-768 FIPS 203 §7.3: decapsulate with a wrong key returns a
    // pseudorandom value ("implicit rejection"), NOT an exception. This
    // prevents timing-based oracle attacks. Any drift in this property is
    // a security regression.
    const { publicKey: pk1 } = ml_kem768.keygen(hex(VEC1.seed));
    const { secretKey: sk2 } = ml_kem768.keygen(hex(VEC2.seed));
    const { cipherText } = ml_kem768.encapsulate(pk1, hex(VEC1.msg));
    const wrongSs = ml_kem768.decapsulate(cipherText, sk2);
    // Must not match the honest decap result
    expect(toHex(wrongSs)).not.toBe(VEC1.ss);
    // Must still return 32 bytes (implicit rejection = random-looking, not empty)
    expect(wrongSs.length).toBe(32);
  });
});
