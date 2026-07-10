/**
 * noise-xx.ts — Noise XX (25519/AES-GCM/SHA-256) + ML-KEM-768 hybrid.
 *
 * Pattern (Noise spec rev 34 §7.5):
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 *
 * Hybrid extension: initiator includes ML-KEM pubkey in msg-1 payload;
 * responder includes ML-KEM ciphertext in msg-2 payload. Final session
 * keys = split(noise_ck mixed with mlkem_ss via HKDF) — same construction
 * as Signal PQXDH / Apple PQ3.
 *
 * State machine: writeMessage / readMessage advance the message index.
 * isComplete() returns true after 3 messages. split() returns AEAD keys
 * + nonces for session.ts; sas() returns the 5-digit MITM-defence string.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';

// ─── Typed Noise error classes (B.2-typed-noise-errors) ──────────────────────

/** Thrown when the Noise state machine receives a message that is valid in
 * structure but out-of-order or replayed — i.e., not a real crypto failure.
 * Transport layer catches instanceof NoiseStateError and silently drops the
 * frame instead of counting it toward the retry budget. */
export class NoiseStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NoiseStateError';
    // Restore prototype chain in transpiled environments.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Specialisation for explicitly detected replay / duplicate frames.
 * Subclass of NoiseStateError so a single instanceof check covers both. */
export class NoiseReplayError extends NoiseStateError {
  constructor(message: string) {
    super(message);
    this.name = 'NoiseReplayError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

import { computeSas } from './sas.js';
import {
  generateMlkemKeypair, encapsulate, decapsulate,
} from './mlkem-wrap.js';
import type { DeviceIdentityProvider } from './identity.js';
import {
  AEAD_KEY_BYTES, AEAD_NONCE_BYTES,
  MLKEM_PUBLIC_KEY_BYTES, MLKEM_CIPHERTEXT_BYTES,
  MAX_HANDSHAKE_MSG_BYTES,
} from '../constants.generated.js';
import { toBufferSource } from './buffer.js';

const PROTOCOL_NAME = 'Noise_XX_25519_AESGCM_SHA256_OXPULSE_MESH_B2_V1';
const HKDF_INFO = new TextEncoder().encode('oxpulse-mesh-b2-v1');

// ─── AES-GCM via WebCrypto (browser + Node 22+) ──────────────────────────────

async function aesGcmEncrypt(
  key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toBufferSource(key), 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBufferSource(nonce), additionalData: toBufferSource(ad) },
    cryptoKey,
    toBufferSource(plaintext),
  );
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(
  key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toBufferSource(key), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBufferSource(nonce), additionalData: toBufferSource(ad) },
    cryptoKey,
    toBufferSource(ciphertext),
  );
  return new Uint8Array(pt);
}

// ─── HKDF helpers (Noise SymmetricState) ─────────────────────────────────────

function hkdfExpand(ck: Uint8Array, input: Uint8Array, n: 2 | 3): Uint8Array[] {
  // Noise §4.3 HKDF: PRK = HMAC(ck, input); then expand T1..Tn.
  const prk = hmac(sha256, ck, input);
  const out: Uint8Array[] = [];
  let prev = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    const data = new Uint8Array(prev.length + 1);
    data.set(prev, 0);
    data[prev.length] = i;
    prev = hmac(sha256, prk, data);
    out.push(prev);
  }
  return out;
}

// ─── Internal Noise state ────────────────────────────────────────────────────

type Role = 'initiator' | 'responder';
type MessageIdx = 0 | 1 | 2 | 3; // 0 = before msg-1; 3 = after msg-3

interface NoiseState {
  ck: Uint8Array;          // chaining key
  h: Uint8Array;           // handshake hash
  k: Uint8Array | null;    // current cipher key (null = no encryption yet)
  n: bigint;               // cipher nonce counter (per CipherState)
}

function mixHash(s: NoiseState, data: Uint8Array): void {
  const buf = new Uint8Array(s.h.length + data.length);
  buf.set(s.h, 0);
  buf.set(data, s.h.length);
  s.h = sha256(buf);
}

function mixKey(s: NoiseState, ikm: Uint8Array): void {
  const [newCk, newK] = hkdfExpand(s.ck, ikm, 2);
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  s.ck = newCk!;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  s.k = newK!.slice(0, AEAD_KEY_BYTES);
  s.n = 0n;
}

function nonceBytes(n: bigint): Uint8Array {
  const buf = new Uint8Array(AEAD_NONCE_BYTES); // 12 bytes
  // First 4 bytes zero (Noise convention), last 8 big-endian counter
  const view = new DataView(buf.buffer);
  view.setBigUint64(4, n, false);
  return buf;
}

async function encryptAndHash(s: NoiseState, plaintext: Uint8Array): Promise<Uint8Array> {
  if (!s.k) {
    // No key yet → pass through, but still mix into h.
    mixHash(s, plaintext);
    return plaintext;
  }
  const ct = await aesGcmEncrypt(s.k, nonceBytes(s.n), plaintext, s.h);
  s.n += 1n;
  mixHash(s, ct);
  return ct;
}

async function decryptAndHash(s: NoiseState, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (!s.k) {
    mixHash(s, ciphertext);
    return ciphertext;
  }
  const pt = await aesGcmDecrypt(s.k, nonceBytes(s.n), ciphertext, s.h);
  s.n += 1n;
  mixHash(s, ciphertext);
  return pt;
}

// ─── Public handshake API ────────────────────────────────────────────────────

export interface NoiseXxOptions {
  role: Role;
  identity: DeviceIdentityProvider;
  /** Test hook only; production always uses crypto.getRandomValues. */
  _rngOverride?: () => Uint8Array;
}

export interface NoiseSplit {
  sendKey: Uint8Array;
  recvKey: Uint8Array;
}

export class NoiseXxHandshake {
  private readonly role: Role;
  private readonly identity: DeviceIdentityProvider;
  private state: NoiseState;
  private msgIdx: MessageIdx = 0;

  // X25519 ephemerals
  private eSecret: Uint8Array | null = null;
  private ePublic: Uint8Array | null = null;
  private rePublic: Uint8Array | null = null; // remote ephemeral

  // ML-KEM (only initiator generates; only responder encapsulates)
  // R7 NOTE: For the responder, mlkemKeypair.publicKey stores the ML-KEM
  // *ciphertext* (not a real public key). This stash pattern avoids
  // adding a separate field at the cost of field-name accuracy. Future
  // refactor should use a union type:
  //   mlkemState: { phase: 'keypair'; kp: MlkemKeypair }
  //              | { phase: 'encapped'; ciphertext: Uint8Array }
  private mlkemKeypair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private mlkemSharedSecret: Uint8Array | null = null;

  // Remote static: peer long-term Ed25519 pubkey (learned in msg-2 or msg-3)
  private rsPublic: Uint8Array | null = null;
  // Remote static X25519 pubkey (B.2-noise-s-key-derivation; learned alongside rsPublic)
  private rsX25519Public: Uint8Array | null = null;

  constructor(opts: NoiseXxOptions) {
    this.role = opts.role;
    this.identity = opts.identity;
    const protoHash = sha256(new TextEncoder().encode(PROTOCOL_NAME));
    this.state = {
      ck: protoHash,
      h: protoHash,
      k: null,
      n: 0n,
    };
  }

  isComplete(): boolean { return this.msgIdx === 3; }

  /** Write the next handshake message; returns the bytes to send over the wire. */
  async writeMessage(payload: Uint8Array): Promise<Uint8Array> {
    if (payload.length > MAX_HANDSHAKE_MSG_BYTES) {
      throw new Error('handshake payload too large');
    }
    if (this.role === 'initiator' && this.msgIdx === 0) {
      return this.writeMsg1(payload);
    }
    if (this.role === 'responder' && this.msgIdx === 1) {
      return this.writeMsg2(payload);
    }
    if (this.role === 'initiator' && this.msgIdx === 2) {
      return this.writeMsg3(payload);
    }
    throw new NoiseStateError(`writeMessage: invalid state role=${this.role} idx=${this.msgIdx}`);
  }

  /** Read an incoming handshake message; returns the embedded payload bytes. */
  async readMessage(message: Uint8Array): Promise<Uint8Array> {
    if (message.length > MAX_HANDSHAKE_MSG_BYTES + 256) {
      throw new Error('handshake message too large');
    }
    if (this.role === 'responder' && this.msgIdx === 0) {
      return this.readMsg1(message);
    }
    if (this.role === 'initiator' && this.msgIdx === 1) {
      return this.readMsg2(message);
    }
    if (this.role === 'responder' && this.msgIdx === 2) {
      return this.readMsg3(message);
    }
    throw new NoiseStateError(`readMessage: invalid state role=${this.role} idx=${this.msgIdx}`);
  }

  /** After isComplete(): derive AEAD send/recv keys hybridised with ML-KEM. */
  split(): NoiseSplit {
    if (this.msgIdx !== 3) throw new Error('split: handshake incomplete');
    if (!this.mlkemSharedSecret) throw new Error('split: missing mlkem shared secret');

    // Hybrid: HKDF over (ck || mlkem_ss) with our app-specific info string.
    const ikm = new Uint8Array(this.state.ck.length + this.mlkemSharedSecret.length);
    ikm.set(this.state.ck, 0);
    ikm.set(this.mlkemSharedSecret, this.state.ck.length);

    const okm = hkdf(sha256, ikm, this.state.h, HKDF_INFO, AEAD_KEY_BYTES * 2);
    const k1 = okm.slice(0, AEAD_KEY_BYTES);
    const k2 = okm.slice(AEAD_KEY_BYTES, AEAD_KEY_BYTES * 2);

    return this.role === 'initiator'
      ? { sendKey: k1, recvKey: k2 }
      : { sendKey: k2, recvKey: k1 };
  }

  /** 5-digit SAS over the final handshake hash. */
  sas(): string {
    return computeSas(this.state.h);
  }

  // ─── msg-1: initiator → e (+ ML-KEM pubkey in payload) ─────────────────────

  private async writeMsg1(payload: Uint8Array): Promise<Uint8Array> {
    this.eSecret = x25519.utils.randomSecretKey();
    this.ePublic = x25519.getPublicKey(this.eSecret);
    mixHash(this.state, this.ePublic);

    // Hybrid: include ML-KEM pubkey in payload.
    this.mlkemKeypair = generateMlkemKeypair();
    const hybridPayload = new Uint8Array(this.mlkemKeypair.publicKey.length + payload.length);
    hybridPayload.set(this.mlkemKeypair.publicKey, 0);
    hybridPayload.set(payload, this.mlkemKeypair.publicKey.length);

    const ct = await encryptAndHash(this.state, hybridPayload);
    const out = new Uint8Array(this.ePublic.length + ct.length);
    out.set(this.ePublic, 0);
    out.set(ct, this.ePublic.length);
    this.msgIdx = 1;
    return out;
  }

  private async readMsg1(message: Uint8Array): Promise<Uint8Array> {
    if (message.length < 32 + MLKEM_PUBLIC_KEY_BYTES) {
      throw new Error('msg-1: too short');
    }
    this.rePublic = message.slice(0, 32);
    mixHash(this.state, this.rePublic);
    const payload = await decryptAndHash(this.state, message.slice(32));
    const peerMlkemPub = payload.slice(0, MLKEM_PUBLIC_KEY_BYTES);

    // Responder encapsulates immediately so msg-2 can carry the ciphertext.
    const { ciphertext, sharedSecret } = encapsulate(peerMlkemPub);
    // R7: store ciphertext in `publicKey` slot — see class-level comment for rationale.
    this.mlkemKeypair = { publicKey: ciphertext, secretKey: new Uint8Array(0) };
    this.mlkemSharedSecret = sharedSecret;

    this.msgIdx = 1;
    return payload.slice(MLKEM_PUBLIC_KEY_BYTES);
  }

  // ─── msg-2: responder → e, ee, s, es (+ ML-KEM ciphertext in payload) ─────

  private async writeMsg2(payload: Uint8Array): Promise<Uint8Array> {
    if (!this.rePublic) throw new Error('msg-2: missing remote ephemeral');
    if (!this.mlkemKeypair || !this.mlkemSharedSecret) {
      throw new Error('msg-2: missing mlkem state');
    }
    this.eSecret = x25519.utils.randomSecretKey();
    this.ePublic = x25519.getPublicKey(this.eSecret);
    mixHash(this.state, this.ePublic);

    // ee
    mixKey(this.state, x25519.getSharedSecret(this.eSecret, this.rePublic));

    // s — encrypt our Ed25519 pubkey (32 bytes) || our X25519 pubkey (32 bytes).
    // B.2-noise-s-key-derivation: X25519 pubkey is now included so the peer
    // can perform real es/se DH against our static key (not the ephemeral again).
    // SECURITY: s-payload is Ed25519_pubkey || X25519_pubkey with NO cryptographic
    // binding (Ed25519 signature over the concatenation would close the gap).
    // Today this is mitigated because:
    //   (a) attacker cannot decrypt msg-2 AEAD without responder's static X25519 priv
    //   (b) Ed25519 signatures elsewhere in the protocol re-bind identity
    // Future: B.2-ed25519-x25519-cross-binding FOLLOWUP — add explicit signature.
    const sPub = await this.identity.getPublicKey();           // 32-byte Ed25519
    const sX25519Pub = await this.identity.getX25519PublicKey(); // 32-byte X25519
    const sPayload = new Uint8Array(sPub.length + sX25519Pub.length); // 64 bytes
    sPayload.set(sPub, 0);
    sPayload.set(sX25519Pub, sPub.length);
    const sCt = await encryptAndHash(this.state, sPayload);

    // es — DH(s_responder_static_x25519, re_initiator_ephemeral).
    // B.2-noise-s-key-derivation: now uses real static DH via identity.dhX25519()
    // instead of the ephemeral-only approximation (X25519(eSecret, rePublic)).
    mixKey(this.state, await this.identity.dhX25519(this.rePublic));

    // Hybrid: include ML-KEM ciphertext (stored in publicKey slot at msg-1).
    const ct = this.mlkemKeypair.publicKey;
    const hybridPayload = new Uint8Array(ct.length + payload.length);
    hybridPayload.set(ct, 0);
    hybridPayload.set(payload, ct.length);

    const ctPayload = await encryptAndHash(this.state, hybridPayload);
    const out = new Uint8Array(this.ePublic.length + sCt.length + ctPayload.length);
    out.set(this.ePublic, 0);
    out.set(sCt, this.ePublic.length);
    out.set(ctPayload, this.ePublic.length + sCt.length);
    this.msgIdx = 2;
    return out;
  }

  private async readMsg2(message: Uint8Array): Promise<Uint8Array> {
    if (!this.eSecret) throw new Error('msg-2: missing local ephemeral');
    if (!this.mlkemKeypair) throw new Error('msg-2: missing mlkem keypair');

    this.rePublic = message.slice(0, 32);
    mixHash(this.state, this.rePublic);
    mixKey(this.state, x25519.getSharedSecret(this.eSecret, this.rePublic));

    // s: encrypted 64-byte payload (32 ed25519 || 32 x25519) + 16-byte GCM tag = 80 bytes.
    // B.2-noise-s-key-derivation: extended from 48→80 bytes to carry X25519 pubkey.
    const S_CT_BYTES = 64 + 16; // 80 = 64-byte plaintext + 16-byte AES-GCM tag
    const sCt = message.slice(32, 32 + S_CT_BYTES);
    const sPayload = await decryptAndHash(this.state, sCt);
    this.rsPublic = sPayload.slice(0, 32);          // Ed25519 pubkey
    this.rsX25519Public = sPayload.slice(32, 64);   // X25519 pubkey

    // es — DH(e_initiator_ephemeral, s_responder_static_x25519).
    // B.2-noise-s-key-derivation: uses real static DH against responder's X25519 key.
    // The ephemeral private key (eSecret) performs x25519 DH against rsX25519Public.
    // SECURITY: rsX25519Public is not validated against the low-order X25519 point
    // list (small-subgroup attack). @noble/curves x25519.getSharedSecret() already
    // throws on all-zero DH output (RFC 7748 §6.1), but older Firefox/WebCrypto
    // deriveBits does NOT reject low-order points — full validation deferred.
    // Future: B.2-x25519-small-subgroup-validation FOLLOWUP.
    mixKey(this.state, x25519.getSharedSecret(this.eSecret, this.rsX25519Public));

    // Hybrid payload
    const rest = message.slice(32 + S_CT_BYTES);
    const payload = await decryptAndHash(this.state, rest);
    const mlkemCt = payload.slice(0, MLKEM_CIPHERTEXT_BYTES);
    this.mlkemSharedSecret = decapsulate(this.mlkemKeypair.secretKey, mlkemCt);

    this.msgIdx = 2;
    return payload.slice(MLKEM_CIPHERTEXT_BYTES);
  }

  // ─── msg-3: initiator → s, se ──────────────────────────────────────────────

  private async writeMsg3(payload: Uint8Array): Promise<Uint8Array> {
    if (!this.eSecret || !this.rePublic) throw new Error('msg-3: missing ephemerals');

    // s — encrypt Ed25519 pubkey (32) || X25519 pubkey (32) = 64 bytes plaintext.
    // B.2-noise-s-key-derivation: symmetric with writeMsg2 — responder learns
    // initiator's X25519 static key here so it can compute the se DH.
    // SECURITY: s-payload is Ed25519_pubkey || X25519_pubkey with NO cryptographic
    // binding (Ed25519 signature over the concatenation would close the gap).
    // Today this is mitigated because:
    //   (a) attacker cannot decrypt msg-3 AEAD without initiator's X25519 priv
    //   (b) Ed25519 signatures elsewhere in the protocol re-bind identity
    // Future: B.2-ed25519-x25519-cross-binding FOLLOWUP — add explicit signature.
    const sPub = await this.identity.getPublicKey();
    const sX25519Pub = await this.identity.getX25519PublicKey();
    const sPayload = new Uint8Array(sPub.length + sX25519Pub.length);
    sPayload.set(sPub, 0);
    sPayload.set(sX25519Pub, sPub.length);
    const sCt = await encryptAndHash(this.state, sPayload);

    // se — DH(s_initiator_static_x25519, e_responder_ephemeral).
    // B.2-noise-s-key-derivation: uses real static DH via identity.dhX25519()
    // against the responder's ephemeral public key (rePublic).
    mixKey(this.state, await this.identity.dhX25519(this.rePublic));

    const ctPayload = await encryptAndHash(this.state, payload);
    const out = new Uint8Array(sCt.length + ctPayload.length);
    out.set(sCt, 0);
    out.set(ctPayload, sCt.length);
    this.msgIdx = 3;
    return out;
  }

  private async readMsg3(message: Uint8Array): Promise<Uint8Array> {
    if (!this.eSecret) throw new Error('msg-3: missing local ephemeral');

    // s: encrypted 64-byte payload (32 ed25519 || 32 x25519) + 16-byte GCM tag = 80 bytes.
    // B.2-noise-s-key-derivation: extended from 48→80 bytes, symmetric with readMsg2.
    const S_CT_BYTES = 64 + 16; // 80
    const sCt = message.slice(0, S_CT_BYTES);
    const sPayload = await decryptAndHash(this.state, sCt);
    this.rsPublic = sPayload.slice(0, 32);          // Ed25519 pubkey
    this.rsX25519Public = sPayload.slice(32, 64);   // X25519 pubkey

    // se — DH(e_responder_ephemeral, s_initiator_static_x25519).
    // B.2-noise-s-key-derivation: uses real static DH — responder's ephemeral
    // against initiator's static X25519 key learned from the s token above.
    // SECURITY: rsX25519Public is not validated against the low-order X25519 point
    // list (small-subgroup attack). @noble/curves x25519.getSharedSecret() already
    // throws on all-zero DH output (RFC 7748 §6.1), but older Firefox/WebCrypto
    // deriveBits does NOT reject low-order points — full validation deferred.
    // Future: B.2-x25519-small-subgroup-validation FOLLOWUP.
    mixKey(this.state, x25519.getSharedSecret(this.eSecret, this.rsX25519Public));

    const payload = await decryptAndHash(this.state, message.slice(S_CT_BYTES));
    this.msgIdx = 3;
    return payload;
  }

  /** Peer's long-term Ed25519 pubkey (available after msg-2 for initiator, msg-3 for responder). */
  peerStaticPublicKey(): Uint8Array | null { return this.rsPublic; }
}
