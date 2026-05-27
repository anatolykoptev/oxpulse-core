/**
 * wrap.ts — Phase 3 T1: composeMeshWrap / peelMeshWrap.
 *
 * Wraps a MessageEnvelope v1 (from @oxpulse/crypto-primitives) inside a
 * mesh-bundle-v1 frame (from @oxpulse/wire-codec) so that sealed 1:1
 * messages can be routed via routeOutgoing (online / BLE / outbox).
 *
 * Wire-format layering:
 *
 *   mesh-bundle-v1 (magic 0xC9, 61-byte outer header, 64-byte outer sig)
 *     └─ body = mesh-wrap-v1 body:
 *          offset 0  1  MESH_WRAP_MAGIC (0xAE)
 *          offset 1  1  flags  (bit 0 = IS_SEALED_1TO1 — see below)
 *          offset 2  N  envelopeBytes (raw MessageEnvelope v1)
 *
 * ADR — why flags live in the body, not the outer header:
 *   The mesh-bundle-v1 outer header has no flags field (Phase B spec v1 frozen).
 *   Extending the outer wire format requires operator design review.  This wrap
 *   body header is entirely owned by wrap.ts and is invisible to the existing
 *   mesh-bundle codec (body is opaque bytes to it).  The IS_SEALED_1TO1 bit is
 *   grep-auditable via MESH_WRAP_FLAG_SEALED_1TO1 — no permissive middleware.
 *   Followup ADR: outer mesh-bundle flags byte addition (1 reserved byte after
 *   channelIdHash at offset 59, shifting bodyLen to offset 60–61), gated by
 *   operator sign-off.
 *
 * channelIdHash derivation:
 *   SHA-256(recipientX25519Pub)[0..4] — maps 1:1 sealed routing into the
 *   mesh-bundle channel field per operator decision §2.
 *
 * Signature:
 *   The outer Ed25519 signature covers magic..body (mesh-bundle signed range)
 *   per the existing bundle-composer convention.  The inner MessageEnvelope
 *   carries its own senderSig — the wrap signature is a separate proof of
 *   transport-layer authorship.
 *
 * @see docs/superpowers/plans/2026-05-17-phase3-mesh-bridge.md §T1
 * @see packages/wire-codec/src/mesh-bundle.ts  (outer frame)
 * @see packages/crypto-primitives/src/envelope.ts  (MessageEnvelope v1)
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  encodeMeshBundle,
  decodeMeshBundle,
  meshBundleSignedRange,
} from '@oxpulse/wire-codec';

/** Ed25519 signature length in bytes. Matches MESH_BUNDLE_SIG_LEN in mesh-bundle.ts. */
const SIG_LEN = 64;
import { ed25519 } from '@noble/curves/ed25519.js';

// ---------------------------------------------------------------------------
// Mesh-wrap body constants (body sub-format owned by this module)
// ---------------------------------------------------------------------------

/**
 * Magic byte at body[0] identifying a mesh-wrap-v1 body.
 * Distinct from MESH_BUNDLE_MAGIC_V1 (0xC9) and MessageEnvelope magic (0x4F).
 */
export const MESH_WRAP_MAGIC = 0xae;

/**
 * Flags byte at body[1].
 * Bit 0: IS_SEALED_1TO1 — when set, server relay MUST bypass channel-registration
 * check (Task T2). This bit is the ONLY place this semantic is encoded in the
 * wire format; all code paths must check this constant, never a raw literal.
 */
export const MESH_WRAP_FLAG_SEALED_1TO1 = 0x01;

/** Size of the mesh-wrap body header (magic + flags). */
const MESH_WRAP_BODY_HEADER_LEN = 2; // body[0]=magic, body[1]=flags

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface ComposeMeshWrapArgs {
  /** Raw MessageEnvelope v1 bytes (>= 98 bytes with OXPE magic). */
  envelopeBytes: Uint8Array;
  /**
   * Recipient X25519 public key (32 bytes).
   * channelIdHash = SHA-256(recipientX25519Pub)[0..4].
   */
  recipientX25519Pub: Uint8Array;
  /** Sender Ed25519 public key (32 bytes) — written into outer bundle header. */
  senderEd25519Pub: Uint8Array;
  /**
   * Async Ed25519 signer: signs the mesh-bundle signed range
   * (outer header + body, excluding the trailing sig slot).
   * Returns 64-byte raw Ed25519 signature.
   */
  signEd25519: (msg: Uint8Array) => Promise<Uint8Array>;
  /**
   * Message ID (16 bytes) — MUST match the msgId inside envelopeBytes.
   * Caller is responsible for consistency; wrap.ts does not parse the envelope.
   */
  msgId: Uint8Array;
  /**
   * Seconds since ROOM_EPOCH (2026-01-01 UTC) as unsigned u32.
   * Units: SECONDS (not milliseconds). See PR #1037.
   */
  tsMsOffset: number;
  /**
   * When true, the IS_SEALED_1TO1 bit (bit 0) is set in the wrap flags byte.
   * Server relay (Task T2) must bypass channel-registration check when this is set.
   * Grep-auditable via MESH_WRAP_FLAG_SEALED_1TO1.
   */
  isSealed1to1: boolean;
}

export interface PeeledMeshWrap {
  /** Raw MessageEnvelope v1 bytes extracted from the bundle body. */
  envelopeBytes: Uint8Array;
  /** Ed25519 sender public key from the outer bundle header (32 bytes). */
  senderEd25519Pub: Uint8Array;
  /** Message ID from the outer bundle header (16 bytes). */
  msgId: Uint8Array;
  /** First 4 bytes of SHA-256(recipientX25519Pub) from outer header (4 bytes). */
  channelIdHash: Uint8Array;
  /**
   * True when MESH_WRAP_FLAG_SEALED_1TO1 is set in body[1].
   * Used by server relay (Task T2) to bypass channel-registration check.
   */
  isSealed1to1: boolean;
}

// ---------------------------------------------------------------------------
// composeMeshWrap
// ---------------------------------------------------------------------------

/**
 * Wrap a MessageEnvelope v1 in a signed mesh-bundle-v1 frame.
 *
 * Steps:
 * 1. Derive channelIdHash = SHA-256(recipientX25519Pub)[0..4].
 * 2. Build mesh-wrap body: [MESH_WRAP_MAGIC, flags, ...envelopeBytes].
 * 3. Produce unsigned bundle (zero sig) and extract the signed range.
 * 4. Sign the signed range via the caller-supplied signEd25519.
 * 5. Re-encode the bundle with the real signature.
 *
 * @throws {Error} if recipientX25519Pub is not 32 bytes
 * @throws {Error} if senderEd25519Pub is not 32 bytes
 * @throws {Error} if msgId is not 16 bytes
 * @throws {Error} if signEd25519 returns a value that is not 64 bytes
 * @throws {WireCodecError} if body exceeds 1500 bytes (MESH_BUNDLE_MAX_BODY)
 */
export async function composeMeshWrap(args: ComposeMeshWrapArgs): Promise<Uint8Array> {
  if (args.recipientX25519Pub.length !== 32) {
    throw new Error(
      `composeMeshWrap: recipientX25519Pub must be 32 bytes, got ${args.recipientX25519Pub.length}`,
    );
  }
  if (args.senderEd25519Pub.length !== 32) {
    throw new Error(
      `composeMeshWrap: senderEd25519Pub must be 32 bytes, got ${args.senderEd25519Pub.length}`,
    );
  }
  if (args.msgId.length !== 16) {
    throw new Error(
      `composeMeshWrap: msgId must be 16 bytes, got ${args.msgId.length}`,
    );
  }

  // 1. channelIdHash = SHA-256(recipientX25519Pub)[0..4]
  const channelIdHash = sha256(args.recipientX25519Pub).slice(0, 4);

  // 2. Build mesh-wrap body: magic(1) + flags(1) + envelopeBytes(N)
  const flags = args.isSealed1to1 ? MESH_WRAP_FLAG_SEALED_1TO1 : 0x00;
  const body = new Uint8Array(MESH_WRAP_BODY_HEADER_LEN + args.envelopeBytes.length);
  body[0] = MESH_WRAP_MAGIC;
  body[1] = flags;
  body.set(args.envelopeBytes, MESH_WRAP_BODY_HEADER_LEN);

  // 3. Produce unsigned bundle (zero sig) to derive the signed range
  const zeroSig = new Uint8Array(SIG_LEN);
  const unsigned = encodeMeshBundle({
    senderPubkey: args.senderEd25519Pub,
    msgId: args.msgId,
    tsSecOffset: args.tsMsOffset,
    ttlHops: 3,
    channelIdHash,
    body,
    signature: zeroSig,
  });

  // 4. Sign the bytes[0 .. 61+bodyLen) range
  const signedRange = meshBundleSignedRange(unsigned);
  const signature = await args.signEd25519(signedRange);
  if (signature.length !== SIG_LEN) {
    throw new Error(
      `composeMeshWrap: signEd25519 must return 64 bytes, got ${signature.length}`,
    );
  }

  // 5. Re-encode with real signature
  return encodeMeshBundle({
    senderPubkey: args.senderEd25519Pub,
    msgId: args.msgId,
    tsSecOffset: args.tsMsOffset,
    ttlHops: 3,
    channelIdHash,
    body,
    signature,
  });
}

// ---------------------------------------------------------------------------
// peelMeshWrap
// ---------------------------------------------------------------------------

/**
 * Peel a signed mesh-bundle-v1 frame and extract the mesh-wrap-v1 contents.
 *
 * NOTE: This function validates structure only. It does NOT verify the outer
 * Ed25519 signature or the inner MessageEnvelope senderSig. Signature
 * verification is the caller's responsibility (verify outer sig with
 * meshBundleSignedRange + ed25519.verify before trusting the envelope).
 *
 * @throws {WireCodecError} MESH_BUNDLE_TRUNCATED if bytes are too short
 * @throws {WireCodecError} UNKNOWN_MAGIC if first byte is not 0xC9
 * @throws {WireCodecError} MESH_BUNDLE_VERSION_UNSUPPORTED if version != 0x01
 * @throws {Error} if body is too short to contain the mesh-wrap header (< 2 bytes)
 * @throws {Error} if body[0] is not MESH_WRAP_MAGIC
 */
export function peelMeshWrap(bundleBytes: Uint8Array): PeeledMeshWrap {
  // decodeMeshBundle validates magic, version, body_len, total length
  const decoded = decodeMeshBundle(bundleBytes);

  const body = decoded.body;
  if (body.length < MESH_WRAP_BODY_HEADER_LEN) {
    throw new Error(
      `peelMeshWrap: body too short to contain mesh-wrap header ` +
        `(${body.length} < ${MESH_WRAP_BODY_HEADER_LEN})`,
    );
  }
  // body.length >= MESH_WRAP_BODY_HEADER_LEN >= 2 checked above — explicit locals
  // avoid `!` non-null assertions that suppress future length-check removals.
  const magic = body[0] as number;
  if (magic !== MESH_WRAP_MAGIC) {
    throw new Error(
      `peelMeshWrap: body[0] is not MESH_WRAP_MAGIC ` +
        `(got 0x${magic.toString(16).padStart(2, '0')}, expected 0x${MESH_WRAP_MAGIC.toString(16)})`,
    );
  }

  const flags = body[1] as number;
  const isSealed1to1 = (flags & MESH_WRAP_FLAG_SEALED_1TO1) !== 0;
  const envelopeBytes = body.slice(MESH_WRAP_BODY_HEADER_LEN);

  return {
    envelopeBytes,
    senderEd25519Pub: decoded.senderPubkey,
    msgId: decoded.msgId,
    channelIdHash: decoded.channelIdHash,
    isSealed1to1,
  };
}
