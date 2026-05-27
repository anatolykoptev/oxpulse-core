/**
 * bundle-composer.ts — B-4 Phase.
 *
 * Builds and signs a mesh-bundle-v1 frame ready for transmission.
 * Signs with Ed25519 via @noble/curves.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { encodeMeshBundle, meshBundleSignedRange, ROOM_EPOCH } from '@oxpulse/wire-codec';

export interface ComposeBundleArgs {
  channelId: Uint8Array;       // 4 B channel-id hash
  body: Uint8Array;            // <= 1500 B payload
  /**
   * Ed25519 private key — 32 bytes raw.
   *
   * SECURITY CONTRACT (caller responsibility):
   * - Hold this key in volatile memory ONLY. Never store in localStorage,
   *   sessionStorage, IndexedDB, or any persistent store.
   * - For production: derive ephemeral keys per channel-day via HKDF or similar.
   * - senderPubkey MUST be the public key that corresponds to senderKey.
   *   The composer does NOT validate this correspondence; mismatch = invalid sig.
   *
   * RECOMMENDED SOURCE: the long-term device identity exported from
   * `@oxpulse/identity`. Call `getOrCreateDeviceIdentity()` to obtain the
   * (non-extractable) keypair, then `exportRawDeviceSecret()` to read the
   * raw 32-byte Ed25519 secret and base64url-encoded public key. The
   * identity package handles AES-KW-wrapped IndexedDB persistence and
   * non-extractable `CryptoKey` storage; mesh-core itself stays
   * identity-agnostic by design (see docs/architecture/mesh-workspace-split-adr.md).
   */
  senderKey: Uint8Array;       // Ed25519 privkey (32 B)
  senderPubkey: Uint8Array;    // Ed25519 pubkey (32 B)
  msgId?: Uint8Array;          // 16 B; auto-generated if absent
}

export interface ComposeBundleResult {
  bundle: Uint8Array;
  msgId: Uint8Array;           // 16 B
  channelId: Uint8Array;       // 4 B — echoed from input
}

/**
 * Wire-format epoch — 2026-01-01 00:00:00 UTC in Unix milliseconds.
 * Single source of truth lives in @oxpulse/wire-codec (envelope-v2.ts → ROOM_EPOCH).
 * Re-exported here for backwards compatibility with any callers that import from
 * bundle-composer directly.
 *
 * Must match server-side ROOM_EPOCH_MS in sdk_mesh_relay.rs.
 * This constant is inviolable per architecture/wire-optimization.md §4.
 */
export const MESH_BUNDLE_TS_EPOCH_MS = ROOM_EPOCH;

/** Generate a UUIDv4 as 16 raw bytes using Web Crypto API (requires Node >= 18). */
function randomUuid16(): Uint8Array {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  // Set UUIDv4 version (4) and variant bits (RFC 4122)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  return bytes;
}

/**
 * Seconds since MESH_BUNDLE_TS_EPOCH_MS, coerced to unsigned uint32.
 * Uses Math.floor for sub-second truncation, then `>>> 0` for unsigned semantics.
 * 1-second resolution is sufficient: freshness window is ±2h/±5min.
 * u32::MAX seconds = ~136 years headroom from ROOM_EPOCH (2026-01-01).
 *
 * If now < MESH_BUNDLE_TS_EPOCH_MS (clock skew / test fixture), Math.floor
 * gives a negative result; `>>> 0` wraps to a large u32 (unsigned semantics).
 * The server-side freshness check will reject such bundles as too-far-future.
 */
function tsSecOffset(): number {
  return (Math.floor((Date.now() - MESH_BUNDLE_TS_EPOCH_MS) / 1000)) >>> 0;
}

/**
 * Build and sign a mesh-bundle-v1.
 * Signs via Ed25519 using @noble/curves.
 *
 * @throws {Error} if senderKey is not exactly 32 bytes
 * @throws {Error} if senderPubkey is not exactly 32 bytes
 */
export async function composeBundle(args: ComposeBundleArgs): Promise<ComposeBundleResult> {
  if (args.senderKey.length !== 32) {
    throw new Error(
      `composeBundle: senderKey must be 32 bytes (Ed25519 private key), got ${args.senderKey.length}`
    );
  }
  if (args.senderPubkey.length !== 32) {
    throw new Error(
      `composeBundle: senderPubkey must be 32 bytes (Ed25519 public key), got ${args.senderPubkey.length}`
    );
  }

  const msgId = args.msgId ?? randomUuid16();
  const ts = tsSecOffset();

  // Produce an unsigned bundle (signature field all-zeros).
  const zeroSig = new Uint8Array(64);
  const unsigned = encodeMeshBundle({
    senderPubkey: args.senderPubkey,
    msgId,
    tsSecOffset: ts,
    ttlHops: 3,
    channelIdHash: args.channelId,
    body: args.body,
    signature: zeroSig,
  });

  // Sign the byte range that covers magic..body (excluding trailing sig slot).
  const signedBytes = meshBundleSignedRange(unsigned);
  const signature = ed25519.sign(signedBytes, args.senderKey);

  // Re-encode with real signature.
  const bundle = encodeMeshBundle({
    senderPubkey: args.senderPubkey,
    msgId,
    tsSecOffset: ts,
    ttlHops: 3,
    channelIdHash: args.channelId,
    body: args.body,
    signature,
  });

  return { bundle, msgId, channelId: args.channelId };
}
