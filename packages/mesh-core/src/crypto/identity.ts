/**
 * identity.ts — long-term Ed25519 identity adapter for mesh-core.
 *
 * Imports directly from @oxpulse/identity (PR #1039, 2026-05-17).
 * The provider-injection seam (B.2 plan R5) is no longer needed —
 * @oxpulse/identity is a direct workspace dependency of mesh-core.
 * See: docs/architecture/identity-extraction-adr.md §5 Step 3.
 */

import { getOrCreateDeviceIdentity, fromBase64url } from '@oxpulse/identity';
import { sha256 } from '@noble/hashes/sha2.js';
import { PEER_ID_BYTES } from '../constants.generated.js';

/**
 * X25519 static keypair adapter for Noise XX es/se DH binding.
 *
 * Design: Option B per B.2-noise-s-key-derivation.
 * (Option B: independent X25519 keypair generated alongside Ed25519,
 * NOT derived from Ed25519 seed. See device-identity.ts getOrCreateX25519Keypair.
 * WebCrypto's generateKey returns non-extractable Ed25519 keys with no seed
 * access, so birational-map approach (Option C) was infeasible. Tests in
 * noise-xx-static-dh.test.ts use ed25519.utils.toMontgomerySecret() for
 * deterministic vectors — production code does NOT use that path.)
 */
export interface DeviceIdentityProvider {
  /** Returns the 32-byte Ed25519 public key. */
  getPublicKey(): Promise<Uint8Array>;
  /** Signs msg with the corresponding Ed25519 secret key. */
  sign(msg: Uint8Array): Promise<Uint8Array>;
  /**
   * Returns the 32-byte X25519 static public key for Noise XX `s` tokens.
   * B.2-noise-s-key-derivation: separate X25519 keypair stored alongside Ed25519.
   */
  getX25519PublicKey(): Promise<Uint8Array>;
  /**
   * Performs X25519 Diffie-Hellman with the device static private key and
   * the given remote X25519 public key. Returns 32 raw shared-secret bytes.
   * Used for Noise XX `es` and `se` tokens.
   */
  dhX25519(remotePub: Uint8Array): Promise<Uint8Array>;
}

/** Derive 8-byte peer-id from the device's long-term Ed25519 pubkey. */
export async function derivePeerId(): Promise<Uint8Array> {
  const identity = await getOrCreateDeviceIdentity();
  // Use publicKeyB64 (raw 32 bytes) — works on all runtimes including those
  // where WebCrypto Ed25519 is absent (HyperOS/HarmonyOS, Chrome <137).
  // identity.publicKey CryptoKey may be null on those runtimes.
  const pk = fromBase64url(identity.publicKeyB64);
  if (pk.length !== 32) throw new Error('identity: expected 32-byte Ed25519 pubkey');
  return sha256(pk).slice(0, PEER_ID_BYTES);
}
