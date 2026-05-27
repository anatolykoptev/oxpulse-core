// X25519 identity keypair extension for @oxpulse/identity.
//
// Phase 2 T0.5 — operator decision #10:
//   X25519 keypair is separate from Ed25519 (NOT derived).
//   Bound to the Ed25519 identity via a self-sig over "oxp/pkbind/v1" || x25519_pub.
//
// Plan: docs/superpowers/plans/2026-05-17-phase2-w7p2b1-sdk-pairwise.md §T0.5

import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import type { DeviceIdentity } from './device-identity.js';

const PKBIND_PREFIX = new TextEncoder().encode('oxp/pkbind/v1');

export interface X25519Identity {
	priv: Uint8Array; // 32-byte X25519 private key
	pub: Uint8Array; // 32-byte X25519 public key
	selfSig: Uint8Array; // 64-byte Ed25519 signature over "oxp/pkbind/v1" || pub
}

/**
 * Generate a new X25519 keypair and sign the public key with the given Ed25519 private key.
 *
 * The self-sig proves the holder of the Ed25519 identity acknowledges ownership of this
 * X25519 key. Signed payload: "oxp/pkbind/v1" (15 bytes) || x25519_pub (32 bytes) = 47 bytes.
 *
 * @param ed25519PrivKey - 32-byte raw Ed25519 private key scalar (from @noble/curves)
 */
export function generateX25519Identity(ed25519PrivKey: Uint8Array): {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
	selfSig: Uint8Array;
} {
	const kp = x25519.keygen();
	const signedBytes = new Uint8Array(PKBIND_PREFIX.length + 32);
	signedBytes.set(PKBIND_PREFIX, 0);
	signedBytes.set(kp.publicKey, PKBIND_PREFIX.length);
	const selfSig = ed25519.sign(signedBytes, ed25519PrivKey);
	return { privateKey: kp.secretKey, publicKey: kp.publicKey, selfSig };
}

/**
 * Verify a self-sig binding an X25519 public key to an Ed25519 identity.
 *
 * Returns true iff selfSig is a valid Ed25519 signature over
 * "oxp/pkbind/v1" || x25519Pub produced by the private key corresponding to ed25519Pub.
 */
export function verifyX25519SelfSig(
	x25519Pub: Uint8Array,
	selfSig: Uint8Array,
	ed25519Pub: Uint8Array,
): boolean {
	const signedBytes = new Uint8Array(PKBIND_PREFIX.length + 32);
	signedBytes.set(PKBIND_PREFIX, 0);
	signedBytes.set(x25519Pub, PKBIND_PREFIX.length);
	try {
		// zip215:false aligns with server ed25519_dalek::verify_strict — both enforce
		// RFC 8032 strict semantics (reject small-order / non-canonical pubkeys).
		// The lenient default (zip215:true / ZIP-215) would accept inputs that the
		// server rejects, creating a client↔server verify split.
		return ed25519.verify(selfSig, signedBytes, ed25519Pub, { zip215: false });
	} catch {
		return false;
	}
}

// ─── Session-level X25519 identity cache ─────────────────────────────────────
//
// FOLLOWUP(T0.5b): persist X25519 keypair to IDB with same AES-KW wrap pattern
// as Ed25519 (device-identity.ts). For now, in-memory generation on first call
// per session is functionally correct for Phase 2 testing. Persistence requires
// extending the IDB schema without stranding existing users' identities.

/** Module-scoped cache keyed by DeviceIdentity instance reference. */
const x25519Cache = new WeakMap<DeviceIdentity, X25519Identity>();

/**
 * Get or create the X25519 identity associated with the given Ed25519 DeviceIdentity.
 *
 * FOLLOWUP(T0.5b): currently in-memory only — regenerated on each page load.
 * Persistence to IDB is deferred. The TOFU store (T9) compensates: recipients
 * see a new fingerprint on each session, triggering the "key changed" warn-and-send
 * path. This is acceptable for Phase 2 (decision #5 — warn, don't block).
 *
 * Idempotent within a session: multiple calls return the same keypair.
 */
export async function getOrCreateX25519Identity(
	identity: DeviceIdentity,
): Promise<X25519Identity> {
	const cached = x25519Cache.get(identity);
	if (cached) return cached;

	// Generate fresh X25519 keypair and self-sign with @noble/curves ed25519.
	// privateKeyBytes is the raw 32-byte Ed25519 seed — always available for
	// W7-P2b1+ identities (which include all new enrollments after the noble-universal
	// swap). Pre-W7-P2b1 identities have privateKeyBytes=null and cannot produce
	// a self-sig — they show a migration banner instead.
	//
	// Previously this path called crypto.subtle.sign() with identity.privateKey
	// (CryptoKey). That is now unnecessary: noble ed25519.sign() works on all
	// runtimes including HyperOS/HarmonyOS where WebCrypto Ed25519 is absent,
	// and produces byte-identical signatures. The workaround comment is removed.
	if (!identity.privateKeyBytes) {
		throw new Error('[x25519-identity] getOrCreateX25519Identity: privateKeyBytes null — identity migration required');
	}
	const kp = x25519.keygen();

	const signedBytes = new Uint8Array(PKBIND_PREFIX.length + 32);
	signedBytes.set(PKBIND_PREFIX, 0);
	signedBytes.set(kp.publicKey, PKBIND_PREFIX.length);

	const selfSig = ed25519.sign(signedBytes, identity.privateKeyBytes);

	const x25519Id: X25519Identity = {
		priv: kp.secretKey,
		pub: kp.publicKey,
		selfSig,
	};

	x25519Cache.set(identity, x25519Id);
	return x25519Id;
}
