// X25519 identity keypair extension for @oxpulse/identity.
//
// Phase 2 T0.5 — operator decision #10:
//   X25519 keypair is separate from Ed25519 (NOT derived).
//   Bound to the Ed25519 identity via a self-sig over "oxp/pkbind/v1" || x25519_pub.

import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { getOrCreateSealedX25519Secret, type DeviceIdentity } from './device-identity.js';

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
// T0.5b DONE: the scalar is persisted in IDB, AES-KW wrapped, by
// getOrCreateSealedX25519Secret() in device-identity.ts. The WeakMap below is
// now only a per-session memo over that read — the durable copy is the one on
// disk, and it is what makes the key publishable at all.

/** Module-scoped cache keyed by DeviceIdentity instance reference. */
const x25519Cache = new WeakMap<DeviceIdentity, X25519Identity>();

/**
 * Get or create the X25519 identity associated with the given Ed25519 DeviceIdentity.
 *
 * The keypair is PERSISTED (IDB, AES-KW wrapped) as of T0.5b, so the public key
 * is stable across sessions and reloads. Before that it was regenerated per
 * page load, which is why the TOFU store saw a new fingerprint every session
 * and why the key could never be published to the server's registry.
 *
 * Idempotent within a session: multiple calls return the same keypair.
 */
export async function getOrCreateX25519Identity(
	identity: DeviceIdentity,
): Promise<X25519Identity> {
	const cached = x25519Cache.get(identity);
	if (cached) return cached;

	// privateKeySeed is the raw 32-byte Ed25519 seed — always available for
	// W7-P2b1+ identities. Pre-W7-P2b1 identities have privateKeySeed=null and
	// cannot produce a self-sig; they show a migration banner instead. Signing
	// goes through noble, which works on runtimes where WebCrypto Ed25519 is
	// absent (HyperOS/HarmonyOS) and is byte-identical where it is present.
	if (!identity.privateKeySeed) {
		throw new Error('[x25519-identity] getOrCreateX25519Identity: privateKeySeed null — identity migration required');
	}

	// PERSISTED, not generated per session (T0.5b, done). A peer encrypts to
	// this public key, so a key that changes on every page load makes every
	// message sealed to the previous one permanently unreadable — and publishing
	// such a key trips the server's 1-rotation/hour throttle and churns every
	// peer's TOFU fingerprint. The scalar now comes from IDB, AES-KW wrapped.
	const priv = await getOrCreateSealedX25519Secret();
	const pub = x25519.getPublicKey(priv);

	const signedBytes = new Uint8Array(PKBIND_PREFIX.length + 32);
	signedBytes.set(PKBIND_PREFIX, 0);
	signedBytes.set(pub, PKBIND_PREFIX.length);

	// Recomputed rather than stored: Ed25519 signing is deterministic (RFC 8032
	// §5.1.6 derives the nonce from the key and message), so this reproduces the
	// same 64 bytes every session — and storing a signature next to the key it
	// signs only adds a way for the two to disagree.
	const selfSig = ed25519.sign(signedBytes, identity.privateKeySeed.bytes());

	const x25519Id: X25519Identity = { priv, pub, selfSig };

	x25519Cache.set(identity, x25519Id);
	return x25519Id;
}
