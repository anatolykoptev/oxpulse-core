// History keyring: pure validation, no storage.
//
// A device that restores a backup or links to another device must still be able
// to DECRYPT messages sealed to X25519 keys it no longer publishes. Those keys
// are kept as decrypt-only "history" entries (stored by device-identity.ts, next
// to the current sealed key). They are never published and never sign anything.
//
// Everything in here is the trust boundary for key material arriving from
// OUTSIDE the device (a .oxp file, a link-sync frame, an escrow blob), so it is
// strict: exact lengths, canonical base64url, bounded count before any decode,
// and the secret must derive the public key it claims. The server is an
// adversary for this surface (it stores and replays the carrier), so nothing
// here trusts a field because it parsed.

import { x25519 } from '@noble/curves/ed25519.js';
import { toBase64url, fromBase64url } from './base64url.js';

/** Hard cap on history entries held per identity. Checked before any decode. */
export const MAX_HISTORY_KEYS = 64;

/** Provenance of a history entry; telemetry and future policy only. */
export type HistorySource = 'oxp' | 'link' | 'escrow' | 'retired-current';
export const HISTORY_SOURCES: ReadonlySet<string> = new Set([
	'oxp',
	'link',
	'escrow',
	'retired-current',
]);

/**
 * The server's pinned X25519 public-key rejection set, byte-for-byte
 * `X25519_SMALL_ORDER` in oxpulse-chat `crates/sdk/src/keys.rs` (little-endian,
 * bit 255 masked): 0, 1, the two order-8 points and p-1 are the low-order
 * points; p and p+1 are NON-canonical encodings of 0 and 1, rejected for the
 * same reason (they reduce to low-order points). It is the set libsodium's
 * `has_small_order` blocklists. X25519 against any entry yields the all-zero
 * shared secret.
 *
 * The design called for one shared constant in crypto-primitives; that package
 * lives in another repo and identity depends only on @noble/curves, so this is
 * a pinned copy. __tests__/history-keys.test.ts pins it against independent
 * vectors AND against noble's own zero-output rejection, so drift in either
 * direction fails a test.
 */
const ff = (first: number): Uint8Array => {
	const b = new Uint8Array(32).fill(0xff);
	b[0] = first;
	b[31] = 0x7f;
	return b;
};
const one = new Uint8Array(32);
one[0] = 1;

export const X25519_SMALL_ORDER: ReadonlyArray<Uint8Array> = [
	new Uint8Array(32),
	one,
	Uint8Array.from([
		0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
	]),
	Uint8Array.from([
		0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
	]),
	ff(0xec),
	ff(0xed),
	ff(0xee),
];

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.byteLength !== b.byteLength) return false;
	for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
	return true;
}

/**
 * True when `u` is a low-order X25519 public key. Bit 255 is ignored, exactly
 * as X25519 itself ignores it — a high-bit variant of a listed point is the
 * same point and must be rejected too.
 */
export function isSmallOrderX25519(u: Uint8Array): boolean {
	if (u.byteLength !== 32) return false;
	const c = u.slice();
	c[31] = (c[31] ?? 0) & 0x7f;
	return X25519_SMALL_ORDER.some((p) => bytesEqual(p, c));
}

/** Why a keyring operation was refused. Bounded: safe as a telemetry label. */
export type KeyringInvalidReason =
	| 'not_array'
	| 'too_many'
	| 'bad_entry'
	| 'bad_encoding'
	| 'small_order'
	| 'zero_secret'
	| 'pair_mismatch'
	| 'duplicate_pub'
	| 'duplicate_address'
	| 'address_collision'
	| 'owner_mismatch'
	| 'bad_source'
	| 'corrupt_store';

/** One validated entry: decoded, canonical, and `X25519(secret) == pub`. */
export interface ParsedKeyEntry {
	pubB64u: string;
	pub: Uint8Array;
	secret: Uint8Array;
}

/** Canonical 32-byte base64url: exactly 43 chars, and re-encoding is the identity. */
const B64U_32 = /^[A-Za-z0-9_-]{43}$/;

/**
 * Decode a canonical 32-byte base64url string, or null. The length and alphabet
 * are checked BEFORE decoding (fromBase64url is lenient: it accepts padding and
 * ignores trailing bits), and the re-encode check rejects the non-canonical
 * final character — two strings must never name the same key.
 */
export function decodeCanonicalKey32(s: unknown): Uint8Array | null {
	if (typeof s !== 'string' || !B64U_32.test(s)) return null;
	let bytes: Uint8Array;
	try {
		bytes = fromBase64url(s);
	} catch {
		return null;
	}
	if (bytes.byteLength !== 32 || toBase64url(bytes) !== s) return null;
	return bytes;
}

/** X25519(secret) == pub, computed with the library directly. */
export function x25519PairMatches(secret: Uint8Array, pub: Uint8Array): boolean {
	try {
		return bytesEqual(x25519.getPublicKey(secret), pub);
	} catch {
		return false;
	}
}

function isAllZero(b: Uint8Array): boolean {
	let acc = 0;
	for (const x of b) acc |= x;
	return acc === 0;
}

/**
 * Validate one decoded (pub, secret) pair. Shared by import (untrusted input)
 * and by the store's read path (a record is re-proven at every read, so a
 * tampered row is dropped rather than used).
 *
 * Order matters for the REASON only: a small-order pub also fails the pair
 * check, so the small-order test comes first to say what is actually wrong.
 */
export function checkKeyPair(
	pub: Uint8Array,
	secret: Uint8Array,
): KeyringInvalidReason | null {
	if (isSmallOrderX25519(pub)) return 'small_order';
	if (isAllZero(secret)) return 'zero_secret';
	if (!x25519PairMatches(secret, pub)) return 'pair_mismatch';
	return null;
}

/**
 * Parse untrusted `{ pubB64u, secretB64u }[]`. Count and shape are checked
 * before any element is decoded. All-or-nothing: the first bad entry rejects
 * the whole batch, and nothing here touches storage.
 *
 * Uniqueness by public key and by address is NOT decided here (the address
 * needs SHA-256, and the comparison set includes keys already held) — see
 * importSealedHistoryKeys.
 */
export function parseKeyringEntries(
	input: unknown,
	maxEntries: number = MAX_HISTORY_KEYS,
): { ok: true; entries: ParsedKeyEntry[] } | { ok: false; reason: KeyringInvalidReason } {
	if (!Array.isArray(input)) return { ok: false, reason: 'not_array' };
	// Length first: a hostile bundle must not make us decode 10^6 entries before
	// noticing the cap.
	if (input.length > maxEntries) return { ok: false, reason: 'too_many' };

	const entries: ParsedKeyEntry[] = [];
	for (const raw of input as unknown[]) {
		if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
			return { ok: false, reason: 'bad_entry' };
		}
		const keys = Object.keys(raw).sort();
		if (keys.length !== 2 || keys[0] !== 'pubB64u' || keys[1] !== 'secretB64u') {
			return { ok: false, reason: 'bad_entry' };
		}
		const e = raw as { pubB64u: unknown; secretB64u: unknown };
		const pub = decodeCanonicalKey32(e.pubB64u);
		const secret = decodeCanonicalKey32(e.secretB64u);
		if (!pub || !secret) return { ok: false, reason: 'bad_encoding' };
		const bad = checkKeyPair(pub, secret);
		if (bad) return { ok: false, reason: bad };
		entries.push({ pubB64u: e.pubB64u as string, pub, secret });
	}
	return { ok: true, entries };
}

const HEX = '0123456789abcdef';
/** Lowercase hex of `b`; used for address map keys and stored address fields. */
export function toHex(b: Uint8Array): string {
	let s = '';
	for (const x of b) s += HEX.charAt(x >> 4) + HEX.charAt(x & 15);
	return s;
}

/**
 * The 8-byte routing address of an X25519 public key:
 * `SHA-256(pub)[0..8]`, identical to `derivePeerIdTarget` in
 * @oxpulse/crypto-primitives (peer-id.ts). Computed with WebCrypto so identity
 * gains no dependency; __tests__/history-keys.test.ts cross-checks the two
 * against node:crypto.
 */
export async function derivePeerAddress(pub: Uint8Array): Promise<Uint8Array> {
	if (pub.byteLength !== 32) throw new Error('history-keys: x25519 pubkey must be 32 bytes');
	const copy = new ArrayBuffer(32);
	new Uint8Array(copy).set(pub);
	const digest = await crypto.subtle.digest('SHA-256', copy);
	return new Uint8Array(digest).slice(0, 8);
}
