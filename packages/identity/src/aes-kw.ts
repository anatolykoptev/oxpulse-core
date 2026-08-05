// Algorithm-agnostic raw-bytes AES-KW wrap/unwrap.
//
// WebCrypto's wrapKey('raw', ...) refuses to wrap an arbitrary CryptoKey unless
// it was imported with a concrete algorithm. To wrap OPAQUE secret bytes (e.g.
// an Ed25519 seed) without lying about their type, we import them as an HMAC
// key, so wrapKey('raw', ...) encodes the raw key material. The wire format is
// plain AES-KW ciphertext (RFC 3394: inputLength + 8 bytes), independent of the
// wrapped key's declared algorithm — which is what makes this format-compatible
// with data written by the previous AES-256-import code (measured: identical
// ciphertext, byte for byte).
//
// What the HMAC import actually buys, precisely: an AES-KW *import* accepts
// only 16/24/32 bytes, so it cannot represent a 40- or 64-byte secret at all.
// HMAC import accepts any length. It does NOT make any length wrappable —
// AES-KW itself still requires the payload to be a multiple of 8 bytes and at
// least 16, whatever the inner key claims to be. Measured on Node 24:
//
//     16 -> ok    20 -> OperationError    24 -> ok    31 -> OperationError
//     32 -> ok    33 -> OperationError    40 -> ok    64 -> ok
//
// An earlier version of this comment said HMAC import made arbitrary lengths
// work. It does not, and the failure is a bare OpenSSL "invalid input length"
// with nothing pointing back here — hence the explicit check in
// wrapSecretBytes below.
//
// This module is deliberately algorithm-agnostic: it knows nothing about
// Ed25519, PKCS8, or OIDs. Domain layers (device-identity.ts etc.) own that
// knowledge and call into these helpers with raw bytes.
//
// HMAC-import trick adapted from MrKCodes/KonvoPro packages/crypto/src/internal/aes-kw.ts.

import { toArrayBuffer } from './crypto-utils.js';

/**
 * Wrap opaque secret bytes under an AES-KW key.
 *
 * The bytes are imported as an HMAC key (extractable, usages=['sign']) purely so
 * wrapKey('raw', ...) will encode them — the algorithm is never used for
 * anything else. The returned ArrayBuffer is RFC 3394 ciphertext
 * (rawBytes.length + 8 bytes).
 */
export async function wrapSecretBytes(
	kek: CryptoKey,
	rawBytes: Uint8Array,
): Promise<ArrayBuffer> {
	// Fail with the reason rather than letting AES-KW throw
	// `OperationError: invalid input length` from deep inside WebCrypto.
	if (rawBytes.byteLength < 16 || rawBytes.byteLength % 8 !== 0) {
		throw new Error(
			`[aes-kw] cannot wrap ${rawBytes.byteLength} bytes: AES-KW requires a multiple of 8, minimum 16`,
		);
	}
	const inner = await crypto.subtle.importKey(
		'raw',
		toArrayBuffer(rawBytes),
		{ name: 'HMAC', hash: 'SHA-256' },
		true, // must be extractable so wrapKey can encode it
		['sign'],
	);
	return crypto.subtle.wrapKey('raw', inner, kek, 'AES-KW');
}

/**
 * Unwrap AES-KW ciphertext back into the original opaque secret bytes.
 *
 * Mirrors {@link wrapSecretBytes}: unwrapKey('raw', ...) into an HMAC key, then
 * exportKey('raw') to recover the bytes. Returns a Uint8Array view over a
 * fresh ArrayBuffer.
 */
export async function unwrapSecretBytes(
	kek: CryptoKey,
	wrapped: ArrayBuffer,
): Promise<Uint8Array> {
	const inner = await crypto.subtle.unwrapKey(
		'raw',
		wrapped,
		kek,
		'AES-KW',
		{ name: 'HMAC', hash: 'SHA-256' },
		true, // must be extractable so exportKey can recover the bytes
		['sign'],
	);
	const exported = await crypto.subtle.exportKey('raw', inner);
	return new Uint8Array(exported);
}

/**
 * Generate a fresh AES-256-KW key (the KEK used to wrap/unwrap secret bytes).
 */
export async function generateAesKwKey(extractable: boolean): Promise<CryptoKey> {
	return crypto.subtle.generateKey(
		{ name: 'AES-KW', length: 256 },
		extractable,
		['wrapKey', 'unwrapKey'],
	);
}

/**
 * Import raw bytes as an AES-KW key (e.g. to restore a persisted KEK).
 *
 * AES-KW keys must be 16, 24, or 32 bytes (AES-128/192/256-KW).
 */
export async function importAesKwRaw(
	bytes: BufferSource,
	extractable: boolean,
): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		'raw',
		bytes,
		{ name: 'AES-KW', length: bytes.byteLength * 8 },
		extractable,
		['wrapKey', 'unwrapKey'],
	);
}

/**
 * A KEK entry as read back from IndexedDB, classified by shape.
 *
 * Both KEK stores persist exactly two shapes: a non-extractable AES-KW CryptoKey
 * (on runtimes that can structured-clone one) or its raw 32 bytes.
 */
export type KekEntry =
	| { kind: 'raw'; bytes: BufferSource }
	| { kind: 'key'; key: CryptoKey };

/**
 * Classify a stored KEK entry. Returns null for anything that is neither shape —
 * callers must treat that as a hard error rather than caching it as a key handle.
 *
 * Telling the two apart must NOT use `instanceof` on either side. Both halves of
 * that were measured, not reasoned about:
 *
 *   - `existing instanceof CryptoKey` throws ReferenceError wherever the
 *     constructor is not bound as a global (#108). It fires only on a SECOND
 *     load, once a KEK exists, so first run looks healthy.
 *   - `existing instanceof ArrayBuffer` is realm-local, and under jsdom it is
 *     FALSE for a genuine 32-byte export — `crypto.subtle` hands back a
 *     Node-realm buffer while the global is jsdom's. Measured:
 *
 *         PROBE exported  toString= [object ArrayBuffer] | instanceof = false
 *         PROBE roundtrip toString= [object ArrayBuffer] | instanceof = false
 *
 *     Keying off it routes real KEK bytes into the CryptoKey branch and makes a
 *     READABLE key undecryptable — strictly worse than the bug it replaced.
 *
 * `Object.prototype.toString` and `ArrayBuffer.isView` are internal-slot brand
 * checks, so both are realm-safe. The CryptoKey side is validated POSITIVELY
 * rather than inferred by elimination: an entry of an unexpected shape must not
 * become the process-lifetime `cachedWrappingKey`, and it should fail at the KEK
 * layer with a name that says so instead of surfacing later as `unwrap_failed`.
 */
export function classifyKekEntry(existing: unknown): KekEntry | null {
	if (
		ArrayBuffer.isView(existing) ||
		Object.prototype.toString.call(existing) === '[object ArrayBuffer]'
	) {
		return { kind: 'raw', bytes: existing as BufferSource };
	}
	const key = existing as CryptoKey | null;
	if (
		typeof key === 'object' &&
		key !== null &&
		key.type === 'secret' &&
		key.algorithm?.name === 'AES-KW' &&
		key.extractable === false
	) {
		return { kind: 'key', key };
	}
	return null;
}
