// Algorithm-agnostic raw-bytes AES-KW wrap/unwrap.
//
// WebCrypto's wrapKey('raw', ...) refuses to wrap an arbitrary CryptoKey unless
// it was imported with a concrete algorithm. To wrap OPAQUE secret bytes (e.g.
// an Ed25519 seed) without lying about their type, we import them as an HMAC
// key — HMAC accepts arbitrary byte lengths — so wrapKey('raw', ...) encodes
// the raw key material. The wire format is plain AES-KW ciphertext (RFC 3394:
// inputLength + 8 bytes), independent of the wrapped key's declared algorithm.
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
	bytes: ArrayBuffer,
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
