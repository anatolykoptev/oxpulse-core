// Tests for the algorithm-agnostic AES-KW wrap/unwrap helpers.
//
// These verify the HMAC-import trick: opaque bytes round-trip through
// wrapSecretBytes/unwrapSecretBytes without any knowledge of what the bytes
// actually are (Ed25519 seed, X25519 seed, etc.).

import { describe, it, expect } from 'vitest';
import {
	wrapSecretBytes,
	unwrapSecretBytes,
	generateAesKwKey,
	importAesKwRaw,
} from '../aes-kw.js';

describe('aes-kw (algorithm-agnostic raw-bytes wrap/unwrap)', () => {
	it('round-trips a 32-byte secret through wrap/unwrap', async () => {
		const kek = await generateAesKwKey(true);
		const seed = crypto.getRandomValues(new Uint8Array(32));

		const wrapped = await wrapSecretBytes(kek, seed);
		const unwrapped = await unwrapSecretBytes(kek, wrapped);

		expect(unwrapped.byteLength).toBe(seed.byteLength);
		expect(Array.from(unwrapped)).toEqual(Array.from(seed));
	});

	it('throws when unwrapping with the wrong KEK (AES-KW integrity check)', async () => {
		const wrappingKek = await generateAesKwKey(true);
		const wrongKek = await generateAesKwKey(true);
		const seed = crypto.getRandomValues(new Uint8Array(32));

		const wrapped = await wrapSecretBytes(wrappingKek, seed);

		await expect(unwrapSecretBytes(wrongKek, wrapped)).rejects.toThrow();
	});

	it('generateAesKwKey(false) produces a non-extractable key', async () => {
		const kek = await generateAesKwKey(false);
		expect(kek.extractable).toBe(false);
	});

	it('generateAesKwKey(true) produces an extractable key', async () => {
		const kek = await generateAesKwKey(true);
		expect(kek.extractable).toBe(true);
	});

	it('importAesKwRaw accepts 32-byte (AES-256-KW) and 16-byte (AES-128-KW) inputs', async () => {
		const kek256 = await importAesKwRaw(crypto.getRandomValues(new Uint8Array(32)).buffer, true);
		expect(kek256.extractable).toBe(true);

		const kek128 = await importAesKwRaw(crypto.getRandomValues(new Uint8Array(16)).buffer, false);
		expect(kek128.extractable).toBe(false);
	});

	it.each([8, 12, 15, 20, 31, 33])('rejects %i bytes with a reason, not an OpenSSL error', async (n) => {
		const kek = await generateAesKwKey(true);
		const bytes = crypto.getRandomValues(new Uint8Array(n));

		// AES-KW takes multiples of 8, minimum 16. Without the precondition
		// these throw `OperationError: invalid input length` from inside
		// WebCrypto, which says nothing about where the constraint comes from.
		await expect(wrapSecretBytes(kek, bytes)).rejects.toThrow(/multiple of 8, minimum 16/);
	});

	it.each([16, 24, 32, 40, 64])('accepts %i bytes (multiple of 8, >= 16)', async (n) => {
		const kek = await generateAesKwKey(true);
		const bytes = crypto.getRandomValues(new Uint8Array(n));

		const wrapped = await wrapSecretBytes(kek, bytes);
		const back = await unwrapSecretBytes(kek, wrapped);

		expect(Array.from(back)).toEqual(Array.from(bytes));
	});

	it('wrap output length is input length + 8 (RFC 3394)', async () => {
		const kek = await generateAesKwKey(true);
		const seed = crypto.getRandomValues(new Uint8Array(32));

		const wrapped = await wrapSecretBytes(kek, seed);

		expect(wrapped.byteLength).toBe(seed.byteLength + 8);
	});
});
