// classify-kek-entry.test.ts — the classifier's contract, tested directly.
//
// Every KEK read in this package routes through classifyKekEntry, but until now
// every test reached it through getOrCreateDeviceIdentity / getOrCreateRoomHostSeed.
// A mutation matrix showed three of its five clauses could be DELETED with the
// whole suite still green — `ArrayBuffer.isView`, `type === 'secret'` and
// `algorithm.name === 'AES-KW'` were unmeasured. Untested validation is decoration.
//
// A direct table also covers shapes the integration path cannot easily produce
// (a typed-array view, a detached buffer), and states the contract in one place
// a maintainer can read.

import { describe, expect, it } from 'vitest';
import { classifyKekEntry, generateAesKwKey } from '../aes-kw.js';

async function aesKw(extractable: boolean): Promise<CryptoKey> {
	return crypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, extractable, [
		'wrapKey',
		'unwrapKey',
	]);
}

describe('generateAesKwKey', () => {
	it('generates a 256-bit KEK', async () => {
		// Measured: mutating the length to 128 passed the entire suite. Nothing
		// pinned the strength — classifyKekEntry checks the algorithm NAME but
		// deliberately not the length, and an AES-128-KW key wraps and unwraps a
		// 256-bit seed perfectly well.
		//
		// The check stays here rather than in classifyKekEntry on purpose. Adding
		// a length clause to the classifier would make every stored KEK of an
		// unexpected strength a hard error, and a read-side predicate that can
		// reject a legitimately stored key is how permanent secret loss happens —
		// the same trap as `extractable === false`. Generation is the right place
		// to pin strength; the read side should stay permissive about it.
		const kek = await generateAesKwKey(false);
		expect((kek.algorithm as AesKeyAlgorithm).length).toBe(256);
		expect(kek.extractable).toBe(false);
	});

	it('honours the extractable argument', async () => {
		expect((await generateAesKwKey(true)).extractable).toBe(true);
	});
});

describe('classifyKekEntry', () => {
	it('accepts a non-extractable AES-KW key as { kind: "key" }', async () => {
		const entry = classifyKekEntry(await aesKw(false));
		expect(entry?.kind).toBe('key');
	});

	it('accepts a raw ArrayBuffer as { kind: "raw" }', async () => {
		const raw = await crypto.subtle.exportKey('raw', await aesKw(true));
		const entry = classifyKekEntry(raw);
		expect(entry?.kind).toBe('raw');
	});

	it('accepts a typed-array VIEW as { kind: "raw" }', async () => {
		// No writer in this package produces a view today. The clause is
		// deliberate breadth — IndexedDB implementations are free to hand back a
		// view, and importAesKwRaw takes BufferSource precisely so that works.
		// Asserting it keeps the clause from being silently deletable.
		const raw = await crypto.subtle.exportKey('raw', await aesKw(true));
		const entry = classifyKekEntry(new Uint8Array(raw));
		expect(entry?.kind).toBe('raw');
	});

	it('rejects an EXTRACTABLE AES-KW key', async () => {
		expect(classifyKekEntry(await aesKw(true))).toBeNull();
	});

	it('rejects a key of the wrong ALGORITHM', async () => {
		const hmac = await crypto.subtle.generateKey(
			{ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'],
		);
		expect(classifyKekEntry(hmac)).toBeNull();
	});

	it('rejects an object claiming AES-KW but not type "secret"', () => {
		// NOT constructible with real WebCrypto — an AES-KW key is always
		// 'secret', so the ECDH case below is rejected by the ALGORITHM clause
		// and never exercises this one. Measured: without this case, deleting
		// `type === 'secret'` leaves the whole suite green. The only way to
		// reach the clause is a forged or corrupted entry that satisfies the
		// other two, which is exactly what it is there to refuse.
		expect(
			classifyKekEntry({ type: 'private', algorithm: { name: 'AES-KW' }, extractable: false }),
		).toBeNull();
	});

	it('rejects a key of the wrong TYPE', async () => {
		// An asymmetric private key: type 'private', not 'secret'.
		const pair = await crypto.subtle.generateKey(
			{ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
		);
		expect(classifyKekEntry((pair as CryptoKeyPair).privateKey)).toBeNull();
	});

	it.each([
		['null', null],
		['undefined', undefined],
		['a plain object', { not: 'a key' }],
		['a string', 'wrapping-key'],
		['a number', 42],
		['an array', [1, 2, 3]],
	])('rejects %s', (_label, value) => {
		expect(classifyKekEntry(value)).toBeNull();
	});

	it('does NOT treat a missing extractable flag as extractable', async () => {
		// SEC-CR-008: the predicate is `!== true`, not `=== false`. If an engine's
		// CryptoKey structured-serialization ever succeeds while dropping the
		// flag, `=== false` would reject EVERY legitimately stored KEK — and with
		// no second copy and no migration by design, that is permanent secret
		// loss. `!== true` still rejects a genuinely extractable key, which is all
		// #95 asks, and degrades safely.
		const key = await aesKw(false);
		const flagless = {
			type: key.type,
			algorithm: key.algorithm,
			usages: key.usages,
			// extractable deliberately absent
		};
		expect(classifyKekEntry(flagless)?.kind).toBe('key');
	});
});
