/**
 * history-keys.test.ts — the pure validation layer of the history keyring.
 *
 * Oracles here are deliberately NOT the code under test:
 *  - the small-order list is pinned against vectors written out independently
 *    (the libsodium `has_small_order` blocklist, which keys.rs also copies) AND
 *    against the library's own behaviour (noble throws on an all-zero DH
 *    output), so an edit to the list fails in either direction;
 *  - the routing address is checked against node:crypto, not WebCrypto.
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import {
	X25519_SMALL_ORDER,
	checkKeyPair,
	decodeCanonicalKey32,
	derivePeerAddress,
	isSmallOrderX25519,
	parseKeyringEntries,
	MAX_HISTORY_KEYS,
} from '../history-keys.js';

const b64u = (b: Uint8Array) =>
	Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

// libsodium crypto_scalarmult_curve25519 blocklist (masked-bit-255 forms).
const LIBSODIUM_BLOCKLIST_HEX = [
	'0000000000000000000000000000000000000000000000000000000000000000',
	'0100000000000000000000000000000000000000000000000000000000000000',
	'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
	'5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
	'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
	'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
	'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

function freshPair() {
	const kp = x25519.keygen();
	return { pub: kp.publicKey, secret: kp.secretKey, pubB64u: b64u(kp.publicKey), secretB64u: b64u(kp.secretKey) };
}

describe('X25519 small-order list', () => {
	it('is exactly the libsodium blocklist the server uses', () => {
		expect(X25519_SMALL_ORDER.map((p) => Buffer.from(p).toString('hex'))).toEqual(
			LIBSODIUM_BLOCKLIST_HEX,
		);
	});

	it('every listed point really yields the all-zero DH output (library oracle)', () => {
		const secret = x25519.keygen().secretKey;
		for (const p of X25519_SMALL_ORDER) {
			expect(() => x25519.getSharedSecret(secret, p)).toThrow();
		}
	});

	it('rejects every listed point, and its bit-255 variant (the same point)', () => {
		for (const h of LIBSODIUM_BLOCKLIST_HEX) {
			const p = fromHex(h);
			expect(isSmallOrderX25519(p), h).toBe(true);
			const hi = p.slice();
			hi[31] = (hi[31] ?? 0) | 0x80;
			expect(isSmallOrderX25519(hi), `${h} |bit255`).toBe(true);
		}
	});

	it('does not reject ordinary public keys', () => {
		for (let i = 0; i < 20; i++) expect(isSmallOrderX25519(freshPair().pub)).toBe(false);
	});
});

describe('canonical key decoding', () => {
	const good = freshPair().pubB64u;
	it('accepts a canonical 43-char key', () => {
		expect(decodeCanonicalKey32(good)).toBeInstanceOf(Uint8Array);
	});
	it.each([
		['padded', good + '='],
		['short', good.slice(0, 42)],
		['long', good + 'A'],
		['standard alphabet', good.replace(/-/g, '+').replace(/_/g, '/') + (good.includes('-') || good.includes('_') ? '' : '+')],
		['empty', ''],
		['non-string', 42 as unknown],
	])('rejects %s', (_n, v) => {
		expect(decodeCanonicalKey32(v)).toBeNull();
	});
	it('rejects a non-canonical final character (two strings, one key)', () => {
		// 43 chars carry 258 bits; the last char's low 2 bits must be zero.
		const last = good.charAt(42);
		const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
		const idx = alphabet.indexOf(last);
		const twin = alphabet.charAt(idx ^ 1);
		expect(twin).not.toBe(last);
		expect(decodeCanonicalKey32(good.slice(0, 42) + twin)).toBeNull();
	});
});

describe('routing address', () => {
	it('is SHA-256(pub)[0..8], same as derivePeerIdTarget (node:crypto oracle)', async () => {
		for (let i = 0; i < 10; i++) {
			const { pub } = freshPair();
			const want = createHash('sha256').update(pub).digest().subarray(0, 8);
			expect(Buffer.from(await derivePeerAddress(pub)).equals(want)).toBe(true);
		}
	});
});

describe('checkKeyPair / parseKeyringEntries', () => {
	it('accepts a real pair', () => {
		const p = freshPair();
		expect(checkKeyPair(p.pub, p.secret)).toBeNull();
	});
	it('flags a mismatched pair, a zero secret, and a small-order pub with distinct reasons', () => {
		const a = freshPair();
		const b = freshPair();
		expect(checkKeyPair(a.pub, b.secret)).toBe('pair_mismatch');
		const zero = new Uint8Array(32);
		expect(checkKeyPair(x25519.getPublicKey(zero), zero)).toBe('zero_secret');
		expect(checkKeyPair(fromHex(LIBSODIUM_BLOCKLIST_HEX[3]!), a.secret)).toBe('small_order');
	});
	it('checks the count BEFORE decoding any element', () => {
		const garbage = Array.from({ length: MAX_HISTORY_KEYS + 1 }, () => 'not-an-entry');
		expect(parseKeyringEntries(garbage)).toEqual({ ok: false, reason: 'too_many' });
	});
	it('requires exactly the two fields', () => {
		const p = freshPair();
		const base = { pubB64u: p.pubB64u, secretB64u: p.secretB64u };
		expect(parseKeyringEntries([base]).ok).toBe(true);
		expect(parseKeyringEntries([{ ...base, extra: 1 }])).toEqual({ ok: false, reason: 'bad_entry' });
		expect(parseKeyringEntries([{ pubB64u: base.pubB64u }])).toEqual({ ok: false, reason: 'bad_entry' });
		expect(parseKeyringEntries([[base.pubB64u, base.secretB64u]])).toEqual({ ok: false, reason: 'bad_entry' });
		expect(parseKeyringEntries({ 0: base })).toEqual({ ok: false, reason: 'not_array' });
	});
});
