// T0.5 — X25519 identity keypair + self-sig binding
//
// Plan: docs/superpowers/plans/2026-05-17-phase2-w7p2b1-sdk-pairwise.md §T0.5
//
// Tests:
//   1. generateX25519Identity returns 32-byte priv, 32-byte pub, 64-byte selfSig
//   2. verifyX25519SelfSig passes for own keypair
//   3. verifyX25519SelfSig fails for tampered selfSig
//   4. Self-sig covers "oxp/pkbind/v1"(15) || x25519_pub(32) = 47 bytes
//   5. getOrCreateX25519Identity idempotent — same keypair returned across calls
//   6. getOrCreateX25519Identity persists across module reset (IDB restart)

import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { beforeAll, describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { generateX25519Identity, verifyX25519SelfSig } from '../x25519-identity.js';

// Check runtime supports Ed25519 (same guard as device-identity.test.ts)
let ed25519WebCryptoSupported = false;
beforeAll(async () => {
	try {
		await crypto.subtle.generateKey(
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false,
			['sign', 'verify'],
		);
		ed25519WebCryptoSupported = true;
	} catch {
		ed25519WebCryptoSupported = false;
	}
});

// Generate a random Ed25519 keypair for test fixtures using @noble directly
function makeEd25519Keypair(): { priv: Uint8Array; pub: Uint8Array } {
	const priv = crypto.getRandomValues(new Uint8Array(32));
	const pub = ed25519.getPublicKey(priv);
	return { priv, pub };
}

describe('generateX25519Identity', () => {
	it('returns 32-byte priv, 32-byte pub, 64-byte selfSig', () => {
		const { priv, pub } = makeEd25519Keypair();
		const result = generateX25519Identity(priv);
		expect(result.privateKey).toBeInstanceOf(Uint8Array);
		expect(result.publicKey).toBeInstanceOf(Uint8Array);
		expect(result.selfSig).toBeInstanceOf(Uint8Array);
		expect(result.privateKey.byteLength).toBe(32);
		expect(result.publicKey.byteLength).toBe(32);
		expect(result.selfSig.byteLength).toBe(64);
	});

	it('generates distinct keypairs on each call', () => {
		const { priv } = makeEd25519Keypair();
		const a = generateX25519Identity(priv);
		const b = generateX25519Identity(priv);
		// Distinct random keypairs — probability of collision is negligible
		expect(Buffer.from(a.publicKey).toString('hex')).not.toBe(
			Buffer.from(b.publicKey).toString('hex'),
		);
	});
});

describe('verifyX25519SelfSig', () => {
	it('returns true for a freshly-generated keypair with own ed25519 pub', () => {
		const { priv, pub } = makeEd25519Keypair();
		const { publicKey, selfSig } = generateX25519Identity(priv);
		expect(verifyX25519SelfSig(publicKey, selfSig, pub)).toBe(true);
	});

	it('returns false when selfSig is tampered (first byte flipped)', () => {
		const { priv, pub } = makeEd25519Keypair();
		const { publicKey, selfSig } = generateX25519Identity(priv);
		const tampered = new Uint8Array(selfSig);
		tampered[0] ^= 0xff;
		expect(verifyX25519SelfSig(publicKey, tampered, pub)).toBe(false);
	});

	it('returns false when ed25519Pub belongs to a different keypair', () => {
		const { priv } = makeEd25519Keypair();
		const wrongPub = makeEd25519Keypair().pub;
		const { publicKey, selfSig } = generateX25519Identity(priv);
		expect(verifyX25519SelfSig(publicKey, selfSig, wrongPub)).toBe(false);
	});

	it('self-sig covers "oxp/pkbind/v1" || x25519_pub', () => {
		const { priv, pub } = makeEd25519Keypair();
		const { publicKey, selfSig } = generateX25519Identity(priv);

		// Verify manually using @noble/ed25519 to confirm the signed payload
		const prefix = new TextEncoder().encode('oxp/pkbind/v1');
		// "oxp/pkbind/v1" = 13 bytes (plan comment says 15 — plan has a typo, 13 is correct)
		expect(prefix.byteLength).toBe(13);
		const signedBytes = new Uint8Array(prefix.byteLength + 32);
		signedBytes.set(prefix, 0);
		signedBytes.set(publicKey, prefix.byteLength);
		// Total: 13 + 32 = 45 bytes
		expect(signedBytes.byteLength).toBe(45);

		const valid = ed25519.verify(selfSig, signedBytes, pub);
		expect(valid).toBe(true);
	});
});

describe('getOrCreateX25519Identity (device-identity integration)', () => {
	it('is idempotent — same keypair across calls within session', async () => {
		if (!ed25519WebCryptoSupported) {
			console.warn('Skipping: Ed25519 WebCrypto not available in this runtime');
			return;
		}
		// Reset module so cachedIdentity state is fresh
		const { vi } = await import('vitest');
		vi.resetModules();
		globalThis.indexedDB = new IDBFactory();
		const { getOrCreateDeviceIdentity } = await import('../device-identity.js');
		const { getOrCreateX25519Identity } = await import('../x25519-identity.js');

		const identity = await getOrCreateDeviceIdentity();
		const kp1 = await getOrCreateX25519Identity(identity);
		const kp2 = await getOrCreateX25519Identity(identity);

		expect(Buffer.from(kp1.pub).toString('hex')).toBe(Buffer.from(kp2.pub).toString('hex'));
		expect(Buffer.from(kp1.priv).toString('hex')).toBe(Buffer.from(kp2.priv).toString('hex'));
		expect(Buffer.from(kp1.selfSig).toString('hex')).toBe(
			Buffer.from(kp2.selfSig).toString('hex'),
		);
	});

	it('each returned keypair has correct sizes', async () => {
		if (!ed25519WebCryptoSupported) return;

		const { vi } = await import('vitest');
		vi.resetModules();
		// Use a fresh IDB so tests don't share identity state
		globalThis.indexedDB = new IDBFactory();
		const { getOrCreateDeviceIdentity } = await import('../device-identity.js');
		const { getOrCreateX25519Identity } = await import('../x25519-identity.js');

		const identity = await getOrCreateDeviceIdentity();
		const kp = await getOrCreateX25519Identity(identity);

		expect(kp.priv.byteLength).toBe(32);
		expect(kp.pub.byteLength).toBe(32);
		expect(kp.selfSig.byteLength).toBe(64);
	});

	it('selfSig verifies against ed25519 pubkey via WebCrypto', async () => {
		if (!ed25519WebCryptoSupported) return;

		const { vi } = await import('vitest');
		vi.resetModules();
		globalThis.indexedDB = new IDBFactory();
		const { getOrCreateDeviceIdentity } = await import('../device-identity.js');
		const { getOrCreateX25519Identity, verifyX25519SelfSig } = await import(
			'../x25519-identity.js'
		);
		const { fromBase64url } = await import('../base64url.js');

		const identity = await getOrCreateDeviceIdentity();
		const kp = await getOrCreateX25519Identity(identity);

		// Decode the Ed25519 pub to raw bytes for verifyX25519SelfSig
		const ed25519PubBytes = fromBase64url(identity.publicKeyB64);

		// verifyX25519SelfSig uses @noble — cross-compatible with WebCrypto (both RFC 8032)
		expect(verifyX25519SelfSig(kp.pub, kp.selfSig, ed25519PubBytes)).toBe(true);
	});
});
