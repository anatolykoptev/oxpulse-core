// noble-universal.test.ts
//
// TDD RED: Tests for Ed25519/X25519 noble-only paths required for
// HyperOS/HarmonyOS (old-Chromium WebView) that lack WebCrypto Ed25519/X25519.
//
// Root cause: WebCrypto Ed25519 unflagged only in Chrome 137+; GMS-less Xiaomi
// HyperOS (frozen WebView) + HarmonyOS ArkWeb (≤M132) throw NotSupportedError
// → prod metric device_identity_failure_total{ed25519_unsupported}=53.
//
// Fix: route sign/verify/keygen through @noble/curves (RFC 8032-compatible)
// so server ed25519_dalek::verify_strict still accepts signatures.
//
// Tests:
//   1. noble_sign_verify_roundtrip: noble-sign a join payload, noble-verify it
//   2. no_webcrypto_ed25519_still_creates_identity: simulate broken
//      crypto.subtle.importKey(Ed25519) → getOrCreateDeviceIdentity still works
//   3. x25519_noble_dh_roundtrip: noble X25519 keygen + shared secret both ways
//
// Cross-impl KAT (server interop guard) lives in crates/signaling/tests/join_auth_noble_kat.rs

import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ed25519 as nobleEd25519, x25519 as nobleX25519 } from '@noble/curves/ed25519.js';

type DeviceIdentityModule = typeof import('../device-identity.js');

/** Reset module registry so device-identity.ts re-evaluates with empty caches. */
async function freshImport(): Promise<DeviceIdentityModule> {
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

beforeEach(() => {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
});

afterEach(() => {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
	vi.restoreAllMocks();
});

// ── Test 1: noble sign / verify round-trip ────────────────────────────────────

describe('noble_sign_verify_roundtrip', () => {
	it('noble-sign a join payload and noble-verify it', () => {
		// This is a pure noble test that does NOT depend on WebCrypto Ed25519.
		// It verifies the signing path we will use after the swap.
		const seed = nobleEd25519.utils.randomSecretKey();
		const pubBytes = nobleEd25519.getPublicKey(seed);

		// Payload format mirrors server: room_id:nonce_b64:ts
		const payload = 'test-room:AAAAAAAAAAAAAAAAAAAAAA:1748124000';
		const msg = new TextEncoder().encode(payload);

		const sig = nobleEd25519.sign(msg, seed);
		expect(sig.byteLength).toBe(64);

		// noble verify with same pubkey
		const valid = nobleEd25519.verify(sig, msg, pubBytes);
		expect(valid).toBe(true);

		// Wrong message must fail
		const wrong = nobleEd25519.verify(sig, new TextEncoder().encode('different'), pubBytes);
		expect(wrong).toBe(false);
	});

	it('signWithDeviceIdentity produces a sig verifiable by noble (noble-only verify)', async () => {
		// After the swap: signWithDeviceIdentity uses noble internally.
		// This test verifies noble-sign output is verifiable by noble-verify
		// without going through WebCrypto at all.
		const mod = await freshImport();
		const id = await mod.getOrCreateDeviceIdentity();

		// identity.privateKeyBytes is the raw seed — must be non-null post-swap
		expect(id.privateKeyBytes).not.toBeNull();

		const payload = `room-abc:${btoa(String.fromCharCode(...new Uint8Array(16).fill(1))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}:1748124000`;
		const sigB64 = await mod.signWithDeviceIdentity(id, payload);

		// Decode the base64url signature
		const sigBytes = mod.fromBase64url(sigB64);
		const pubBytes = mod.fromBase64url(id.publicKeyB64);
		const msg = new TextEncoder().encode(payload);

		// Noble verify (no WebCrypto Ed25519)
		const valid = nobleEd25519.verify(sigBytes, msg, pubBytes);
		expect(valid).toBe(true);
	});

	it('verifyDeviceSignature uses noble internally and returns true for valid sig', async () => {
		const mod = await freshImport();

		// Generate a noble keypair
		const seed = nobleEd25519.utils.randomSecretKey();
		const pubBytes = nobleEd25519.getPublicKey(seed);
		const msg = new TextEncoder().encode('test-room:nonce-xyz:1748124000');
		const sig = nobleEd25519.sign(msg, seed);

		// After the swap, verifyDeviceSignature must not call crypto.subtle.importKey Ed25519
		const valid = await mod.verifyDeviceSignature(pubBytes, 'test-room:nonce-xyz:1748124000', sig);
		expect(valid).toBe(true);

		// Wrong sig must return false (not throw)
		const tampered = new Uint8Array(sig);
		tampered[0] ^= 0xff;
		const invalid = await mod.verifyDeviceSignature(pubBytes, 'test-room:nonce-xyz:1748124000', tampered);
		expect(invalid).toBe(false);
	});
});

// ── Test 2: no WebCrypto Ed25519 → identity still works ──────────────────────

describe('no_webcrypto_ed25519_still_creates_identity', () => {
	it('getOrCreateDeviceIdentity succeeds when importKey Ed25519 throws NotSupportedError', async () => {
		// Simulate HyperOS/HarmonyOS: crypto.subtle.importKey for Ed25519 throws.
		// After the swap, the identity creation path must succeed via noble.
		const originalImportKey = crypto.subtle.importKey.bind(crypto.subtle);
		vi.spyOn(crypto.subtle, 'importKey').mockImplementation(
			async (format: string, keyData: unknown, algorithm: unknown, extractable: boolean, keyUsages: KeyUsage[]) => {
				const alg = algorithm as { name?: string } | string;
				const algName = typeof alg === 'string' ? alg : alg?.name ?? '';
				if (algName === 'Ed25519') {
					const err = new DOMException('Ed25519 is not supported', 'NotSupportedError');
					throw err;
				}
				// AES-KW, X25519 raw imports still work
				return originalImportKey(format as Parameters<typeof crypto.subtle.importKey>[0], keyData as Parameters<typeof crypto.subtle.importKey>[1], algorithm as Parameters<typeof crypto.subtle.importKey>[2], extractable, keyUsages);
			}
		);

		const mod = await freshImport();

		// Must NOT throw — noble path takes over
		const identity = await mod.getOrCreateDeviceIdentity();
		expect(identity.publicKeyB64).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(identity.privateKeyBytes).not.toBeNull();
		expect(identity.privateKeyBytes!.byteLength).toBe(32);

		// Must NOT classify as ed25519_unsupported (the error we're fixing)
		// i.e., no error thrown at all
	});

	it('getOrCreateDeviceIdentity succeeds on reload when importKey Ed25519 throws', async () => {
		// First: create identity with normal WebCrypto (so IDB is populated)
		const mod1 = await freshImport();
		await mod1.getOrCreateDeviceIdentity();

		// Now simulate reload with broken WebCrypto Ed25519
		const originalImportKey = crypto.subtle.importKey.bind(crypto.subtle);
		vi.spyOn(crypto.subtle, 'importKey').mockImplementation(
			async (format: string, keyData: unknown, algorithm: unknown, extractable: boolean, keyUsages: KeyUsage[]) => {
				const alg = algorithm as { name?: string } | string;
				const algName = typeof alg === 'string' ? alg : alg?.name ?? '';
				if (algName === 'Ed25519') {
					throw new DOMException('Ed25519 is not supported', 'NotSupportedError');
				}
				return originalImportKey(format as Parameters<typeof crypto.subtle.importKey>[0], keyData as Parameters<typeof crypto.subtle.importKey>[1], algorithm as Parameters<typeof crypto.subtle.importKey>[2], extractable, keyUsages);
			}
		);

		// Fresh module import (simulates reload), but SAME IDB
		const mod2 = await freshImport();
		const identity = await mod2.getOrCreateDeviceIdentity();
		expect(identity.publicKeyB64).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(identity.privateKeyBytes).not.toBeNull();
	});
});

// ── Test 3: X25519 noble ECDH roundtrip (KAT) ────────────────────────────────

describe('x25519_noble_dh_roundtrip', () => {
	it('noble X25519 derives identical shared secret in both directions', () => {
		// This is the pure-noble equivalent of the WebCrypto deriveBits path.
		// After the swap, dhX25519 must use this same computation.
		const alicePriv = nobleX25519.utils.randomSecretKey();
		const alicePub = nobleX25519.getPublicKey(alicePriv);
		const bobPriv = nobleX25519.utils.randomSecretKey();
		const bobPub = nobleX25519.getPublicKey(bobPriv);

		const aliceShared = nobleX25519.getSharedSecret(alicePriv, bobPub);
		const bobShared = nobleX25519.getSharedSecret(bobPriv, alicePub);

		expect(Array.from(aliceShared)).toEqual(Array.from(bobShared));
		expect(aliceShared.byteLength).toBe(32);
	});

	it('dhX25519 returns 32-byte shared secret using noble (no WebCrypto X25519)', async () => {
		// After the swap, dhX25519 must not call crypto.subtle.generateKey('X25519', ...)
		// Simulate X25519 not being in WebCrypto
		const originalGenerateKey = crypto.subtle.generateKey.bind(crypto.subtle);
		vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(
			async (algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]) => {
				const alg = algorithm as { name?: string } | string;
				const algName = typeof alg === 'string' ? alg : alg?.name ?? '';
				if (algName === 'X25519') {
					throw new DOMException('X25519 is not supported', 'NotSupportedError');
				}
				return originalGenerateKey(algorithm, extractable, keyUsages);
			}
		);

		const mod = await freshImport();

		// Generate a remote party X25519 keypair via noble (as the remote peer would)
		const remotePriv = nobleX25519.utils.randomSecretKey();
		const remotePub = nobleX25519.getPublicKey(remotePriv);

		// After the swap, this must succeed without WebCrypto X25519
		const shared = await mod.dhX25519(remotePub);
		expect(shared).toBeInstanceOf(Uint8Array);
		expect(shared.byteLength).toBe(32);

		// The remote party should compute the same shared secret
		// We need the local public key — get the keypair first
		const kp = await mod.getOrCreateX25519Keypair();
		const remoteShared = nobleX25519.getSharedSecret(remotePriv, kp.publicKey);
		expect(Array.from(shared)).toEqual(Array.from(remoteShared));
	});
});

// ── Test 4: probeBrowserSupport does not throw on old WebCrypto ───────────────

describe('probeBrowserSupport_no_throw', () => {
	it('probeBrowserSupport never throws even when Ed25519 WebCrypto is absent', async () => {
		vi.spyOn(crypto.subtle, 'generateKey').mockRejectedValueOnce(
			new DOMException('Ed25519 is not supported', 'NotSupportedError')
		);

		const mod = await freshImport();
		// Must not throw
		await expect(mod.probeBrowserSupport()).resolves.toBeUndefined();
	});
});
