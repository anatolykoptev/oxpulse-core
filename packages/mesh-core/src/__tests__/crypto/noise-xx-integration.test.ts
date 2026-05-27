/**
 * noise-xx-integration.test.ts — B.2-noise-s-key-derivation
 *
 * Integration test covering the production X25519 code path via
 * @oxpulse/identity.dhX25519() (WebCrypto ECDH deriveBits) — distinct from
 * the @noble/curves edwardsToMontgomery helpers used in noise-xx-static-dh.test.ts.
 *
 * Purpose: the unit tests mock DH with Option C (birational map); production
 * uses Option B (independent WebCrypto X25519 keypair). Without this test,
 * a regression in the WebCrypto DH path could go undetected.
 *
 * Requirement per PR #1069 review: at least one handshake test MUST exercise
 * the @oxpulse/identity production dhX25519() path end-to-end.
 */

import { describe, it, expect } from 'vitest';
import 'fake-indexeddb/auto';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { getOrCreateX25519Keypair, dhX25519 } from '@oxpulse/identity';
import { NoiseXxHandshake } from '../../crypto/noise-xx.js';
import type { DeviceIdentityProvider } from '../../crypto/identity.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Build a DeviceIdentityProvider backed by raw @noble/curves keys.
 * Represents a remote peer (not using WebCrypto storage).
 */
function makePeerProvider(
	edPriv: Uint8Array,
	xPriv: Uint8Array,
): DeviceIdentityProvider {
	const edPub = ed25519.getPublicKey(edPriv);
	const xPub = x25519.getPublicKey(xPriv);
	return {
		async getPublicKey(): Promise<Uint8Array> { return edPub; },
		async sign(msg: Uint8Array): Promise<Uint8Array> { return ed25519.sign(msg, edPriv); },
		async getX25519PublicKey(): Promise<Uint8Array> { return xPub; },
		async dhX25519(remotePub: Uint8Array): Promise<Uint8Array> {
			return x25519.getSharedSecret(xPriv, remotePub);
		},
	};
}

/**
 * Build a DeviceIdentityProvider backed by production @oxpulse/identity
 * WebCrypto X25519 keypair (Option B path). Ed25519 identity uses a
 * fresh @noble/curves keypair (sign() only — not stored in IDB for simplicity;
 * the Noise handshake uses getPublicKey() for the `s` token encryption but
 * does not call crypto.subtle.verify internally).
 */
async function makeProductionProvider(): Promise<DeviceIdentityProvider> {
	// Use noble/curves for Ed25519 (signing identity) — lightweight in tests.
	const edPriv = ed25519.utils.randomSecretKey();
	const edPub = ed25519.getPublicKey(edPriv);

	// Reset cached keypair so each test gets a fresh one via IDB (fake-indexeddb
	// provides isolation at the module level; re-importing clears state).
	// getOrCreateX25519Keypair() is idempotent within a session — call it once
	// to initialise and cache the production WebCrypto keypair.
	const kp = await getOrCreateX25519Keypair();

	return {
		async getPublicKey(): Promise<Uint8Array> { return edPub; },
		async sign(msg: Uint8Array): Promise<Uint8Array> { return ed25519.sign(msg, edPriv); },
		async getX25519PublicKey(): Promise<Uint8Array> { return kp.publicKey; },
		async dhX25519(remotePub: Uint8Array): Promise<Uint8Array> { return dhX25519(remotePub); },
	};
}

/** Run a complete 3-message Noise XX handshake; returns both sides. */
async function runHandshake(
	initiatorId: DeviceIdentityProvider,
	responderId: DeviceIdentityProvider,
): Promise<{ initiator: NoiseXxHandshake; responder: NoiseXxHandshake }> {
	const initiator = new NoiseXxHandshake({ role: 'initiator', identity: initiatorId });
	const responder = new NoiseXxHandshake({ role: 'responder', identity: responderId });

	const m1 = await initiator.writeMessage(new Uint8Array(0));
	await responder.readMessage(m1);

	const m2 = await responder.writeMessage(new Uint8Array(0));
	await initiator.readMessage(m2);

	const m3 = await initiator.writeMessage(new Uint8Array(0));
	await responder.readMessage(m3);

	return { initiator, responder };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Noise XX — production X25519 path (Option B, WebCrypto ECDH)', () => {
	it('completes handshake with production initiator X25519 ↔ noble peer', async () => {
		// Initiator uses production WebCrypto X25519 (Option B).
		// Responder uses @noble/curves (simulates a remote peer).
		const initiatorId = await makeProductionProvider();
		const responderEdPriv = ed25519.utils.randomSecretKey();
		const responderXPriv = x25519.utils.randomSecretKey();
		const responderId = makePeerProvider(responderEdPriv, responderXPriv);

		const { initiator, responder } = await runHandshake(initiatorId, responderId);

		expect(initiator.isComplete()).toBe(true);
		expect(responder.isComplete()).toBe(true);
	});

	it('session keys cross-match when initiator uses production WebCrypto X25519', async () => {
		const initiatorId = await makeProductionProvider();
		const responderId = makePeerProvider(
			ed25519.utils.randomSecretKey(),
			x25519.utils.randomSecretKey(),
		);

		const { initiator, responder } = await runHandshake(initiatorId, responderId);

		const iSplit = initiator.split();
		const rSplit = responder.split();

		// Cross-match: initiator sendKey = responder recvKey and vice versa.
		expect(Array.from(iSplit.sendKey)).toEqual(Array.from(rSplit.recvKey));
		expect(Array.from(iSplit.recvKey)).toEqual(Array.from(rSplit.sendKey));
	});

	it('SAS matches on both sides with production X25519', async () => {
		const initiatorId = await makeProductionProvider();
		const responderId = makePeerProvider(
			ed25519.utils.randomSecretKey(),
			x25519.utils.randomSecretKey(),
		);

		const { initiator, responder } = await runHandshake(initiatorId, responderId);

		expect(initiator.sas()).toBe(responder.sas());
		expect(initiator.sas()).toMatch(/^[0-9]{5}$/);
	});

	it('completes handshake with production responder X25519 ↔ noble initiator', async () => {
		// Responder uses production WebCrypto X25519 (Option B).
		// Initiator uses @noble/curves.
		const initiatorId = makePeerProvider(
			ed25519.utils.randomSecretKey(),
			x25519.utils.randomSecretKey(),
		);
		const responderId = await makeProductionProvider();

		const { initiator, responder } = await runHandshake(initiatorId, responderId);

		const iSplit = initiator.split();
		const rSplit = responder.split();
		expect(Array.from(iSplit.sendKey)).toEqual(Array.from(rSplit.recvKey));
		expect(Array.from(iSplit.recvKey)).toEqual(Array.from(rSplit.sendKey));
	});
});
