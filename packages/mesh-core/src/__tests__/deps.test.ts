import { describe, it, expect } from 'vitest';

describe('crypto deps', () => {
	it('@noble/curves Ed25519 importable', async () => {
		const { ed25519 } = await import('@noble/curves/ed25519.js');
		expect(typeof ed25519.getPublicKey).toBe('function');
	});

	it('@noble/hashes HKDF importable', async () => {
		const { hkdf } = await import('@noble/hashes/hkdf.js');
		expect(typeof hkdf).toBe('function');
	});

	it('@noble/post-quantum ML-KEM-768 importable', async () => {
		const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
		expect(typeof ml_kem768.keygen).toBe('function');
	});

	it('@oxpulse/identity public surface importable', async () => {
		const mod = await import('@oxpulse/identity');
		expect(typeof mod.getOrCreateDeviceIdentity).toBe('function');
	});
});
