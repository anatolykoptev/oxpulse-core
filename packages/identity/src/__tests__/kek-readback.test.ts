// kek-readback.test.ts — the KEK must survive a SECOND load.
//
// Deleting the legacy-KEK migration in #104 also deleted the only test that
// loaded an EXISTING KEK; everything left asserts the creation path, which is
// the branch that works. identity 0.2.0 shipped a read-back that crashes, and
// this repo's suite could not see it: vitest runs `environment: 'node'`, where
// `CryptoKey` is a global. jsdom — every consumer's test environment — provides
// crypto.subtle and structuredClone but no CryptoKey constructor binding. See #108.

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';

type DeviceIdentityModule = typeof import('../device-identity.js');

let ed25519Supported = false;

beforeAll(async () => {
	try {
		await crypto.subtle.generateKey(
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false,
			['sign', 'verify'],
		);
		ed25519Supported = true;
	} catch {
		ed25519Supported = false;
	}
});

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

/**
 * A fresh module graph over the SAME IndexedDB — this is what a page reload is.
 * `cachedWrappingKey` and the structured-clone probe are module-level, so
 * resetting modules WITHOUT resetting IDB is the only way to reach the
 * load-an-existing-KEK branch at all.
 */
async function reload(): Promise<DeviceIdentityModule> {
	vi.resetModules();
	return (await import('../device-identity.js')) as DeviceIdentityModule;
}

beforeEach(() => { resetIDB(); });
afterEach(() => { resetIDB(); });

describe('KEK read-back (#108)', () => {
	it('reloads an existing KEK on a runtime with NO global CryptoKey binding', async () => {
		if (!ed25519Supported) return;

		// First load: creates the identity and persists the KEK as a CryptoKey.
		const first = await reload();
		const before = await first.getOrCreateDeviceIdentity();

		const savedCtor = (globalThis as Record<string, unknown>).CryptoKey;
		delete (globalThis as Record<string, unknown>).CryptoKey;
		try {
			const second = await reload();
			const after = await second.getOrCreateDeviceIdentity();
			// Same device — not a silently re-minted one, and not a crash.
			expect(after.publicKeyB64).toBe(before.publicKeyB64);
			expect(after.privateKeySeed).not.toBeNull();
		} finally {
			(globalThis as Record<string, unknown>).CryptoKey = savedCtor;
		}
	});

	// NOTE — a second defect was hypothesised for this line: that `canClone`
	// (a WRITE-capability probe) gating a READ would mis-handle a stored
	// CryptoKey after a WebView downgrade. Measured, that case is NOT reachable:
	// IndexedDB structured-clones on read too, so a runtime that cannot clone a
	// CryptoKey cannot return one either — the load rejects first, which is the
	// honest "unreadable KEK" hard error the docstring already promises. The
	// hypothesis is recorded here rather than as a test that passes vacuously.
});
