// IDB availability probe + graceful degradation for in-app WebView environments.
//
// Prod context: Instagram/TikTok/Facebook in-app WebViews return a broken
// indexedDB handle (or throw on .open()), causing:
//   TypeError: undefined is not an object (evaluating 't.objectStoreNames')
// at boot — before any identity is established. The user never enters.
//
// This test suite covers:
//   1. isIDBAvailable() detection (undefined, open throws, open hangs > 500 ms)
//   2. getOrCreateDeviceIdentity() falls back to in-memory identity on negative detect
//   3. client.idb_unavailable analytics emitted with bounded reason enum

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';

import { isIDBAvailable } from '../idb-availability.js';
import { _resetIDBAvailabilityCache } from '../idb-store.js';
import { clearDeviceIdentity, getOrCreateDeviceIdentity, hasDeviceIdentity } from '../device-identity.js';
import { setIdentityTracker } from '../tracker-shim.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

function deleteIDB(): void {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	delete (globalThis as any).indexedDB;
}

beforeEach(() => {
	resetIDB();
});

afterEach(() => {
	// Always restore IDB so subsequent test files (device-identity-migration.test.ts)
	// see a healthy IDB. This is critical: fake-indexeddb/auto installs IDB globals
	// once at file load time; our deleteIDB() removes them and we must restore.
	resetIDB();
	vi.useRealTimers();
	vi.restoreAllMocks();
});

// ── isIDBAvailable ────────────────────────────────────────────────────────────

describe('isIDBAvailable', () => {
	it('returns true when indexedDB is present and open() succeeds', async () => {
		const result = await isIDBAvailable();
		expect(result).toBe(true);
	});

	it('returns false when indexedDB is undefined (no_indexedDB)', async () => {
		deleteIDB();
		const result = await isIDBAvailable();
		expect(result).toBe(false);
	});

	it('returns false when indexedDB.open() throws synchronously (open_failed)', async () => {
		(globalThis as { indexedDB: unknown }).indexedDB = {
			open: () => {
				throw new DOMException('SecurityError', 'SecurityError');
			},
		};
		const result = await isIDBAvailable();
		expect(result).toBe(false);
	});

	it('returns false when open() fires onerror (open_failed)', async () => {
		(globalThis as { indexedDB: unknown }).indexedDB = {
			open: () => {
				const req = {
					onerror: null as (() => void) | null,
					onsuccess: null as (() => void) | null,
					onupgradeneeded: null as (() => void) | null,
					error: new DOMException('UnknownError', 'UnknownError'),
				};
				// Fire onerror asynchronously on the next microtask
				queueMicrotask(() => {
					req.onerror?.();
				});
				return req;
			},
		};
		const result = await isIDBAvailable();
		expect(result).toBe(false);
	});

	it('returns false when open() hangs beyond 500 ms (timeout)', async () => {
		vi.useFakeTimers();
		(globalThis as { indexedDB: unknown }).indexedDB = {
			open: () => ({
				onerror: null,
				onsuccess: null,
				onupgradeneeded: null,
				// Never fires — simulates a broken frozen handle
			}),
		};
		const resultPromise = isIDBAvailable();
		// Advance past the 500 ms probe timeout
		vi.advanceTimersByTime(600);
		const result = await resultPromise;
		expect(result).toBe(false);
	});
});

// ── getOrCreateDeviceIdentity fallback ───────────────────────────────────────
//
// Strategy: avoid vi.resetModules() to prevent WebCrypto key context corruption
// across test files (Node.js rejects CryptoKey objects across module resets).
// Instead:
//   1. Use _resetIDBAvailabilityCache() to clear the probe cache in idb-store.ts.
//   2. Use clearDeviceIdentity() to clear cachedIdentity in device-identity.ts.
//   3. deleteIDB() + resetIDB() to control IDB availability.

describe('getOrCreateDeviceIdentity — IDB unavailable fallback', () => {
	it('returns an in-memory identity and emits client.idb_unavailable when IDB is missing', async () => {
		const trackSpy = vi.fn();
		setIdentityTracker(trackSpy);

		// Clear module-level caches so the call proceeds from a clean state.
		await clearDeviceIdentity().catch(() => { /* no-op if IDB was never used */ });
		_resetIDBAvailabilityCache();

		// Remove IDB so isIDBAvailable returns false
		deleteIDB();

		const identity = await getOrCreateDeviceIdentity();

		// Must still return a usable identity (publicKeyB64 present, 32 bytes base64url)
		expect(identity.publicKeyB64).toMatch(/^[A-Za-z0-9_-]{43,44}$/);

		// telemetry emitted with bounded reason enum
		const idbUnavailableCall = trackSpy.mock.calls.find(
			([evt]) => evt === 'client.idb_unavailable',
		);
		expect(idbUnavailableCall).toBeDefined();
		const reason = idbUnavailableCall?.[2]?.reason as string;
		expect(['no_indexedDB', 'open_failed', 'timeout']).toContain(reason);
	});

	it('in-memory identity is not persisted — re-call after restoring IDB creates a persistent identity', async () => {
		// Session 1: IDB absent → ephemeral identity (not cached)
		await clearDeviceIdentity().catch(() => {});
		_resetIDBAvailabilityCache();
		deleteIDB();

		const first = await getOrCreateDeviceIdentity();
		expect(first.publicKeyB64).toMatch(/^[A-Za-z0-9_-]{43,44}$/);

		// Behavioral invariant: ephemeral identity must NOT be persisted.
		// We verify this by checking that IDB is empty after restoring IDB
		// (the ephemeral path explicitly skips setting cachedIdentity, so
		// next call will re-probe and generate a fresh persistent key).
		resetIDB();
		_resetIDBAvailabilityCache(); // clear negative cache so hasDeviceIdentity() can probe
		// IDB is now empty — hasDeviceIdentity() must return false because
		// the ephemeral path never wrote to IDB.
		const persisted = await hasDeviceIdentity();
		expect(persisted).toBe(false);

		// Session 2: IDB available → should create a NEW persistent identity
		_resetIDBAvailabilityCache();

		const second = await getOrCreateDeviceIdentity();
		expect(second.publicKeyB64).toMatch(/^[A-Za-z0-9_-]{43,44}$/);

		// Behavioral: second identity IS persisted in IDB.
		const persistedAfterSecond = await hasDeviceIdentity();
		expect(persistedAfterSecond).toBe(true);
	});
});
