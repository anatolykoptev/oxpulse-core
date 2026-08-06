// raw-export-audit.test.ts — every exportRawDeviceSecret call leaves a record (#103).
//
// The function has TWO success paths (WebCrypto PKCS8, and the noble-only raw-seed
// fallback for runtimes without WebCrypto Ed25519) plus a failure path. All three
// must emit, which is why the emit lives in a wrapper rather than at each return —
// a hand-placed emit is exactly what a new return statement escapes.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';

type Ev = { event: string; payload?: Record<string, unknown> };

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

async function loadWithTracker(): Promise<{
	mod: typeof import('../device-identity.js');
	events: Ev[];
}> {
	vi.resetModules();
	const shim = await import('../tracker-shim.js');
	const events: Ev[] = [];
	shim.setIdentityTracker((event, _roomId, payload) => events.push({ event, payload }));
	const mod = (await import('../device-identity.js')) as typeof import('../device-identity.js');
	return { mod, events };
}

const AUDIT = 'client.identity_raw_export';

beforeEach(() => { resetIDB(); });
afterEach(() => { resetIDB(); vi.restoreAllMocks(); });

describe('exportRawDeviceSecret audit (#103)', () => {
	it('emits on the WebCrypto success path', async () => {
		const { mod, events } = await loadWithTracker();
		await mod.getOrCreateDeviceIdentity();

		const before = events.filter((e) => e.event === AUDIT).length;
		const { secret } = await mod.exportRawDeviceSecret();
		expect(secret.byteLength).toBe(32);

		const audits = events.filter((e) => e.event === AUDIT);
		expect(audits.length).toBe(before + 1);
		expect(audits.at(-1)!.payload?.outcome).toBe('ok');
	}, 30_000);

	it('emits on the NOBLE-ONLY success path', async () => {
		// Runtimes without WebCrypto Ed25519 (HyperOS/HarmonyOS) store a
		// zero-length wrappedPrivateKey and export via the raw-seed fallback —
		// a different return statement, and the one a per-return emit would miss.
		const { mod, events } = await loadWithTracker();
		await mod.getOrCreateDeviceIdentity();

		// Force the fallback by blanking the PKCS8 wrap, the way a noble-only
		// runtime leaves it.
		const idb = await import('../idb-store.js');
		const store = idb.createIdbStore({ dbName: 'oxpulse-device-id', storeName: 'identity' });
		const stored = await store.load<{ publicKeyB64: string; wrappedPrivateKey: ArrayBuffer }>(
			'device-key',
		);
		expect(stored).not.toBeNull();
		await store.save('device-key', {
			publicKeyB64: stored!.publicKeyB64,
			wrappedPrivateKey: new ArrayBuffer(0),
		});

		const before = events.filter((e) => e.event === AUDIT).length;
		const { secret } = await mod.exportRawDeviceSecret();
		expect(secret.byteLength).toBe(32);

		const audits = events.filter((e) => e.event === AUDIT);
		expect(audits.length).toBe(before + 1);
		expect(audits.at(-1)!.payload?.outcome).toBe('ok');
	}, 30_000);

	it('emits on FAILURE and rethrows', async () => {
		// A failed export is signal: repeated failures are what probing looks
		// like, and swallowing them is what an attacker would prefer.
		const { mod, events } = await loadWithTracker();

		const before = events.filter((e) => e.event === AUDIT).length;
		await expect(mod.exportRawDeviceSecret()).rejects.toThrow();

		const audits = events.filter((e) => e.event === AUDIT);
		expect(audits.length).toBe(before + 1);
		expect(audits.at(-1)!.payload?.outcome).toBe('error');
	}, 30_000);

	it('reports a MISSING identity as a data failure, not an Ed25519 capability failure', async () => {
		// classifyIdentityError sniffs the message for /Ed25519/i to catch
		// WebCrypto's "Ed25519 is not supported". Two of this file's own error
		// messages contain the word Ed25519 while meaning the opposite — a
		// missing entry and a corrupt one — so both were reported as
		// ed25519_unsupported. An operator investigating a spike of "this
		// runtime cannot do Ed25519" would have found data corruption in it.
		const { mod, events } = await loadWithTracker();

		await expect(mod.exportRawDeviceSecret()).rejects.toThrow(/No device identity in IDB/);

		const audit = events.filter((e) => e.event === AUDIT).at(-1)!;
		expect(audit.payload?.error_class).toBe('unwrap_failed');
	}, 30_000);

	it('reports a MISSING raw seed on the noble-only path as a data failure', async () => {
		// "No Ed25519 private key in IDB (noble-only identity, no raw seed
		// stored)" — the message that most obviously trips the regex.
		const { mod, events } = await loadWithTracker();
		await mod.getOrCreateDeviceIdentity();

		const idb = await import('../idb-store.js');
		const store = idb.createIdbStore({ dbName: 'oxpulse-device-id', storeName: 'identity' });
		const stored = await store.load<{ publicKeyB64: string; wrappedPrivateKey: ArrayBuffer }>(
			'device-key',
		);
		// Blank the PKCS8 wrap to force the noble-only branch, and delete the raw
		// seed it falls back to.
		await store.save('device-key', {
			publicKeyB64: stored!.publicKeyB64,
			wrappedPrivateKey: new ArrayBuffer(0),
		});
		await store.delete('oxp/identity/ed25519-priv-raw');

		await expect(mod.exportRawDeviceSecret()).rejects.toThrow(/No Ed25519 private key/);

		const audit = events.filter((e) => e.event === AUDIT).at(-1)!;
		expect(audit.payload?.error_class).toBe('unwrap_failed');
	}, 30_000);

	it('throws IdentityDataError, which is exported for callers to discriminate on', async () => {
		// The classification test above cannot tell a typed throw from a plain
		// one here — "No device identity in IDB" contains no "Ed25519", so both
		// spellings report unwrap_failed. Measured: untyping that throw survives
		// the whole suite.
		//
		// What IS observable is the type. IdentityDataError is exported from
		// index.ts precisely so a consumer can tell "your stored data is missing
		// or corrupt" from "this runtime cannot do Ed25519" without parsing a
		// message string — which is the same mistake classifyIdentityError makes
		// internally and that this class exists to stop spreading.
		const { mod } = await loadWithTracker();
		const index = await import('../index.js');

		await expect(mod.exportRawDeviceSecret()).rejects.toBeInstanceOf(
			(index as unknown as { IdentityDataError: new (m: string) => Error }).IdentityDataError,
		);
	}, 30_000);

	it('records a plausible duration', async () => {
		// Without this, duration_ms could be hardcoded to 0 and every test still
		// passes — measured, that mutation survived the first version of this file.
		const { mod, events } = await loadWithTracker();
		await mod.getOrCreateDeviceIdentity();
		await mod.exportRawDeviceSecret();

		const audit = events.filter((e) => e.event === AUDIT).at(-1)!;
		const ms = audit.payload?.duration_ms;
		expect(typeof ms).toBe('number');
		expect(ms as number).toBeGreaterThan(0);
		// An export is sub-second work; a wildly large value means the clock
		// source is wrong rather than the export being slow.
		expect(ms as number).toBeLessThan(30_000);
	}, 30_000);

	it('never puts key material in the payload', async () => {
		const { mod, events } = await loadWithTracker();
		await mod.getOrCreateDeviceIdentity();
		const { secret } = await mod.exportRawDeviceSecret();

		const audit = events.filter((e) => e.event === AUDIT).at(-1)!;
		const serialised = JSON.stringify(audit.payload ?? {});

		// The seed must not appear in any encoding a payload could carry it in.
		const hex = Array.from(secret).map((b) => b.toString(16).padStart(2, '0')).join('');
		const b64 = Buffer.from(secret).toString('base64');
		expect(serialised).not.toContain(hex);
		expect(serialised).not.toContain(b64);
		expect(serialised).not.toContain(Array.from(secret).join(','));

		// And the payload should be small metadata, not a smuggled object.
		expect(Object.keys(audit.payload ?? {}).sort()).toEqual(['duration_ms', 'outcome']);
	}, 30_000);
});
