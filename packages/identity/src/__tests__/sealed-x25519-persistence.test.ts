/**
 * sealed-x25519-persistence.test.ts — T0.5b
 *
 * The sealed-messaging X25519 scalar must SURVIVE a page reload.
 *
 * Why this is the invariant and not a nicety: a peer encrypts to this public
 * key. When it was generated per session (a WeakMap in x25519-identity.ts),
 * every reload produced a different key, so anything sealed to the previous one
 * became permanently unreadable, every peer saw a TOFU fingerprint change, and
 * publishing it to the server's registry would have tripped the 1-rotation/hour
 * throttle on every load. That is why sealed 1:1 messaging could never be
 * enrolled at all — the production registry held 0 rows.
 *
 * "Reload" is modelled the way the sibling suite models it: drop the module
 * cache (vi.resetModules) while KEEPING the IDB contents. A test that also
 * reset IDB would pass against a purely in-memory implementation and prove
 * nothing.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { createIdbStore } from '../idb-store.js';

/** Pinned literal — renaming this after the first user strands their key. */
const SEALED_KEY_STORAGE_NAME = 'x25519-sealed-v1';

type DeviceIdentityModule = typeof import('../device-identity.js');
type X25519IdentityModule = typeof import('../x25519-identity.js');

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

/** A page reload: module state gone, IDB retained. */
async function reload(): Promise<{
	device: DeviceIdentityModule;
	x25519Id: X25519IdentityModule;
}> {
	const { vi } = await import('vitest');
	vi.resetModules();
	return {
		device: (await import('../device-identity.js')) as DeviceIdentityModule,
		x25519Id: (await import('../x25519-identity.js')) as X25519IdentityModule,
	};
}

/** The live identity's publicKeyB64 — the owner the stored scalar is bound to. */
async function ownerOf(device: DeviceIdentityModule): Promise<string> {
	return (await device.getOrCreateDeviceIdentity()).publicKeyB64;
}

function hex(b: Uint8Array): string {
	return Array.from(b)
		.map((x) => x.toString(16).padStart(2, '0'))
		.join('');
}

beforeEach(() => resetIDB());
afterEach(() => resetIDB());

describe('sealed X25519 secret persistence', () => {
	it('returns a 32-byte scalar', async () => {
		const { device } = await reload();
		const priv = await device.getOrCreateSealedX25519Secret(await ownerOf(device));
		expect(priv).toBeInstanceOf(Uint8Array);
		expect(priv.byteLength).toBe(32);
	});

	it('is idempotent within one session', async () => {
		const { device } = await reload();
		const a = await device.getOrCreateSealedX25519Secret(await ownerOf(device));
		const b = await device.getOrCreateSealedX25519Secret(await ownerOf(device));
		expect(hex(b)).toBe(hex(a));
	});

	// THE test. Without persistence this returns a different scalar and fails.
	it('SURVIVES a reload — same scalar after the module cache is dropped', async () => {
		const first = await reload();
		const before = hex(await first.device.getOrCreateSealedX25519Secret(await ownerOf(first.device)));

		const second = await reload();
		const after = hex(await second.device.getOrCreateSealedX25519Secret(await ownerOf(second.device)));

		expect(after).toBe(before);
	});

	it('the PUBLIC key a peer encrypts to is stable across reloads', async () => {
		const first = await reload();
		const pubBefore = hex(x25519.getPublicKey(await first.device.getOrCreateSealedX25519Secret(await ownerOf(first.device))));

		const second = await reload();
		const pubAfter = hex(x25519.getPublicKey(await second.device.getOrCreateSealedX25519Secret(await ownerOf(second.device))));

		expect(pubAfter).toBe(pubBefore);
	});

	it('a message sealed before a reload is still decryptable after it', async () => {
		// The consequence the invariant exists for, exercised as raw DH: a
		// sender derives a shared secret from our published public key, and we
		// must still derive the same one in the next session.
		const first = await reload();
		const ourPubBefore = x25519.getPublicKey(
			await first.device.getOrCreateSealedX25519Secret(await ownerOf(first.device)),
		);
		const senderSk = x25519.utils.randomSecretKey();
		const senderView = hex(x25519.getSharedSecret(senderSk, ourPubBefore));

		const second = await reload();
		const ourPrivAfter = await second.device.getOrCreateSealedX25519Secret(await ownerOf(second.device));
		const ourView = hex(x25519.getSharedSecret(ourPrivAfter, x25519.getPublicKey(senderSk)));

		expect(ourView).toBe(senderView);
	});

	it('clearDeviceIdentity REMOVES the stored entry, not just its readability', async () => {
		// "A different key comes back" is NOT this assertion. clearDeviceIdentity
		// also drops the wrapping key, so the old ciphertext becomes unreadable
		// and a fresh scalar is generated whether or not the entry itself was
		// deleted — a mutation removing the delete left that version of this test
		// green. Read the raw row instead: an orphaned wrapped secret sitting in
		// IDB after the user asked to be forgotten is exactly what "forget" is
		// supposed to mean.
		const first = await reload();
		const before = hex(await first.device.getOrCreateSealedX25519Secret(await ownerOf(first.device)));

		const store = createIdbStore({
			dbName: first.device.IDB_DB_NAME,
			storeName: first.device.IDB_STORE_NAME,
		});
		// Storage name is pinned here on purpose: renaming it after the first
		// user strands their key, so the literal belongs in a test.
		expect(await store.load(SEALED_KEY_STORAGE_NAME)).toBeTruthy();

		await first.device.clearDeviceIdentity();
		expect(await store.load(SEALED_KEY_STORAGE_NAME)).toBeFalsy();

		const second = await reload();
		const after = hex(await second.device.getOrCreateSealedX25519Secret(await ownerOf(second.device)));
		expect(after).not.toBe(before);
	});

	it('does NOT survive replaceDeviceIdentity — it belongs to the retired identity', async () => {
		// The subtle case: self_sig is recomputed from whichever seed is current,
		// so a carried-over key would still verify and nothing would look broken.
		// It would simply follow the user across the identity change it was meant
		// to be severed by, while peers hold that public key pinned against the
		// OLD user_id.
		if (!ed25519Supported) return;

		const first = await reload();
		await first.device.getOrCreateDeviceIdentity();
		const before = hex(await first.device.getOrCreateSealedX25519Secret(await ownerOf(first.device)));

		const newSeed = ed25519.utils.randomSecretKey();
		const newPub = ed25519.getPublicKey(newSeed);
		const b64u = (b: Uint8Array) =>
			btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		await first.device.replaceDeviceIdentity(newSeed, b64u(newPub));

		const second = await reload();
		const after = hex(await second.device.getOrCreateSealedX25519Secret(await ownerOf(second.device)));

		expect(after).not.toBe(before);
	});

	it('is a DIFFERENT key from the Noise static keypair', async () => {
		// Cross-protocol static-DH reuse is a question this codebase should not
		// have to answer; the two keys are separate by construction.
		if (!ed25519Supported) return;
		const { device } = await reload();
		const sealed = x25519.getPublicKey(await device.getOrCreateSealedX25519Secret(await ownerOf(device)));
		const noise = (await device.getOrCreateX25519Keypair()).publicKey;
		expect(hex(sealed)).not.toBe(hex(noise));
	});

	it('does not disturb the Noise keypair across a reload', async () => {
		// The Noise key's own recovery path exists precisely so it is NOT
		// regenerated (it would break TOFU with every peer). Adding a second
		// stored key must not perturb it.
		if (!ed25519Supported) return;
		const first = await reload();
		const noiseBefore = hex((await first.device.getOrCreateX25519Keypair()).publicKey);
		await first.device.getOrCreateSealedX25519Secret(await ownerOf(first.device));

		const second = await reload();
		await second.device.getOrCreateSealedX25519Secret(await ownerOf(second.device));
		const noiseAfter = hex((await second.device.getOrCreateX25519Keypair()).publicKey);

		expect(noiseAfter).toBe(noiseBefore);
	});
});

describe('the owner binding is what makes wipe-completeness fail-safe', () => {
	// Three explicit deletes are three places to remember. A carried-over key
	// does NOT fail loudly — self_sig is recomputed from whichever seed is
	// current, so the binding still verifies and the key simply outlives the
	// identity that owned it. These cases assert the property at the point of
	// USE, which holds no matter which route left the row behind.

	it('a row belonging to another identity is replaced, not used', async () => {
		if (!ed25519Supported) return;

		const first = await reload();
		const id1 = await first.device.getOrCreateDeviceIdentity();
		const before = hex(await first.device.getOrCreateSealedX25519Secret(id1.publicKeyB64));

		// A DIFFERENT identity asks for its scalar while that row is still there.
		const second = await reload();
		const otherOwner = 'a'.repeat(43);
		const after = hex(await second.device.getOrCreateSealedX25519Secret(otherOwner));

		expect(after).not.toBe(before);
	});

	it('generateDeviceIdentity leaves a row behind, and it is not served', async () => {
		// generateDeviceIdentity is exported and wipes nothing — a consumer
		// calling it to "start fresh" would, without the owner check, be handed
		// the previous identity's decryption key.
		if (!ed25519Supported) return;

		const first = await reload();
		const id1 = await first.device.getOrCreateDeviceIdentity();
		const before = hex(await first.device.getOrCreateSealedX25519Secret(id1.publicKeyB64));

		const fresh = await first.device.generateDeviceIdentity();
		const after = hex(await first.device.getOrCreateSealedX25519Secret(fresh.publicKeyB64));

		expect(after).not.toBe(before);
	});

	it('an untagged legacy row is replaced rather than trusted', async () => {
		// Rows written before the discriminator existed carry no `kind`. One KEK
		// wraps the Ed25519 seed, the Noise scalar and this one — all 32 bytes —
		// so nothing about length could catch a crossed row.
		const store = createIdbStore({ dbName: 'oxpulse-device-id', storeName: 'identity' });
		const first = await reload();
		const id1 = await first.device.getOrCreateDeviceIdentity();
		const before = hex(await first.device.getOrCreateSealedX25519Secret(id1.publicKeyB64));

		const row = (await store.load(SEALED_KEY_STORAGE_NAME)) as Record<string, unknown>;
		delete row.kind;
		await store.save(SEALED_KEY_STORAGE_NAME, row);

		const second = await reload();
		const after = hex(await second.device.getOrCreateSealedX25519Secret(id1.publicKeyB64));

		expect(after).not.toBe(before);
	});
});

describe('concurrency', () => {
	// HONEST SCOPE: this asserts the observable outcome, and it does NOT gate the
	// in-flight dedup. Removing the dedup leaves it green, because these racers
	// converge for a second reason — they await the wrapping key first, so by the
	// time the later ones reach `idb.load` the first has usually already written,
	// and they read its row instead of minting. The dedup closes the window that
	// remains when that ordering does not hold (a slower write, a real Web Lock
	// across tabs), which single-process fake-indexeddb cannot reproduce on
	// demand. Kept because the outcome is worth pinning; not claimed as the gate.
	// Three racers, not two, and the assertion is on OBJECT IDENTITY.
	//
	// sealedX25519Inner produces exactly one copy. The owning caller slices it
	// again, so with only two racers the deduped one could return the inner
	// buffer unsliced and the two would still be distinct objects — the defect
	// hides. With three, both deduped callers would receive the SAME instance,
	// and a consumer zeroizing either would kill the other.
	it('every concurrent caller gets its own buffer holding the same scalar', async () => {
		if (!ed25519Supported) return;

		const { device } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();
		const owner = identity.publicKeyB64;

		let parked!: () => void;
		const atSeam = new Promise<void>((r) => {
			parked = r;
		});
		let release!: () => void;
		const go = new Promise<void>((r) => {
			release = r;
		});
		let arrived = 0;
		device.__sealedTestHooks.betweenLoadAndSave = async () => {
			// Only the first parks. Release must NOT depend on another racer
			// arriving — with the dedup live none ever does, and an earlier
			// version of this test deadlocked on exactly that assumption.
			if (++arrived === 1) {
				parked();
				await go;
			}
		};

		try {
			const p1 = device.getOrCreateSealedX25519Secret(owner);
			await atSeam; // p1 is between its read and its write

			const p2 = device.getOrCreateSealedX25519Secret(owner);
			const p3 = device.getOrCreateSealedX25519Secret(owner);
			await new Promise((r) => setTimeout(r, 50));
			release();

			const [a, b, c] = await Promise.all([p1, p2, p3]);

			expect(hex(b)).toBe(hex(a));
			expect(hex(c)).toBe(hex(a));
			expect(b).not.toBe(a);
			expect(c).not.toBe(a);
			expect(c).not.toBe(b); // the assertion the third racer exists for
		} finally {
			device.__sealedTestHooks.betweenLoadAndSave = null;
			release();
		}
	});

	// HONEST SCOPE — measured, not assumed. Removing the in-flight dedup does
	// NOT turn either concurrency test red in this environment. The seam above
	// was added to force the interleaving and it still does not fire: racers
	// reaching `getOrCreateSealedX25519Secret` while another is parked at the
	// seam never arrive there themselves, so something upstream of it (the
	// wrapping-key read and the IDB store's own request ordering) already
	// serializes them under fake-indexeddb. The dedup's real job is cross-TAB
	// serialization via Web Locks, and `navigator.locks` does not exist under
	// vitest's node environment, so `withIdentityLock` falls through to a direct
	// call in every test here. That half of the fix is untested and untestable
	// in this suite — a green run says nothing about it.
	it('two concurrent callers get ONE scalar and leave ONE row', async () => {
		if (!ed25519Supported) return;

		const { device } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();

		const [a, b, c] = await Promise.all([
			device.getOrCreateSealedX25519Secret(identity.publicKeyB64),
			device.getOrCreateSealedX25519Secret(identity.publicKeyB64),
			device.getOrCreateSealedX25519Secret(identity.publicKeyB64),
		]);

		expect(hex(b)).toBe(hex(a));
		expect(hex(c)).toBe(hex(a));

		// And the persisted row is the one they all hold.
		const reloaded = await reload();
		const onDisk = hex(await reloaded.device.getOrCreateSealedX25519Secret(identity.publicKeyB64));
		expect(onDisk).toBe(hex(a));
	});

	it('returns a COPY — a caller zeroizing its buffer cannot corrupt the session key', async () => {
		// The value is public API (X25519Identity.priv). A consumer that wipes it
		// after use — ordinary hygiene — must not corrupt the cached scalar: the
		// next derivation would produce a DIFFERENT public key and sign that one,
		// while IDB and the server's registry still hold the original. Silently.
		//
		// Both return paths are exercised: the first call misses the cache and
		// returns from the store, the second and third are cache hits. Zeroing
		// after each is what makes a shared reference on EITHER path show up.
		if (!ed25519Supported) return;
		const { device } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();

		const first = await device.getOrCreateSealedX25519Secret(identity.publicKeyB64);
		const original = hex(first);
		expect(original).not.toBe('00'.repeat(32));
		first.fill(0);

		const second = await device.getOrCreateSealedX25519Secret(identity.publicKeyB64);
		expect(hex(second)).toBe(original);
		second.fill(0);

		const third = await device.getOrCreateSealedX25519Secret(identity.publicKeyB64);
		expect(hex(third)).toBe(original);

		// And the durable copy is untouched by any of it.
		const reloaded = await reload();
		expect(hex(await reloaded.device.getOrCreateSealedX25519Secret(identity.publicKeyB64))).toBe(
			original,
		);
	});
});

describe('getOrCreateX25519Identity uses the persisted scalar', () => {
	it('a wipe landing MID-FLIGHT does not get memoised as current', async () => {
		// The epoch must be sampled at ENTRY, not at write time. Sampling at the
		// write means a wipe arriving during the await bumps it first, and the
		// retired key is then stored under the POST-wipe epoch — matching every
		// later call, served from memory, never reaching the owner check in IDB.
		// clearDeviceIdentity takes no lock, so it interleaves freely, and it is
		// the one operation where a surviving key is the worst outcome.
		if (!ed25519Supported) return;

		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();

		let parked!: () => void;
		const atSeam = new Promise<void>((r) => {
			parked = r;
		});
		let release!: () => void;
		const go = new Promise<void>((r) => {
			release = r;
		});
		let fired = false;
		device.__sealedTestHooks.betweenLoadAndSave = async () => {
			if (fired) return;
			fired = true;
			parked();
			await go;
		};

		try {
			const inFlight = x25519Id.getOrCreateX25519Identity(identity);
			await atSeam;

			// The wipe lands while the sealed mint is parked.
			await device.clearDeviceIdentity();
			release();
			const during = await inFlight;

			// The discriminating question is whether that value was MEMOISED, not
			// what it was. Comparing the two calls directly cannot answer it: the
			// parked mint writes its row after the wipe, tagged with this same
			// (retired) identity, so a re-read legitimately returns the same key.
			// Remove the row instead — then a call that re-enters the store mints
			// a fresh scalar, while a call answered from the memo does not.
			const store = createIdbStore({
				dbName: device.IDB_DB_NAME,
				storeName: device.IDB_STORE_NAME,
			});
			await store.delete(SEALED_KEY_STORAGE_NAME);

			const after = await x25519Id.getOrCreateX25519Identity(identity);
			expect(hex(after.pub)).not.toBe(hex(during.pub));
		} finally {
			device.__sealedTestHooks.betweenLoadAndSave = null;
			release();
		}
	});

	it('a wipe during the READ path does not repopulate the cache either', async () => {
		// Sibling of the mid-flight-mint case, on the branch that runs every
		// session for every existing key — so it is the MORE reachable of the
		// two, not less. The unwrap still succeeds after clearDeviceIdentity
		// because the wrapping-key handle is already resolved in memory.
		if (!ed25519Supported) return;

		// Session 1 persists a key so session 2 takes the read branch.
		const first = await reload();
		const id1 = await first.device.getOrCreateDeviceIdentity();
		const owner = id1.publicKeyB64;
		const before = hex(await first.device.getOrCreateSealedX25519Secret(owner));

		const second = await reload();
		await second.device.getOrCreateDeviceIdentity();

		let parked!: () => void;
		const atSeam = new Promise<void>((r) => {
			parked = r;
		});
		let release!: () => void;
		const go = new Promise<void>((r) => {
			release = r;
		});
		let fired = false;
		second.device.__sealedTestHooks.betweenLoadAndSave = async () => {
			if (fired) return;
			fired = true;
			parked();
			await go;
		};

		try {
			const inFlight = second.device.getOrCreateSealedX25519Secret(owner);
			await atSeam;

			await second.device.clearDeviceIdentity();
			release();
			await inFlight;

			// The cache must not now answer for the retired owner.
			const after = hex(await second.device.getOrCreateSealedX25519Secret(owner));
			expect(after).not.toBe(before);
		} finally {
			second.device.__sealedTestHooks.betweenLoadAndSave = null;
			release();
		}
	});

	it('does not serve a retired identity from the in-memory memo', async () => {
		// The memo is keyed by the DeviceIdentity OBJECT. A caller still holding
		// the retired reference would otherwise be handed that identity's sealed
		// key from memory, after the wipe, without an IDB read.
		if (!ed25519Supported) return;

		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();
		const before = await x25519Id.getOrCreateX25519Identity(identity);

		await device.clearDeviceIdentity();

		const after = await x25519Id.getOrCreateX25519Identity(identity);
		expect(hex(after.pub)).not.toBe(hex(before.pub));
	});

	it('reports the same public key and self_sig across reloads', async () => {
		if (!ed25519Supported) return;

		const first = await reload();
		const id1 = await first.device.getOrCreateDeviceIdentity();
		const before = await first.x25519Id.getOrCreateX25519Identity(id1);

		const second = await reload();
		const id2 = await second.device.getOrCreateDeviceIdentity();
		const after = await second.x25519Id.getOrCreateX25519Identity(id2);

		expect(hex(after.pub)).toBe(hex(before.pub));
		// Ed25519 is deterministic, so a recomputed self_sig is byte-identical.
		expect(hex(after.selfSig)).toBe(hex(before.selfSig));
	});

	it('produces a self_sig that verifies against the device identity', async () => {
		if (!ed25519Supported) return;

		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();
		const sealed = await x25519Id.getOrCreateX25519Identity(identity);

		const edPub = ed25519.getPublicKey(identity.privateKeySeed!.bytes());
		expect(x25519Id.verifyX25519SelfSig(sealed.pub, sealed.selfSig, edPub)).toBe(true);
	});

	it('pub is the public key of priv', async () => {
		if (!ed25519Supported) return;
		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();
		const sealed = await x25519Id.getOrCreateX25519Identity(identity);
		expect(hex(sealed.pub)).toBe(hex(x25519.getPublicKey(sealed.priv)));
	});

	// Both hand-out paths, separately. The memo holds ONE X25519Identity object;
	// handing out that reference means a consumer wiping its own copy silently
	// leaves the memo holding 32 zero bytes while pub/selfSig still describe the
	// original key — every later DH in the session is then wrong, and nothing
	// anywhere reports it. One probe covering only one path survives a mutation
	// of the other, which is why these are two tests and not one.
	it('zeroizing the priv from the MINTING call does not poison the memo', async () => {
		if (!ed25519Supported) return;
		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();

		const minted = await x25519Id.getOrCreateX25519Identity(identity);
		const expected = hex(minted.priv);
		minted.priv.fill(0); // ordinary secret hygiene by a well-behaved consumer

		const later = await x25519Id.getOrCreateX25519Identity(identity);
		expect(hex(later.priv)).toBe(expected);
		expect(hex(later.pub)).toBe(hex(x25519.getPublicKey(later.priv)));
	});

	it('zeroizing the priv from a MEMO-HIT call does not poison the memo', async () => {
		if (!ed25519Supported) return;
		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();

		const minted = await x25519Id.getOrCreateX25519Identity(identity);
		const expected = hex(minted.priv);

		const hit = await x25519Id.getOrCreateX25519Identity(identity); // memo hit
		hit.priv.fill(0);

		const later = await x25519Id.getOrCreateX25519Identity(identity);
		expect(hex(later.priv)).toBe(expected);
		expect(hex(later.pub)).toBe(hex(x25519.getPublicKey(later.priv)));
	});
});

/**
 * Runtimes with no working IndexedDB — Instagram/TikTok in-app WebViews, some
 * private modes.
 *
 * The Ed25519 paths in this package degrade to an ephemeral in-memory identity
 * there, so the SPA still boots. This key must NOT follow that pattern: it
 * exists to be published so a peer can seal to it, and a key that dies at reload
 * is worse in the registry than no key at all — messages sealed to it are
 * permanently unreadable, the server throttles the correcting publish to 1/hour,
 * and every peer's TOFU fingerprint churns on each load.
 *
 * So the contract is a typed refusal, and what these pin is that there is no
 * value for a caller to publish by accident.
 */
describe('sealed X25519 secret when IndexedDB is unavailable', () => {
	let realIDB: IDBFactory | undefined;

	beforeEach(() => {
		realIDB = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
		delete (globalThis as { indexedDB?: IDBFactory }).indexedDB;
	});

	afterEach(() => {
		(globalThis as { indexedDB?: IDBFactory }).indexedDB = realIDB;
	});

	it('refuses with SealedKeyUnavailableError rather than returning a scalar', async () => {
		const { device } = await reload();
		// The Ed25519 identity still resolves — it degrades to ephemeral by
		// design, which is what makes this a test of the sealed key alone.
		const owner = await ownerOf(device);

		await expect(device.getOrCreateSealedX25519Secret(owner)).rejects.toBeInstanceOf(
			device.SealedKeyUnavailableError,
		);
	});

	it('names the reason so an operator can tell absent IDB from a full quota', async () => {
		const { device } = await reload();
		const owner = await ownerOf(device);

		await expect(device.getOrCreateSealedX25519Secret(owner)).rejects.toMatchObject({
			name: 'SealedKeyUnavailableError',
			reason: 'no_indexedDB',
		});
	});

	// The public entry point is what enrollment calls, so the refusal has to
	// survive the trip through it — a catch anywhere in between that substituted
	// a fresh keypair would put an unpersisted key back on the publish path.
	it('propagates through getOrCreateX25519Identity — no substituted keypair', async () => {
		if (!ed25519Supported) return;
		const { device, x25519Id } = await reload();
		const identity = await device.getOrCreateDeviceIdentity();

		await expect(x25519Id.getOrCreateX25519Identity(identity)).rejects.toBeInstanceOf(
			device.SealedKeyUnavailableError,
		);
	});

	it('a quota-exhausted store refuses too, and says so', async () => {
		// Quota is a DISTINCT failure from absent IDB: the store opens fine, then
		// the write fails — so absent-IDB coverage says nothing about it. The two
		// map to different reasons precisely so an operator can tell an in-app
		// WebView from a device that has run out of room.
		//
		// fake-indexeddb has no quota to exhaust, so the fault is injected at the
		// store boundary — the same seam device-identity.ts reads. Scoped with
		// doMock/doUnmock rather than a file-level vi.mock, which would replace
		// the real store for the ~20 persistence tests above that depend on it.
		const { vi } = await import('vitest');
		(globalThis as { indexedDB?: IDBFactory }).indexedDB = realIDB; // IDB works; the ROOM is what is gone

		vi.resetModules();
		vi.doMock('../idb-store.js', async () => {
			const actual =
				await vi.importActual<typeof import('../idb-store.js')>('../idb-store.js');
			return {
				...actual,
				createIdbStore: (opts: Parameters<typeof actual.createIdbStore>[0]) => {
					const real = actual.createIdbStore(opts);
					return {
						...real,
						save: async () => {
							throw Object.assign(new Error('no room'), {
								name: 'QuotaExceededError',
							});
						},
					};
				},
			};
		});

		try {
			const device = (await import('../device-identity.js')) as DeviceIdentityModule;
			// Degrades to an ephemeral identity on the same quota fault, by design
			// — which is exactly the asymmetry under test: it still returns, and
			// the sealed key still must not.
			const owner = (await device.getOrCreateDeviceIdentity()).publicKeyB64;

			await expect(device.getOrCreateSealedX25519Secret(owner)).rejects.toMatchObject({
				name: 'SealedKeyUnavailableError',
				reason: 'quota_exceeded',
			});
		} finally {
			vi.doUnmock('../idb-store.js');
			vi.resetModules();
		}
	});
});
