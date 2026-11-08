/**
 * history-keyring.test.ts — decrypt-only history keys: import, export, read-time
 * validation, and the lifecycle wipe.
 *
 * Why this is its own suite and what it must NOT do: a missing wipe or a missing
 * check is SILENT. Reads are owner-tagged and re-proven, so "history reads empty
 * after the owner changed" stays green with the wipe deleted — which is why the
 * lifecycle tests assert on the RAW rows in IndexedDB, loaded through a second
 * store handle, not on what the read API returns.
 *
 * No secret hex is ever compared with toBe/toEqual: a RED run prints the diff,
 * and that would put key material in a log. Comparisons use booleans or public
 * keys.
 *
 * "Reload" = drop the module cache, keep IDB (same model as the sibling suites).
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { createIdbStore, type IdbTxOp } from '../idb-store.js';

type Device = typeof import('../device-identity.js');

const HISTORY_PREFIX = 'x25519-history-v1/';
const MARKER = 'x25519-history-wipe-pending-v1';
const SEALED = 'x25519-sealed-v1';
const raw = createIdbStore({ dbName: 'oxpulse-device-id', storeName: 'identity' });

let ed25519Supported = false;
beforeAll(async () => {
	try {
		await crypto.subtle.generateKey({ name: 'Ed25519' } as unknown as AlgorithmIdentifier, false, ['sign', 'verify']);
		ed25519Supported = true;
	} catch {
		ed25519Supported = false;
	}
});

const b64u = (b: Uint8Array) =>
	btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (s: string) => Uint8Array.from(Buffer.from(s, 'base64url'));
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}
beforeEach(() => resetIDB());
afterEach(() => {
	resetIDB();
	vi.doUnmock('../idb-store.js');
	vi.doUnmock('../history-keys.js');
	vi.resetModules();
});

function pair() {
	const kp = x25519.keygen();
	return { pubB64u: b64u(kp.publicKey), secretB64u: b64u(kp.secretKey), pub: kp.publicKey, secret: kp.secretKey };
}
type Pair = ReturnType<typeof pair>;
const wire = (p: Pair) => ({ pubB64u: p.pubB64u, secretB64u: p.secretB64u });

interface Faults {
	/** transact() carrying a deletePrefix op throws (the wipe). */
	failWipe: boolean;
	/** save() of the pending marker throws. */
	failMarker: boolean;
	/** the LAST op of every put-only transact() gets an uncloneable value. */
	poisonLastPut: boolean;
	/** collapse the routing address to 1 byte so collisions are findable. */
	weakAddress: boolean;
	/** one-shot: runs right after the next loadPrefix() returns (mid-read interleave). */
	afterLoadPrefix: null | (() => Promise<unknown>);
}

async function boot(f: Partial<Faults> = {}): Promise<{ device: Device; faults: Faults }> {
	const faults: Faults = { failWipe: false, failMarker: false, poisonLastPut: false, weakAddress: false, afterLoadPrefix: null, ...f };
	vi.resetModules();
	vi.doMock('../idb-store.js', async () => {
		const actual = await vi.importActual<typeof import('../idb-store.js')>('../idb-store.js');
		return {
			...actual,
			createIdbStore: (opts: Parameters<typeof actual.createIdbStore>[0]) => {
				const real = actual.createIdbStore(opts);
				return {
					...real,
					loadPrefix: async <T,>(prefix: string, limit?: number) => {
						const out = await real.loadPrefix<T>(prefix, limit);
						if (faults.afterLoadPrefix) {
							const fire = faults.afterLoadPrefix;
							faults.afterLoadPrefix = null;
							await fire();
						}
						return out;
					},
					transact: async (ops: ReadonlyArray<IdbTxOp>, guard?: { prefix: string; max: number }) => {
						if (faults.failWipe && ops.some((o) => o.op === 'deletePrefix')) {
							throw new DOMException('injected wipe fault', 'UnknownError');
						}
						if (faults.poisonLastPut && ops.length > 0 && ops.every((o) => o.op === 'put')) {
							const copy = [...ops];
							const last = copy[copy.length - 1] as Extract<IdbTxOp, { op: 'put' }>;
							copy[copy.length - 1] = { op: 'put', key: last.key, value: () => 'uncloneable' };
							return real.transact(copy, guard);
						}
						return real.transact(ops, guard);
					},
					save: async <T,>(key: string, value: T) => {
						if (faults.failMarker && key === MARKER) throw new DOMException('injected marker fault', 'UnknownError');
						return real.save(key, value);
					},
				};
			},
		};
	});
	vi.doMock('../history-keys.js', async () => {
		const actual = await vi.importActual<typeof import('../history-keys.js')>('../history-keys.js');
		return {
			...actual,
			derivePeerAddress: async (pub: Uint8Array) => {
				const a = await actual.derivePeerAddress(pub);
				if (!faults.weakAddress) return a;
				const o = new Uint8Array(8);
				o[0] = a[0] ?? 0;
				return o;
			},
		};
	});
	const device = (await import('../device-identity.js')) as Device;
	return { device, faults };
}

async function rows(): Promise<Array<{ key: string; value: Record<string, unknown> }>> {
	return raw.loadPrefix<Record<string, unknown>>(HISTORY_PREFIX);
}
const historyRowCount = async () => (await rows()).length;

async function liveOwner(device: Device): Promise<string> {
	return (await device.getOrCreateDeviceIdentity()).publicKeyB64;
}

/** A DIFFERENT identity, from a real Ed25519 pair. */
function otherIdentity() {
	const secret = ed25519.utils.randomSecretKey();
	return { secret, pub: b64u(ed25519.getPublicKey(secret)) };
}

describe('import + export round trip', () => {
	it('imported keys are exported with pubs derived independently from the secrets', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		const b = pair();
		const r = await device.importSealedHistoryKeys(owner, [wire(a), wire(b)], 'oxp');
		expect(r).toEqual({ status: 'ok', added: 2, alreadyHeld: 0 });

		const out = await device.exportSealedKeyring(owner);
		expect(out.status).toBe('ok');
		if (out.status !== 'ok') return;
		expect(out.current).toBeNull();
		const pubs = out.history.map((h) => h.pubB64u).sort();
		expect(pubs).toEqual([a.pubB64u, b.pubB64u].sort());
		for (const h of out.history) {
			// oracle: the library derives the pub from the exported secret
			expect(b64u(x25519.getPublicKey(fromB64u(h.secretB64u))) === h.pubB64u).toBe(true);
		}
	});

	it('survives a reload (rows are durable, not memoised)', async () => {
		if (!ed25519Supported) return;
		const first = await boot();
		const owner = await liveOwner(first.device);
		const a = pair();
		await first.device.importSealedHistoryKeys(owner, [wire(a)]);
		const second = await boot();
		const read = await second.device.readHistoryKeys(owner);
		expect(read.status).toBe('ok');
		if (read.status !== 'ok') return;
		expect(read.keys.map((k) => k.pubB64u)).toEqual([a.pubB64u]);
		expect(read.keys[0]!.addrHex).toMatch(/^[0-9a-f]{16}$/);
	});

	it('export carries the CURRENT sealed key first, without minting one', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		// No sealed key minted yet and no history: absent, and still not minted.
		expect(await device.exportSealedKeyring(owner)).toEqual({ status: 'absent' });
		expect(await raw.load(SEALED)).toBeNull();

		const priv = await device.getOrCreateSealedX25519Secret(owner);
		const out = await device.exportSealedKeyring(owner);
		expect(out.status).toBe('ok');
		if (out.status !== 'ok') return;
		expect(out.current?.pubB64u).toBe(b64u(x25519.getPublicKey(priv)));
		expect(out.history).toEqual([]);
	});

	it('an absent keyring field is `absent`, not an error, and writes nothing', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		expect(await device.importSealedHistoryKeys(owner, undefined)).toEqual({ status: 'absent' });
		expect(await device.importSealedHistoryKeys(owner, null)).toEqual({ status: 'absent' });
		expect(await historyRowCount()).toBe(0);
	});

	it('is idempotent: a held key and the current key are no-ops', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		await device.importSealedHistoryKeys(owner, [wire(a)]);
		expect(await device.importSealedHistoryKeys(owner, [wire(a)])).toEqual({ status: 'ok', added: 0, alreadyHeld: 1 });

		// restoring your own backup onto the same device presents the current key
		const cur = await device.getOrCreateSealedX25519Secret(owner);
		const curWire = { pubB64u: b64u(x25519.getPublicKey(cur)), secretB64u: b64u(cur) };
		expect(await device.importSealedHistoryKeys(owner, [curWire])).toEqual({ status: 'ok', added: 0, alreadyHeld: 1 });
		expect(await historyRowCount()).toBe(1);
	});

	it('refuses an owner that is not the live identity', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		await liveOwner(device);
		const r = await device.importSealedHistoryKeys(otherIdentity().pub, [wire(pair())]);
		expect(r).toEqual({ status: 'invalid', reason: 'owner_mismatch' });
		expect(await historyRowCount()).toBe(0);
		expect((await device.exportSealedKeyring(otherIdentity().pub)).status).toBe('invalid');
	});
});

describe('import is strict, and rejection persists NOTHING', () => {
	const good = () => wire(pair());
	const cases: Array<[string, (g: ReturnType<typeof good>) => unknown, string]> = [
		['not an array', (g) => ({ 0: g }), 'not_array'],
		['extra field', (g) => [{ ...g, extra: 'x' }], 'bad_entry'],
		['missing field', (g) => [{ pubB64u: g.pubB64u }], 'bad_entry'],
		['padded base64url', (g) => [{ ...g, pubB64u: g.pubB64u + '=' }], 'bad_encoding'],
		['41-char secret', (g) => [{ ...g, secretB64u: g.secretB64u.slice(0, 41) }], 'bad_encoding'],
		['non-string pub', (g) => [{ ...g, pubB64u: 7 }], 'bad_encoding'],
		['65 entries (cap checked before decoding)', () => Array.from({ length: 65 }, () => 'garbage'), 'too_many'],
	];
	it.each(cases)('%s', async (_n, mutate, reason) => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		expect(await device.importSealedHistoryKeys(owner, mutate(good()))).toEqual({ status: 'invalid', reason });
		expect(await historyRowCount()).toBe(0);
	});

	it('rejects every small-order public key, including bit-255 variants', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const blocklist = [
			'0000000000000000000000000000000000000000000000000000000000000000',
			'0100000000000000000000000000000000000000000000000000000000000000',
			'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
			'5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
			'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
			'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
			'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
		];
		const secret = x25519.keygen().secretKey;
		for (const h of blocklist) {
			for (const hiBit of [false, true]) {
				const p = fromHex(h);
				if (hiBit) p[31] = (p[31] ?? 0) | 0x80;
				const r = await device.importSealedHistoryKeys(owner, [{ pubB64u: b64u(p), secretB64u: b64u(secret) }]);
				expect(r, `${h} hi=${hiBit}`).toEqual({ status: 'invalid', reason: 'small_order' });
			}
		}
		expect(await historyRowCount()).toBe(0);
	});

	it('requires X25519(secret) == pub', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		const b = pair();
		const r = await device.importSealedHistoryKeys(owner, [{ pubB64u: a.pubB64u, secretB64u: b.secretB64u }]);
		expect(r).toEqual({ status: 'invalid', reason: 'pair_mismatch' });
		expect(await historyRowCount()).toBe(0);
	});

	it('rejects an all-zero secret even though it derives a real public key', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const zero = new Uint8Array(32);
		const r = await device.importSealedHistoryKeys(owner, [{ pubB64u: b64u(x25519.getPublicKey(zero)), secretB64u: b64u(zero) }]);
		expect(r).toEqual({ status: 'invalid', reason: 'zero_secret' });
	});

	it('rejects a duplicate public key within the batch', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		expect(await device.importSealedHistoryKeys(owner, [wire(a), wire(a)])).toEqual({ status: 'invalid', reason: 'duplicate_pub' });
		expect(await historyRowCount()).toBe(0);
	});

	it('is atomic: a bad entry AFTER valid ones persists none of them', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		const b = pair();
		const bad = { pubB64u: pair().pubB64u, secretB64u: pair().secretB64u }; // mismatched
		const r = await device.importSealedHistoryKeys(owner, [wire(a), wire(b), bad]);
		expect(r.status).toBe('invalid');
		expect(await historyRowCount()).toBe(0);
	});

	it('is atomic against a storage fault mid-write: all rows land in ONE transaction or none do', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		faults.poisonLastPut = true; // the 3rd put cannot be cloned; puts 1-2 must roll back
		const r = await device.importSealedHistoryKeys(owner, [wire(pair()), wire(pair()), wire(pair())]);
		expect(r.status).toBe('storage_failure');
		expect(await historyRowCount()).toBe(0);
		// and the failure is typed, not a throw, and the store still works afterwards
		faults.poisonLastPut = false;
		expect((await device.importSealedHistoryKeys(owner, [wire(pair())])).status).toBe('ok');
		expect(await historyRowCount()).toBe(1);
	});

	it('caps total entries at 64 (held + new), without partial success', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const sixtyTwo = Array.from({ length: 62 }, () => wire(pair()));
		expect((await device.importSealedHistoryKeys(owner, sixtyTwo)).status).toBe('ok');
		const three = [wire(pair()), wire(pair()), wire(pair())];
		expect(await device.importSealedHistoryKeys(owner, three)).toEqual({ status: 'invalid', reason: 'too_many' });
		expect(await historyRowCount()).toBe(62);
		// exactly reaching the cap is fine
		expect((await device.importSealedHistoryKeys(owner, three.slice(0, 2))).status).toBe('ok');
		expect(await historyRowCount()).toBe(64);
	});
});

describe('the cap holds under concurrency and with unusable rows', () => {
	it('two concurrent imports with no Web Locks cannot exceed 64 rows, and the keyring stays readable', async () => {
		if (!ed25519Supported) return;
		vi.stubGlobal('navigator', {}); // no navigator.locks: withIdentityLock falls through
		try {
			const { device } = await boot();
			const owner = await liveOwner(device);
			const batch = () => Array.from({ length: 40 }, () => wire(pair()));
			const [r1, r2] = await Promise.all([
				device.importSealedHistoryKeys(owner, batch()),
				device.importSealedHistoryKeys(owner, batch()),
			]);
			const statuses = [r1.status, r2.status].sort();
			expect(statuses).toEqual(['invalid', 'ok']);
			expect(await historyRowCount()).toBe(40);
			const read = await device.readHistoryKeys(owner);
			expect(read.status === 'ok' && read.keys.length).toBe(40);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it('an unusable row still occupies a slot: 63 valid + 1 broken leaves room for none beyond 64', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const sixtyThree = Array.from({ length: 63 }, () => wire(pair()));
		expect((await device.importSealedHistoryKeys(owner, sixtyThree)).status).toBe('ok');
		const any = (await rows())[0]!;
		await raw.save(HISTORY_PREFIX + 'z'.repeat(43), { ...any.value, pubB64u: 'z'.repeat(43), kind: 'garbage' });
		expect(await historyRowCount()).toBe(64);
		expect(await device.importSealedHistoryKeys(owner, [wire(pair())])).toEqual({ status: 'invalid', reason: 'too_many' });
		expect(await historyRowCount()).toBe(64);
		const read = await device.readHistoryKeys(owner);
		expect(read.status === 'ok' && read.keys.length).toBe(63);
	});
});

describe('a corrupt CURRENT sealed key does not strand valid history', () => {
	it('read and import still work; export refuses rather than dropping the current key from a backup', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		await device.getOrCreateSealedX25519Secret(owner);
		const a = pair();
		await device.importSealedHistoryKeys(owner, [wire(a)]);
		const sealed = (await raw.load<Record<string, unknown>>(SEALED))!;
		await raw.save(SEALED, { ...sealed, wrappedPrivateKeyRaw: crypto.getRandomValues(new Uint8Array(40)).buffer });

		const fresh = await boot();
		const read = await fresh.device.readHistoryKeys(owner);
		expect(read.status === 'ok' && read.keys.map((k) => k.pubB64u).join()).toBe(a.pubB64u);
		expect((await fresh.device.importSealedHistoryKeys(owner, [wire(pair())])).status).toBe('ok');
		expect(await fresh.device.exportSealedKeyring(owner)).toEqual({ status: 'storage_failure', reason: 'io_error' });
	});
});

describe('another tab changed the store: a warm cache must not hide it', () => {
	it('an import in another tab becomes visible', async () => {
		if (!ed25519Supported) return;
		const tabA = await boot();
		const owner = await liveOwner(tabA.device);
		const warm = await tabA.device.readHistoryKeys(owner);
		expect(warm.status === 'ok' && warm.keys.length).toBe(0);
		const tabB = await boot();
		const k = pair();
		expect((await tabB.device.importSealedHistoryKeys(owner, [wire(k)])).status).toBe('ok');
		const seen = await tabA.device.readHistoryKeys(owner);
		expect(seen.status === 'ok' && seen.keys.map((x) => x.pubB64u).join()).toBe(k.pubB64u);
	});

	it('a forget in another tab stops this tab serving the forgotten keys', async () => {
		if (!ed25519Supported) return;
		const tabA = await boot();
		const owner = await liveOwner(tabA.device);
		await tabA.device.importSealedHistoryKeys(owner, [wire(pair())]);
		const warm = await tabA.device.readHistoryKeys(owner);
		expect(warm.status === 'ok' && warm.keys.length).toBe(1);
		const tabB = await boot();
		await tabB.device.clearDeviceIdentity();
		const after = await tabA.device.readHistoryKeys(owner);
		expect(after.status === 'ok' && after.keys.length > 0).toBe(false);
	});

	it('a wipe-pending marker written by another tab blocks this tab while the wipe keeps failing', async () => {
		if (!ed25519Supported) return;
		const tabA = await boot();
		const owner = await liveOwner(tabA.device);
		await tabA.device.importSealedHistoryKeys(owner, [wire(pair())]);
		expect((await tabA.device.readHistoryKeys(owner)).status).toBe('ok'); // warm
		await raw.save(MARKER, { kind: 'x25519-history-wipe-pending-v1', atMs: 1 });
		tabA.faults.failWipe = true;
		expect(await tabA.device.readHistoryKeys(owner)).toEqual({ status: 'storage_failure', reason: 'wipe_pending' });
	});
});

describe('duplicate routing addresses', () => {
	/** Two different valid pairs whose (weakened, 1-byte) addresses collide. */
	async function collidingPair(device: Device, avoid?: Uint8Array): Promise<[Pair, Pair]> {
		void device;
		const seen = new Map<number, Pair>();
		const addr = async (p: Pair) => {
			const { createHash } = await import('node:crypto');
			return createHash('sha256').update(p.pub).digest()[0]!;
		};
		for (let i = 0; i < 4000; i++) {
			const p = pair();
			const a = await addr(p);
			if (avoid && a === avoid[0]) return [p, p];
			const hit = seen.get(a);
			if (hit) return [hit, p];
			seen.set(a, p);
		}
		throw new Error('no collision found');
	}

	it('rejects two different keys with one address inside the batch', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot({ weakAddress: true });
		const owner = await liveOwner(device);
		const [a, b] = await collidingPair(device);
		expect(a.pubB64u).not.toBe(b.pubB64u);
		expect(await device.importSealedHistoryKeys(owner, [wire(a), wire(b)])).toEqual({ status: 'invalid', reason: 'duplicate_address' });
		expect(await historyRowCount()).toBe(0);
	});

	it('rejects a key whose address collides with one already held', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot({ weakAddress: true });
		const owner = await liveOwner(device);
		const [a, b] = await collidingPair(device);
		expect((await device.importSealedHistoryKeys(owner, [wire(a)])).status).toBe('ok');
		expect(await device.importSealedHistoryKeys(owner, [wire(b)])).toEqual({ status: 'invalid', reason: 'address_collision' });
		expect(await historyRowCount()).toBe(1);
	});

	it('rejects a key whose address collides with the CURRENT key', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot({ weakAddress: true });
		const owner = await liveOwner(device);
		const cur = await device.getOrCreateSealedX25519Secret(owner);
		const { createHash } = await import('node:crypto');
		const curAddr0 = createHash('sha256').update(x25519.getPublicKey(cur)).digest()[0]!;
		let clash: Pair | null = null;
		for (let i = 0; i < 4000 && !clash; i++) {
			const p = pair();
			if (createHash('sha256').update(p.pub).digest()[0] === curAddr0) clash = p;
		}
		expect(clash).not.toBeNull();
		expect(await device.importSealedHistoryKeys(owner, [wire(clash!)])).toEqual({ status: 'invalid', reason: 'address_collision' });
		expect(await historyRowCount()).toBe(0);
	});

	it('at READ time, colliding stored rows are all dropped (never an arbitrary pick)', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot({ weakAddress: true });
		const owner = await liveOwner(device);
		const [a, b] = await collidingPair(device);
		// bypass import's check by importing each under a strong address, then
		// reading under the weak one
		const strong = await boot({ weakAddress: false });
		await strong.device.importSealedHistoryKeys(owner, [wire(a), wire(b)]);
		const weak = await boot({ weakAddress: true });
		// the stored addrHex no longer matches the weak derivation -> dropped on that ground too;
		// re-store rows with weak addresses to isolate the collision rule
		for (const { key, value } of await rows()) {
			const p = key === HISTORY_PREFIX + a.pubB64u ? a : b;
			void p;
			const weakAddr = (value.addrHex as string).slice(0, 2) + '00000000000000';
			await raw.save(key, { ...value, addrHex: weakAddr });
		}
		const read = await weak.device.readHistoryKeys(owner);
		expect(read.status).toBe('ok');
		if (read.status === 'ok') expect(read.keys).toEqual([]);
	});
});

describe('read-time validation (every record is re-proven at every read)', () => {
	async function seeded(n = 2) {
		const first = await boot();
		const owner = await liveOwner(first.device);
		const ps = Array.from({ length: n }, () => pair());
		await first.device.importSealedHistoryKeys(owner, ps.map(wire));
		return { owner, ps };
	}
	async function tamper(p: Pair, fn: (v: Record<string, unknown>) => Record<string, unknown>) {
		const key = HISTORY_PREFIX + p.pubB64u;
		const v = (await raw.load<Record<string, unknown>>(key))!;
		await raw.save(key, fn(v));
	}
	async function readPubs(owner: string): Promise<{ pubs: string[]; dropped: number }> {
		const { device } = await boot(); // fresh module: no cache
		const r = await device.readHistoryKeys(owner);
		expect(r.status).toBe('ok');
		if (r.status !== 'ok') return { pubs: [], dropped: -1 };
		return { pubs: r.keys.map((k) => k.pubB64u).sort(), dropped: r.dropped };
	}

	it('baseline: untouched rows are served', async () => {
		if (!ed25519Supported) return;
		const { owner, ps } = await seeded();
		expect((await readPubs(owner)).pubs).toEqual(ps.map((p) => p.pubB64u).sort());
	});

	it('drops a row owned by another identity', async () => {
		if (!ed25519Supported) return;
		const { owner, ps } = await seeded();
		await tamper(ps[0]!, (v) => ({ ...v, ownerEd25519PubB64: otherIdentity().pub }));
		const r = await readPubs(owner);
		expect(r.pubs).toEqual([ps[1]!.pubB64u]);
		expect(r.dropped).toBe(1);
	});

	it('drops a row whose wrapped secret belongs to a different key (pair check at read)', async () => {
		if (!ed25519Supported) return;
		const { owner, ps } = await seeded();
		const other = (await raw.load<Record<string, unknown>>(HISTORY_PREFIX + ps[1]!.pubB64u))!;
		await tamper(ps[0]!, (v) => ({ ...v, wrappedSecret: other.wrappedSecret }));
		expect((await readPubs(owner)).pubs).toEqual([ps[1]!.pubB64u]);
	});

	it('drops a row whose stored address is not the derived one', async () => {
		if (!ed25519Supported) return;
		const { owner, ps } = await seeded();
		await tamper(ps[0]!, (v) => ({ ...v, addrHex: '0123456789abcdef' }));
		expect((await readPubs(owner)).pubs).toEqual([ps[1]!.pubB64u]);
	});

	it('drops a row filed under a different key name, and one with an unknown kind', async () => {
		if (!ed25519Supported) return;
		const { owner, ps } = await seeded(3);
		const v = (await raw.load<Record<string, unknown>>(HISTORY_PREFIX + ps[0]!.pubB64u))!;
		await raw.delete(HISTORY_PREFIX + ps[0]!.pubB64u);
		await raw.save(HISTORY_PREFIX + pair().pubB64u, v); // right body, wrong filename
		await tamper(ps[1]!, (x) => ({ ...x, kind: 'x25519-history-v2' }));
		expect((await readPubs(owner)).pubs).toEqual([ps[2]!.pubB64u]);
	});

	it('refuses a store holding more than 64 rows instead of allocating them', async () => {
		if (!ed25519Supported) return;
		const { owner, ps } = await seeded(1);
		const v = (await raw.load<Record<string, unknown>>(HISTORY_PREFIX + ps[0]!.pubB64u))!;
		for (let i = 0; i < 70; i++) await raw.save(HISTORY_PREFIX + 'x'.repeat(43 - 2) + String(i).padStart(2, '0'), v);
		const { device } = await boot();
		expect(await device.readHistoryKeys(owner)).toEqual({ status: 'invalid', reason: 'corrupt_store' });
	});

	it('the cache is stamped with the identity epoch: it cannot serve a retired identity', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		const warm = await device.readHistoryKeys(owner); // populates the cache
		expect(warm.status === 'ok' && warm.keys.length === 1).toBe(true);

		await device.clearDeviceIdentity();
		const after = await device.readHistoryKeys(owner);
		expect(after.status === 'ok' && after.keys.length > 0).toBe(false);
	});

	it('a read that STARTS before a wipe and finishes after it returns nothing, and caches nothing', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		// the read has the old owner's rows in hand when the identity is wiped
		faults.afterLoadPrefix = () => device.clearDeviceIdentity();
		const racing = await device.readHistoryKeys(owner);
		expect(racing).toEqual({ status: 'storage_failure', reason: 'stale_identity' });
		const later = await device.readHistoryKeys(owner);
		expect(later.status === 'ok' && later.keys.length > 0).toBe(false);
	});

	it('an export that races a wipe returns no key material', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		faults.afterLoadPrefix = () => device.clearDeviceIdentity();
		expect(await device.exportSealedKeyring(owner)).toEqual({ status: 'storage_failure', reason: 'stale_identity' });
	});

	it('an import that races a wipe writes nothing after the wipe', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		faults.afterLoadPrefix = () => device.clearDeviceIdentity();
		const r = await device.importSealedHistoryKeys(owner, [wire(pair())]);
		expect(r).toEqual({ status: 'storage_failure', reason: 'stale_identity' });
		expect(await historyRowCount()).toBe(0);
	});

	it('returns fresh buffers: zeroizing a result cannot corrupt the next read', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		await device.importSealedHistoryKeys(owner, [wire(a)]);
		const r1 = await device.readHistoryKeys(owner);
		if (r1.status === 'ok') r1.keys[0]!.priv.fill(0);
		const r2 = await device.readHistoryKeys(owner);
		expect(r2.status === 'ok' && b64u(x25519.getPublicKey(r2.keys[0]!.priv)) === a.pubB64u).toBe(true);
	});
});

describe('lifecycle: history leaves with the sealed key (asserted on RAW rows)', () => {
	it('replaceDeviceIdentity to a DIFFERENT identity deletes every history row and the sealed row', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		await device.getOrCreateSealedX25519Secret(owner);
		await device.importSealedHistoryKeys(owner, [wire(pair()), wire(pair())]);
		expect(await historyRowCount()).toBe(2);
		expect(await raw.load(SEALED)).not.toBeNull();

		const next = otherIdentity();
		await device.replaceDeviceIdentity(next.secret, next.pub);

		expect(await historyRowCount()).toBe(0);
		expect(await raw.load(SEALED)).toBeNull();
		expect(await raw.load(MARKER)).toBeNull();
	});

	it('replaceDeviceIdentity to a different identity deletes history even when no sealed key was ever minted', async () => {
		// The history rule must stand on its own: with no sealed row, the sealed
		// key's rule has nothing to trigger on.
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		expect(await raw.load(SEALED)).toBeNull();
		const next = otherIdentity();
		await device.replaceDeviceIdentity(next.secret, next.pub);
		expect(await historyRowCount()).toBe(0);
	});

	it('replaceDeviceIdentity with the SAME identity keeps its history', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		await device.importSealedHistoryKeys(owner, [wire(a)]);
		const exp = await device.exportRawDeviceSecret();
		await device.replaceDeviceIdentity(exp.secret, exp.publicB64u);
		expect(await historyRowCount()).toBe(1);
		const r = await device.readHistoryKeys(owner);
		expect(r.status === 'ok' && r.keys.map((k) => k.pubB64u).join() === a.pubB64u).toBe(true);
	});

	it('clearDeviceIdentity deletes every history row', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair()), wire(pair())]);
		await device.clearDeviceIdentity();
		expect(await historyRowCount()).toBe(0);
		expect(await raw.load(MARKER)).toBeNull();
	});

	it('a history key imported for a retired owner never reaches the next identity', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		await device.clearDeviceIdentity();
		const fresh = await boot();
		const newOwner = await liveOwner(fresh.device);
		expect(newOwner).not.toBe(owner);
		const r = await fresh.device.readHistoryKeys(newOwner);
		expect(r.status === 'ok' && r.keys.length).toBe(0);
	});
});

describe('a failed wipe blocks history until it is retried successfully', () => {
	it('clearDeviceIdentity does not report success while history survives, and the marker blocks reads', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);

		faults.failWipe = true;
		await expect(device.clearDeviceIdentity()).rejects.toMatchObject({ name: 'HistoryWipePendingError' });
		// the fault was REAL: the row is still on disk, and the marker is durable
		expect(await historyRowCount()).toBe(1);
		expect(await raw.load(MARKER)).not.toBeNull();
		expect(await device.isHistoryWipePending()).toBe(true);
		const r = await device.readHistoryKeys(owner);
		expect(r).toEqual({ status: 'storage_failure', reason: 'wipe_pending' });
	});

	it('the boot retry finishes the wipe and clears the marker', async () => {
		if (!ed25519Supported) return;
		const first = await boot();
		const owner = await liveOwner(first.device);
		await first.device.importSealedHistoryKeys(owner, [wire(pair())]);
		first.faults.failWipe = true;
		await expect(first.device.clearDeviceIdentity()).rejects.toThrow();
		expect(await historyRowCount()).toBe(1);

		const second = await boot(); // faults off: a later session
		await second.device.getOrCreateDeviceIdentity();
		expect(await historyRowCount()).toBe(0);
		expect(await raw.load(MARKER)).toBeNull();
	});

	it('export, import and read are ALL blocked while the marker is set and the wipe keeps failing', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		const a = pair();
		await device.importSealedHistoryKeys(owner, [wire(a)]);
		// a marker for a LIVE owner's keys: only the marker (not the owner check)
		// stands between these rows and the caller
		await raw.save(MARKER, { kind: 'x25519-history-wipe-pending-v1', atMs: 1 });
		faults.failWipe = true;
		const blocked = { status: 'storage_failure', reason: 'wipe_pending' };
		expect(await device.readHistoryKeys(owner)).toEqual(blocked);
		expect(await device.exportSealedKeyring(owner)).toEqual(blocked);
		expect(await device.importSealedHistoryKeys(owner, [wire(pair())])).toEqual(blocked);
		expect(await historyRowCount()).toBe(1);
	});

	it('a read that finds the marker retries the wipe, and a healthy retry empties history', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		await raw.save(MARKER, { kind: 'x25519-history-wipe-pending-v1', atMs: 1 });
		const r = await device.readHistoryKeys(owner);
		expect(r.status === 'ok' && r.keys.length).toBe(0);
		expect(await historyRowCount()).toBe(0);
		expect(await raw.load(MARKER)).toBeNull();
	});

	it('replaceDeviceIdentity still resolves when the wipe fails, and the marker blocks the new owner', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		faults.failWipe = true;
		const next = otherIdentity();
		await expect(device.replaceDeviceIdentity(next.secret, next.pub)).resolves.toBeUndefined();
		expect(await historyRowCount()).toBe(1); // old owner's row survived the fault
		expect(await raw.load(MARKER)).not.toBeNull();
		expect(await device.readHistoryKeys(next.pub)).toEqual({ status: 'storage_failure', reason: 'wipe_pending' });
	});

	it('if even the marker cannot be written, an in-memory latch still blocks this session', async () => {
		if (!ed25519Supported) return;
		const { device, faults } = await boot();
		const owner = await liveOwner(device);
		await device.importSealedHistoryKeys(owner, [wire(pair())]);
		faults.failWipe = true;
		faults.failMarker = true;
		await expect(device.clearDeviceIdentity()).rejects.toMatchObject({ name: 'HistoryWipePendingError' });
		expect(await raw.load(MARKER)).toBeNull(); // the marker write really failed
		expect(await device.isHistoryWipePending()).toBe(true);
	});
});

describe('Ed25519 pair check on replaceDeviceIdentity', () => {
	it('rejects a public key the secret does not derive, and changes NOTHING', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const before = await device.getOrCreateDeviceIdentity();
		await device.getOrCreateSealedX25519Secret(before.publicKeyB64);
		const sealedBefore = await raw.load(SEALED);
		const wrong = otherIdentity();
		const secret = ed25519.utils.randomSecretKey(); // not the secret of `wrong.pub`

		await expect(device.replaceDeviceIdentity(secret, wrong.pub)).rejects.toMatchObject({
			name: 'IdentityKeyPairMismatchError',
			reason: 'pair_mismatch',
		});
		const reloaded = await boot();
		expect((await reloaded.device.getOrCreateDeviceIdentity()).publicKeyB64).toBe(before.publicKeyB64);
		expect(await raw.load(SEALED)).toEqual(sealedBefore);
	});

	it.each([
		['a 31-byte secret', () => ({ secret: new Uint8Array(31), pub: otherIdentity().pub }), 'bad_secret_length'],
		['a padded public key', () => {
			const s = ed25519.utils.randomSecretKey();
			return { secret: s, pub: b64u(ed25519.getPublicKey(s)) + '=' };
		}, 'non_canonical_public'],
	])('rejects %s with a typed reason', async (_n, mk, reason) => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		await device.getOrCreateDeviceIdentity();
		const { secret, pub } = mk();
		await expect(device.replaceDeviceIdentity(secret, pub)).rejects.toMatchObject({
			name: 'IdentityKeyPairMismatchError',
			reason,
		});
	});

	it('accepts a genuine pair', async () => {
		if (!ed25519Supported) return;
		const { device } = await boot();
		const next = otherIdentity();
		await expect(device.replaceDeviceIdentity(next.secret, next.pub)).resolves.toBeUndefined();
		expect((await device.getOrCreateDeviceIdentity()).publicKeyB64).toBe(next.pub);
	});
});

describe('telemetry carries aggregate outcomes only', () => {
	it('a failed wipe is reported, and no event contains key material', async () => {
		if (!ed25519Supported) return;
		const events: Array<{ event: string; payload?: Record<string, unknown> }> = [];
		const { device, faults } = await boot();
		// imported AFTER boot(): same module instance the device module just loaded
		const { setIdentityTracker: wired } = await import('../tracker-shim.js');
		wired((event, _room, payload) => events.push({ event, payload }));
		const owner = await liveOwner(device);
		const a = pair();
		await device.importSealedHistoryKeys(owner, [wire(a)]);
		faults.failWipe = true;
		await expect(device.clearDeviceIdentity()).rejects.toThrow();

		const kr = events.filter((e) => e.event === 'client.identity_history_keyring');
		expect(kr.some((e) => e.payload?.op === 'import' && e.payload?.outcome === 'ok')).toBe(true);
		expect(kr.some((e) => e.payload?.op === 'wipe' && e.payload?.outcome === 'failed')).toBe(true);
		const dump = JSON.stringify(events);
		expect(dump.includes(a.pubB64u)).toBe(false);
		expect(dump.includes(a.secretB64u)).toBe(false);
		expect(dump.includes(owner)).toBe(false);
		wired(() => {});
	});
});
