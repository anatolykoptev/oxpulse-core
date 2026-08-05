import 'fake-indexeddb/auto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- fake-indexeddb has no bundled types here
import { IDBFactory } from 'fake-indexeddb';
import { createIdbStore } from '../idb-store';

// Direct IDB handle to the dedicated room-host-seed store for white-box
// assertions (KEK form, migration seeding, entry counts).
const DB_NAME = 'oxpulse-room-host-seed';
const STORE_NAME = 'seed';
const WRAPPING_KEY = 'wrapping_key';
// The CryptoKey form has its own entry so upgrading never destroys the raw
// bytes, which are the only way back if the CryptoKey stops deserialising.
const WRAPPING_KEY_CK = 'wrapping_key_ck';
const KEY = 'room_host_seed_v1';
const idb = createIdbStore({ dbName: DB_NAME, storeName: STORE_NAME });

type RoomHostSeedModule = typeof import('../room-host-seed.js');

/**
 * Reset module registry so room-host-seed.ts re-evaluates with empty caches.
 * IDB state (fake-indexeddb in-memory) is retained — exactly the production
 * "page reload" semantics. Mirrors device-identity.test.ts freshImport().
 */
async function freshImport(): Promise<RoomHostSeedModule> {
	const { vi } = await import('vitest');
	vi.resetModules();
	return (await import('../room-host-seed.js')) as RoomHostSeedModule;
}

/** Wipe the fake-indexeddb store entirely — used between independent tests. */
function resetIDB(): void {
	(globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

beforeEach(() => { resetIDB(); });
afterEach(() => { resetIDB(); });

describe('room-host-seed', () => {
  it('returns 32 bytes', async () => {
    const mod = await freshImport();
    const seed = await mod.getOrCreateRoomHostSeed();
    expect(seed).toBeInstanceOf(Uint8Array);
    expect(seed.length).toBe(32);
  });

  it('round-trips across reload (clear cache, reload from IDB)', async () => {
    const first = await freshImport();
    const a = await first.getOrCreateRoomHostSeed();

    // Simulate reload: module caches dropped, IDB state retained.
    const second = await freshImport();
    const b = await second.getOrCreateRoomHostSeed();
    expect(Array.from(b)).toEqual(Array.from(a));
  });

  it('exportRoomHostSeed returns same bytes after reload', async () => {
    const first = await freshImport();
    const seed = await first.getOrCreateRoomHostSeed();

    const second = await freshImport();
    const exported = await second.exportRoomHostSeed();
    expect(exported).not.toBeNull();
    expect(Array.from(exported!)).toEqual(Array.from(seed));
  });

  it('exportRoomHostSeed returns null when never created', async () => {
    const mod = await freshImport();
    const exported = await mod.exportRoomHostSeed();
    expect(exported).toBeNull();
  });

  it('KEK is a non-extractable CryptoKey (not raw bytes) after creation', async () => {
    const mod = await freshImport();
    await mod.getOrCreateRoomHostSeed();
    const kek = await idb.load<CryptoKey>(WRAPPING_KEY_CK);
    expect(kek).toBeInstanceOf(CryptoKey);
    expect((kek as CryptoKey).extractable).toBe(false);
    expect((kek as CryptoKey).type).toBe('secret');
  });

  it('KEK remains a non-extractable CryptoKey after reload', async () => {
    const first = await freshImport();
    await first.getOrCreateRoomHostSeed();

    const second = await freshImport();
    await second.getOrCreateRoomHostSeed();
    const kek = await idb.load<CryptoKey>(WRAPPING_KEY_CK);
    expect(kek).toBeInstanceOf(CryptoKey);
    expect((kek as CryptoKey).extractable).toBe(false);
  });

  it('__clearRoomHostSeed wipes all entries', async () => {
    const mod = await freshImport();
    await mod.getOrCreateRoomHostSeed();
    await mod.__clearRoomHostSeed();
    expect(await idb.load(KEY)).toBeNull();
    expect(await idb.load(WRAPPING_KEY)).toBeNull();
  });

  it('migration: legacy raw-bytes KEK → non-extractable CryptoKey, seed still recovers', async () => {
    // 1. Seed a legacy raw-bytes KEK + a seed wrapped under it, using the
    //    pre-Phase-5 inline AES-256-import wrap trick (RFC 3394 ciphertext,
    //    unwrappable by the new aes-kw helper).
    const legacyKek = await crypto.subtle.generateKey(
      { name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey'],
    );
    const legacyRaw = await crypto.subtle.exportKey('raw', legacyKek);
    await idb.save(WRAPPING_KEY, legacyRaw);

    const seedBytes = crypto.getRandomValues(new Uint8Array(32));
    const seedKey = await crypto.subtle.importKey(
      'raw', seedBytes, { name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey'],
    );
    const wrappedSeed = await crypto.subtle.wrapKey('raw', seedKey, legacyKek, 'AES-KW');
    await idb.save(KEY, wrappedSeed);

    // 2. Fresh import so getOrCreateRoomHostSeed re-reads from IDB and runs
    //    the migration path (legacy raw-bytes KEK → non-extractable CryptoKey).
    const mod = await freshImport();
    const recovered = await mod.getOrCreateRoomHostSeed();

    // 3. Seed bytes recovered unchanged.
    expect(Array.from(recovered)).toEqual(Array.from(seedBytes));

    // 4. A non-extractable CryptoKey now exists under its OWN entry.
    const kek = await idb.load<CryptoKey>(WRAPPING_KEY_CK);
    expect(kek).toBeInstanceOf(CryptoKey);
    expect((kek as CryptoKey).extractable).toBe(false);

    // 5. And the legacy raw bytes are STILL THERE. This is the point of the
    //    change: the upgrade used to overwrite them in place, which destroyed
    //    the only path back if the CryptoKey ever stopped deserialising —
    //    permanent seed loss on a runtime regression. ADR-3 calls migrations
    //    copy-only; device-identity honours that with a separate database, and
    //    this store honours it with a separate key.
    const rawStillThere = await idb.load<ArrayBuffer>(WRAPPING_KEY);
    expect(rawStillThere, "legacy raw KEK was destroyed by the upgrade").not.toBeNull();
    expect(Array.from(new Uint8Array(rawStillThere as ArrayBuffer)))
      .toEqual(Array.from(new Uint8Array(legacyRaw)));
  });
});
