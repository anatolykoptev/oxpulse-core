// legacy-kek-adoption.test.ts — the incident gate.
//
// v0.17.0 of oxpulse-chat shipped this package 0.1.5 → 0.2.0 into production
// and locked users out of identities that were sitting intact in their own
// IndexedDB. Measured on that deployment:
//
//   device_identity_failure_total{error_class="unwrap_failed", stage="unwrap"}
//     08-06, every bucket, all day and after the deploy:  0.0
//     08-07 06h  2.0    10h  45.4    18h  35.3
//
// 0.2.x introduced a dedicated KEK database. On a device carrying the pre-#98
// layout it found that database empty, read "first run", generated a fresh
// KEK, and could no longer unwrap what the old one had wrapped.
//
// ## Why this test imports the real 0.1.5
//
// The defect was a WRONG BELIEF ABOUT THE FIELD — "nothing has this package
// installed in the field yet", written in the source. A fixture hand-built
// from someone's reading of the old code encodes a belief of exactly the same
// kind, and would pass while the real layout still failed.
//
// So the store here is written by `@oxpulse/identity@0.1.5` itself, installed
// under an alias. The bytes under test are the bytes 0.1.5 actually produces.
// If that package is ever unpublished this test fails loudly, which is the
// correct outcome: the guarantee it encodes would no longer be checkable.

import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { describe, it, expect, beforeEach, vi } from 'vitest';

/**
 * A device that has never run either version.
 *
 * Both the IDB factory AND the module registry are replaced. The stores in
 * `device-identity` are module-level singletons that capture
 * `globalThis.indexedDB`, so swapping the factory without resetting modules
 * leaves a live handle to the previous device — which is a test that quietly
 * measures the wrong browser.
 */
function freshDevice() {
  globalThis.indexedDB = new IDBFactory();
  vi.resetModules();
}

/**
 * Delete both databases outright.
 *
 * Swapping `globalThis.indexedDB` alone does NOT isolate these tests, which
 * cost a debugging round: with a shared factory the second test read the
 * identity the first one had created and compared it against a freshly-written
 * legacy key, so it failed while the code under test was correct. Deleting the
 * databases does not depend on whether the swap took effect.
 */
async function wipeDatabases() {
  for (const name of ['oxpulse-device-id', 'oxpulse-device-id-kek', 'oxpulse-room-host-seed']) {
    await new Promise<void>((resolve) => {
      const r = indexedDB.deleteDatabase(name);
      r.onsuccess = () => resolve();
      r.onerror = () => resolve();
      r.onblocked = () => resolve();
    });
  }
}

/** Load the version under test with its module state reset. */
async function currentVersion() {
  vi.resetModules();
  return import('../device-identity');
}

/** Load the shipped 0.1.5 build. */
async function legacyVersion() {
  vi.resetModules();
  return import('identity-legacy-0-1-5');
}

/** Read a key straight out of IDB, independent of either package. */
async function rawGet(dbName: string, store: string, key: string): Promise<unknown> {
  const db: IDBDatabase = await new Promise((resolve, reject) => {
    const r = indexedDB.open(dbName);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  try {
    if (!db.objectStoreNames.contains(store)) return null;
    return await new Promise((resolve, reject) => {
      const g = db.transaction(store, 'readonly').objectStore(store).get(key);
      g.onsuccess = () => resolve(g.result ?? null);
      g.onerror = () => reject(g.error);
    });
  } finally {
    db.close();
  }
}

beforeEach(async () => {
  freshDevice();
  await wipeDatabases();
});

describe('a device carrying the 0.1.5 layout', () => {
  // One test, one upgrade. These properties are all facts about the SAME
  // transition, and splitting them across `it`s made each one depend on the
  // previous test's IndexedDB — which is how two of them failed while the code
  // was correct. A shared-state bug in the harness reads exactly like a bug in
  // the thing under test, and costs the same debugging round.
  it('keeps its identity, copies the KEK forward, and keeps the legacy key', async () => {
    // 1. 0.1.5 creates and persists an identity — the pre-#98 layout, written
    //    by the code that actually wrote it in the field.
    const legacy = await legacyVersion();
    const before = (await legacy.getOrCreateDeviceIdentity()).publicKeyB64;
    expect(before, '0.1.5 must produce an identity to migrate').toBeTruthy();
    expect(
      await rawGet('oxpulse-device-id', 'identity', 'wrapping-key'),
      'the premise of this whole test: 0.1.5 writes a legacy wrapping key',
    ).not.toBeNull();

    // 2. The user updates. Same browser, same IndexedDB, new code.
    const current = await currentVersion();
    const after = (await current.getOrCreateDeviceIdentity()).publicKeyB64;

    expect(
      after,
      'THE incident: an identity written by 0.1.5 must survive the upgrade. A ' +
        'different key here means the user was locked out of an identity still ' +
        'sitting in their IndexedDB — what shipped on 2026-08-06.',
    ).toBe(before);

    // 3. The key is copied forward, so adoption runs once per device rather
    //    than on every load.
    expect(
      await rawGet('oxpulse-device-id-kek', 'kek', 'wrapping-key'),
      'without the copy, every future load re-adopts',
    ).not.toBeNull();

    // 4. And the legacy entry survives. Deleting the only thing that can
    //    decrypt a user's identity, in the same step that first uses it,
    //    leaves no second attempt if the copy failed. `forgetDeviceIdentity`
    //    owns that deletion; the migration does not.
    expect(
      await rawGet('oxpulse-device-id', 'identity', 'wrapping-key'),
      'the legacy wrapping key must not be deleted by the migration',
    ).not.toBeNull();

    // 5. The next load resolves from the dedicated database, same identity.
    const reloaded = await currentVersion();
    expect((await reloaded.getOrCreateDeviceIdentity()).publicKeyB64).toBe(before);
  });
});

describe('a device that never ran 0.1.5', () => {
  it('still gets a brand-new identity — adoption must not break a first run', async () => {
    const current = await currentVersion();
    const id = await current.getOrCreateDeviceIdentity();
    expect(id.publicKeyB64).toBeTruthy();
  });

  it('is unaffected by junk under the legacy name', async () => {
    // Something unreadable where the legacy key would be must not fail the
    // app: on a genuinely-new device there is nothing to lose, and throwing
    // here would trade a recoverable lockout for an unrecoverable one.
    await new Promise<void>((resolve, reject) => {
      const open = indexedDB.open('oxpulse-device-id', 1);
      open.onupgradeneeded = () => open.result.createObjectStore('identity');
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const tx = db.transaction('identity', 'readwrite');
        tx.objectStore('identity').put('not-a-key', 'wrapping-key');
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      };
    });

    const current = await currentVersion();
    const id = await current.getOrCreateDeviceIdentity();
    expect(id.publicKeyB64).toBeTruthy();
  });
});
