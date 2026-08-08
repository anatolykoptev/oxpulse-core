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

/** A device that has never run either version. */
function freshDevice() {
  globalThis.indexedDB = new IDBFactory();
  vi.resetModules();
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

beforeEach(() => {
  freshDevice();
});

describe('a device carrying the 0.1.5 layout', () => {
  it('keeps its identity when 0.2.x takes over', async () => {
    // 1. 0.1.5 creates and persists an identity — the pre-#98 layout, written
    //    by the code that actually wrote it in the field.
    const legacy = await legacyVersion();
    const before = await legacy.getOrCreateDeviceIdentity();
    const beforeKey = before.publicKeyB64;
    expect(beforeKey, '0.1.5 must produce an identity to migrate').toBeTruthy();

    // 2. The user updates. Same browser, same IndexedDB, new code.
    const current = await currentVersion();
    const after = await current.getOrCreateDeviceIdentity();
    const afterKey = after.publicKeyB64;

    expect(
      afterKey,
      'THE incident: an identity written by 0.1.5 must survive the upgrade. A ' +
        'different key here means the user was locked out of an identity that ' +
        'is still sitting in their IndexedDB, which is what shipped on ' +
        '2026-08-06 and what this test exists to prevent.',
    ).toBe(beforeKey);
  });

  it('does not need the legacy key twice — the second load takes the new path', async () => {
    const legacy = await legacyVersion();
    const first = await legacy.getOrCreateDeviceIdentity();
    const firstKey = first.publicKeyB64;

    const current = await currentVersion();
    await current.getOrCreateDeviceIdentity();

    // Reload with fresh module state: the KEK must now be in the dedicated
    // database, so this resolves without touching the legacy entry at all.
    const reloaded = await currentVersion();
    const again = await reloaded.getOrCreateDeviceIdentity();
    expect(again.publicKeyB64).toBe(firstKey);
  });

  it('leaves the legacy key in place — a migration must keep its own escape hatch', async () => {
    // Deleting the only thing that can decrypt a user's identity, in the same
    // step that first tries to use it, leaves no second attempt if the copy
    // fails. The forget path owns that deletion; the migration does not.
    const legacy = await legacyVersion();
    await legacy.getOrCreateDeviceIdentity();

    const current = await currentVersion();
    await current.getOrCreateDeviceIdentity();

    const stillThere = await new Promise<boolean>((resolve) => {
      const req = indexedDB.open('oxpulse-device-id');
      req.onerror = () => resolve(false);
      req.onsuccess = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('identity')) return resolve(false);
        const get = db.transaction('identity', 'readonly').objectStore('identity').get('wrapping-key');
        get.onsuccess = () => resolve(get.result != null);
        get.onerror = () => resolve(false);
      };
    });

    expect(stillThere, 'the legacy wrapping key must not be deleted by the migration').toBe(true);
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
