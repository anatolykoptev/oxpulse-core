// recover-after-broken-kek.test.ts — the trajectory that actually happened.
//
// The first fix (legacy-kek-adoption) gated adoption on "the KEK database is
// empty". That helps only devices which never opened the broken build — which
// is nobody in the incident. The broken path generated a fresh KEK and SAVED
// it before the unwrap it was about to fail, so every affected device carries
// a bogus KEK, the database is NOT empty, and adoption never fires.
//
// It shipped, and the operator still could not sign in.
//
// The earlier gate could not have caught this: it starts from a pristine 0.1.5
// store, and the real path is 0.1.5 -> BROKEN 0.2.1 -> patched. Right data
// source, wrong initial state. So this test runs the broken build for real.

import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { describe, it, expect, beforeEach, vi } from 'vitest';

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
  vi.resetModules();
});

describe('a device that already went through the broken 0.2.x', () => {
  it('gets its identity back', async () => {
    // 1. 0.1.5 writes the pre-#98 layout.
    vi.resetModules();
    const legacy = await import('identity-legacy-0-1-5');
    const before = (await legacy.getOrCreateDeviceIdentity()).publicKeyB64;
    expect(before).toBeTruthy();

    // 2. The broken build runs and fails — persisting a bogus KEK on the way.
    vi.resetModules();
    const broken = await import('identity-broken-0-2-1');
    await expect(
      broken.getOrCreateDeviceIdentity(),
      'the premise: 0.2.1 must FAIL here. If it succeeds, this test is not ' +
        'reproducing the incident and proves nothing.',
    ).rejects.toThrow();

    // 3. The patched build must recover the ORIGINAL identity.
    vi.resetModules();
    const fixed = await import('../device-identity');
    const after = (await fixed.getOrCreateDeviceIdentity()).publicKeyB64;

    expect(
      after,
      'a device that already ran the broken build must get its identity back — ' +
        'this is every user in the incident, and the first fix missed all of them',
    ).toBe(before);

    // 4. And stays recovered on the next load.
    vi.resetModules();
    const again = await import('../device-identity');
    expect((await again.getOrCreateDeviceIdentity()).publicKeyB64).toBe(before);
  });
});
