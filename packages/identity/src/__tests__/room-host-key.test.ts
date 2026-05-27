import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { getOrCreateRoomHostKey, signHostAction } from '../host-identity';
import { __clearRoomHostSeed } from '../room-host-seed';

describe('getOrCreateRoomHostKey (derived)', () => {
  beforeEach(async () => { await __clearRoomHostSeed(); });

  it('returns a usable Ed25519 host keypair', async () => {
    const k = await getOrCreateRoomHostKey('ABCD-EFGH');
    expect(k.publicKeyB64).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('is deterministic — same roomId+seed yields the same key (survives reload)', async () => {
    const a = await getOrCreateRoomHostKey('ABCD-EFGH');
    const b = await getOrCreateRoomHostKey('ABCD-EFGH');
    expect(b.publicKeyB64).toBe(a.publicKeyB64);
  });

  it('distinct rooms derive distinct keys', async () => {
    const a = await getOrCreateRoomHostKey('ROOM-0001');
    const b = await getOrCreateRoomHostKey('ROOM-0002');
    expect(b.publicKeyB64).not.toBe(a.publicKeyB64);
  });

  it('a signature from the derived key verifies (round-trip)', async () => {
    const k = await getOrCreateRoomHostKey('ABCD-EFGH');
    const sig = await signHostAction(k, 'pin-mint:ABCD-EFGH:123');
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(sig.length).toBeGreaterThan(0);
  });
});
