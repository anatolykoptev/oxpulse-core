import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { getOrCreateRoomHostSeed, exportRoomHostSeed, __clearRoomHostSeed } from '../room-host-seed';

describe('room-host-seed', () => {
  beforeEach(async () => { await __clearRoomHostSeed(); });

  it('returns 32 bytes', async () => {
    const seed = await getOrCreateRoomHostSeed();
    expect(seed).toBeInstanceOf(Uint8Array);
    expect(seed.length).toBe(32);
  });

  it('is idempotent — same seed across calls (survives reload)', async () => {
    const a = await getOrCreateRoomHostSeed();
    const b = await getOrCreateRoomHostSeed();
    expect(Array.from(b)).toEqual(Array.from(a));
  });

  it('exportRoomHostSeed round-trips the raw bytes', async () => {
    const seed = await getOrCreateRoomHostSeed();
    const exported = await exportRoomHostSeed();
    expect(Array.from(exported!)).toEqual(Array.from(seed));
  });
});
