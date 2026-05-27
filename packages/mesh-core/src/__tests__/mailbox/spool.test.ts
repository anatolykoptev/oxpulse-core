import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { Spool, MESH_SPOOL_DB_NAME } from '../../mailbox/spool.ts';

const sample = (msgId: string, hopsRemaining = 3, addedAgeMs = 0) => ({
  msgId,
  channelId: new Uint8Array([1, 2, 3, 4]),
  bundle: new Uint8Array([0xc9, 0x01]),
  addedAtMs: Date.now() - addedAgeMs,
  hopsRemaining,
});

describe('Spool', () => {
  let spool: Spool;

  beforeEach(async () => {
    spool = new Spool('test-spool-' + Math.random());
    await spool.open();
  });

  afterEach(() => spool.close());

  it('stores a forward-pending bundle', async () => {
    await spool.put(sample('m1'));
    expect(await spool.size()).toBe(1);
  });

  it('decrementHops drops entry when hopsRemaining reaches zero', async () => {
    await spool.put(sample('m1', 1));
    await spool.decrementHops('m1');
    expect(await spool.size()).toBe(0);
  });

  it('decrementHops preserves entry when hops still positive', async () => {
    await spool.put(sample('m1', 3));
    await spool.decrementHops('m1');
    const entries = await spool.all();
    expect(entries).toHaveLength(1);
    expect(entries[0]!.hopsRemaining).toBe(2);
  });

  it('evictOlderThan removes stale entries', async () => {
    await spool.put(sample('old', 3, 8 * 24 * 60 * 60 * 1000));
    await spool.put(sample('fresh', 3, 60 * 1000));
    await spool.evictOlderThan(7 * 24 * 60 * 60 * 1000);
    const remaining = (await spool.all()).map((e) => e.msgId);
    expect(remaining).toEqual(['fresh']);
  });

  it('exports canonical DB name', () => {
    expect(MESH_SPOOL_DB_NAME).toBe('mesh-router-spool');
  });

  it('remove() is idempotent (deleting unknown id is a no-op)', async () => {
    await spool.put(sample('m1'));
    await spool.remove('m1');
    await spool.remove('m1');
    expect(await spool.size()).toBe(0);
  });
});
