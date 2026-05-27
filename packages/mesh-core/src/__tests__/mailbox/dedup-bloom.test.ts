import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { BloomDedup, MESH_BLOOM_DB_NAME } from '../../mailbox/dedup-bloom.ts';

describe('BloomDedup', () => {
  let bloom: BloomDedup;

  beforeEach(async () => {
    bloom = new BloomDedup({ dbName: 'test-bloom-' + Math.random(), capacity: 1000, fpRate: 0.01 });
    await bloom.open();
  });

  afterEach(() => bloom.close());

  it('reports unseen key as not-seen', () => {
    expect(bloom.hasSeen('msg-1')).toBe(false);
  });

  it('reports seen key as seen', () => {
    bloom.markSeen('msg-1');
    expect(bloom.hasSeen('msg-1')).toBe(true);
  });

  it('false positive rate stays under target across 1000 seen + 10000 lookups', () => {
    for (let i = 0; i < 1000; i++) bloom.markSeen('inserted-' + i);
    let fp = 0;
    for (let i = 0; i < 10000; i++) {
      if (bloom.hasSeen('miss-' + i)) fp++;
    }
    expect(fp / 10000).toBeLessThan(0.03); // 3× target — accounts for stochastic noise
  });

  it('flush persists; reopen reloads bits', async () => {
    bloom.markSeen('persisted-1');
    bloom.markSeen('persisted-2');
    await bloom.flush();
    bloom.close();

    const dbName = (bloom as unknown as { dbName: string }).dbName;
    const reopened = new BloomDedup({ dbName, capacity: 1000, fpRate: 0.01 });
    await reopened.open();
    expect(reopened.hasSeen('persisted-1')).toBe(true);
    expect(reopened.hasSeen('persisted-2')).toBe(true);
    expect(reopened.hasSeen('persisted-never')).toBe(false);
    reopened.close();
  });

  it('exports canonical DB name', () => {
    expect(MESH_BLOOM_DB_NAME).toBe('mesh-router-bloom');
  });
});
