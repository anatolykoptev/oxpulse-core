/**
 * Tests for dedupe.ts (B-4 Phase).
 * RED: module does not exist yet.
 */
import { describe, it, expect } from 'vitest';
import { DedupeCache } from '../dedupe.js';

describe('DedupeCache', () => {
  it('hasSeen returns false for unseen entry', () => {
    const cache = new DedupeCache();
    expect(cache.hasSeen('ch1', 'msg1')).toBe(false);
  });

  it('hasSeen returns true after markSeen', () => {
    const cache = new DedupeCache();
    cache.markSeen('ch1', 'msg1');
    expect(cache.hasSeen('ch1', 'msg1')).toBe(true);
  });

  it('different channelId with same msgId are independent', () => {
    const cache = new DedupeCache();
    cache.markSeen('ch1', 'msg1');
    expect(cache.hasSeen('ch2', 'msg1')).toBe(false);
  });

  it('same channelId different msgId are independent', () => {
    const cache = new DedupeCache();
    cache.markSeen('ch1', 'msg1');
    expect(cache.hasSeen('ch1', 'msg2')).toBe(false);
  });

  it('LRU evicts oldest when capacity exceeded', () => {
    const cache = new DedupeCache({ capacity: 3 });
    cache.markSeen('ch', 'a');
    cache.markSeen('ch', 'b');
    cache.markSeen('ch', 'c');
    cache.markSeen('ch', 'd');
    expect(cache.hasSeen('ch', 'a')).toBe(false);
    expect(cache.hasSeen('ch', 'b')).toBe(true);
    expect(cache.hasSeen('ch', 'c')).toBe(true);
    expect(cache.hasSeen('ch', 'd')).toBe(true);
  });

  it('default capacity is 5000 (smoke — does not OOM)', () => {
    const cache = new DedupeCache();
    for (let i = 0; i < 5001; i++) {
      cache.markSeen('ch', `msg-${i}`);
    }
    expect(cache.hasSeen('ch', 'msg-0')).toBe(false);
    expect(cache.hasSeen('ch', 'msg-5000')).toBe(true);
  });

  it('clear() empties the cache (MINOR)', () => {
    const cache = new DedupeCache();
    cache.markSeen('ch', 'msg1');
    cache.markSeen('ch', 'msg2');
    cache.clear();
    expect(cache.hasSeen('ch', 'msg1')).toBe(false);
    expect(cache.hasSeen('ch', 'msg2')).toBe(false);
  });

  it('clear() allows re-marking after clear', () => {
    const cache = new DedupeCache();
    cache.markSeen('ch', 'msg1');
    cache.clear();
    cache.markSeen('ch', 'msg1');
    expect(cache.hasSeen('ch', 'msg1')).toBe(true);
  });
});
