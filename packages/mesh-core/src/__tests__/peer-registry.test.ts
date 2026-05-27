import { describe, it, expect, vi } from 'vitest';
import { PeerRegistry, generatePeerId } from '../peer-registry';

describe('peer registry', () => {
  it('generates 8-byte peer id', () => {
    const id = generatePeerId();
    expect(id.length).toBe(8);
  });

  it('upserts by hex(peer-id), updates last-seen', () => {
    vi.useFakeTimers();
    const r = new PeerRegistry();
    const id = new Uint8Array([1,2,3,4,5,6,7,8]);
    r.upsert(id, 'AA:BB:CC:DD:EE:FF');
    expect(r.list().length).toBe(1);
    expect(r.list()[0].lastSeen).toBe(Date.now());
    vi.advanceTimersByTime(1000);
    r.upsert(id, 'AA:BB:CC:DD:EE:FF');
    expect(r.list()[0].lastSeen).toBe(Date.now());
    expect(r.list().length).toBe(1);
    vi.useRealTimers();
  });

  it('expires entries older than ttl', () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const r = new PeerRegistry({ ttlMs: 60_000 });
    r.upsert(new Uint8Array(8), 'mac1');
    vi.setSystemTime(120_000);
    r.gc();
    expect(r.list().length).toBe(0);
    vi.useRealTimers();
  });
});
