import { describe, it, expect, vi, afterEach } from 'vitest';
import { getRegionFallback, channelIdHash, neighboringChannelIds, currentChannelId } from '../channel.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('getRegionFallback', () => {
  it('returns null for unknown region key', () => {
    expect(getRegionFallback('unknown-region')).toBeNull();
  });

  it('returns lat/lon for known region key (Moscow)', () => {
    const r = getRegionFallback('moscow');
    expect(r).not.toBeNull();
    expect(r!.lat).toBeCloseTo(55.75, 1);
    expect(r!.lon).toBeCloseTo(37.62, 1);
  });
});

describe('channelIdHash', () => {
  // --- MAJOR 5: instanceof Date assertion ---
  it('throws TypeError when non-Date is passed as date', () => {
    // String that looks like a date is NOT a Date object — must throw
    expect(() => channelIdHash(0, 0, '2026-01-01' as unknown as Date)).toThrow(TypeError);
    expect(() => channelIdHash(0, 0, 1234567890 as unknown as Date)).toThrow(TypeError);
  });

  // --- MAJOR 4: determinism ---
  it('channelIdHash is deterministic: same lat/lon/date → same hex', () => {
    const d = new Date('2026-05-16T12:00:00Z');
    const a = channelIdHash(55.7558, 37.6173, d);
    const b = channelIdHash(55.7558, 37.6173, d);
    expect(a.hex).toBe(b.hex);
    expect(a.geohash).toBe(b.geohash);
    expect(a.dayUtc).toBe('2026-05-16');
  });

  // --- MAJOR 4: day rollover ---
  it('different UTC day → different hex', () => {
    // These two timestamps are seconds apart but cross midnight UTC
    const before = channelIdHash(55.7558, 37.6173, new Date('2026-05-16T23:59:59Z'));
    const after = channelIdHash(55.7558, 37.6173, new Date('2026-05-17T00:00:01Z'));
    expect(before.dayUtc).toBe('2026-05-16');
    expect(after.dayUtc).toBe('2026-05-17');
    expect(before.hex).not.toBe(after.hex);
  });

  // --- CRITICAL: wire-format reference vector (no pipe separator) ---
  // Computed once from: encodeGeohash(0,0,4)='s000' + '2026-01-01' → BLAKE3 → first 4 bytes
  // New format: raw concat '${geohash}${dayUtc}' — no | separator.
  // This test WILL FAIL against the old '${geohash}|${dayUtc}' format (which produces 'c31999b5').
  // Locking this hex string permanently protects against silent wire-format drift.
  it('reference vector: channelIdHash(0, 0, 2026-01-01T00:00:00Z) = b6e1d007', () => {
    const result = channelIdHash(0, 0, new Date('2026-01-01T00:00:00Z'));
    expect(result.geohash).toBe('s000');
    expect(result.dayUtc).toBe('2026-01-01');
    // CRITICAL: 'b6e1d007' = BLAKE3('s0002026-01-01').slice(0,4).hex (no pipe separator)
    // If this fails with 'c31999b5', the separator bug is still present.
    expect(result.hex).toBe('b6e1d007');
  });
});

describe('neighboringChannelIds', () => {
  // --- MAJOR 4: ≤9 unique ids and always includes centroid ---
  it('returns at most 9 unique ids', () => {
    const ids = neighboringChannelIds(55.7558, 37.6173, new Date('2026-05-16T00:00:00Z'));
    expect(ids.length).toBeGreaterThan(0);
    expect(ids.length).toBeLessThanOrEqual(9);
    // All values must be unique (Set contract)
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('always includes the centroid channel id', () => {
    const date = new Date('2026-05-16T00:00:00Z');
    const centroid = channelIdHash(55.7558, 37.6173, date).hex;
    const ids = neighboringChannelIds(55.7558, 37.6173, date);
    expect(ids).toContain(centroid);
  });

  it('returns at most 9 unique ids for (0, 0)', () => {
    const ids = neighboringChannelIds(0, 0, new Date('2026-01-01T00:00:00Z'));
    expect(ids.length).toBeGreaterThan(0);
    expect(ids.length).toBeLessThanOrEqual(9);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('currentChannelId', () => {
  // --- Regression: navigator.permissions undefined must not hang ---
  // If navigator.permissions is undefined, the error callback must still
  // resolve cleanly (not throw synchronously inside the Promise, which would
  // leave resolve() never called → infinite hang).
  it('resolves with reason:timeout when permissions API unavailable and error code=3', async () => {
    // Simulate: GPS errors with TIMEOUT (code 3), no permissions API
    const originalNav = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true,
      value: {
        geolocation: {
          getCurrentPosition: (
            _success: PositionCallback,
            error: PositionErrorCallback,
          ) => {
            // code 3 = TIMEOUT, permissions API absent
            error({ code: 3, message: 'Timeout', PERMISSION_DENIED: 1, POSITION_UNAVAILABLE: 2, TIMEOUT: 3 } as GeolocationPositionError);
          },
        },
        // no permissions property — should not hang
      },
    });

    try {
      const result = await currentChannelId(new Date('2026-05-16T00:00:00Z'));
      // Must resolve (not hang), reason must be 'timeout' (code != 1, no permissions API)
      expect(result.channelId).toBeNull();
      expect(result.reason).toBe('timeout');
    } finally {
      if (originalNav) {
        Object.defineProperty(globalThis, 'navigator', originalNav);
      }
    }
  }, 5000); // 5s timeout — if it hangs we'll know

  it('resolves with reason:denied when error code=1 (PERMISSION_DENIED)', async () => {
    const originalNav = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true,
      value: {
        geolocation: {
          getCurrentPosition: (
            _success: PositionCallback,
            error: PositionErrorCallback,
          ) => {
            error({ code: 1, message: 'Permission denied', PERMISSION_DENIED: 1, POSITION_UNAVAILABLE: 2, TIMEOUT: 3 } as GeolocationPositionError);
          },
        },
        // no permissions API needed for code=1 path
      },
    });

    try {
      const result = await currentChannelId(new Date('2026-05-16T00:00:00Z'));
      expect(result.channelId).toBeNull();
      expect(result.reason).toBe('denied');
    } finally {
      if (originalNav) {
        Object.defineProperty(globalThis, 'navigator', originalNav);
      }
    }
  }, 5000);
});
