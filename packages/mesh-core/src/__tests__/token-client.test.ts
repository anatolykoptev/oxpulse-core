/**
 * Tests for token-client.ts (B-4 Phase).
 * RED: module does not exist yet.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getToken, clearTokens, clearTokensForIdentity } from '../token-client.js';

const GEO = 'gcpv';
const DAY = '2026-05-16';
const ID_A = 'identity-aaa';
const ID_B = 'identity-bbb';

function makeFakeJwt(expiresInSec: number): string {
  const exp = Math.floor(Date.now() / 1000) + expiresInSec;
  const payload = btoa(JSON.stringify({ exp, aud: 'mesh_public_v1' }));
  return `eyJhbGciOiJFZERTQSJ9.${payload}.fakesig`;
}

function mockFetchOnce(jwt: string) {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify({ token: jwt }), { status: 200 }),
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  clearTokens();
});

describe('getToken — identity isolation', () => {
  it('fetches a new token on first call', async () => {
    const jwt = makeFakeJwt(3600);
    vi.stubGlobal('fetch', mockFetchOnce(jwt));
    const result = await getToken(GEO, DAY, ID_A);
    expect(result).toBe(jwt);
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it('returns cached token on second call within TTL (same identity)', async () => {
    const jwt = makeFakeJwt(3600);
    vi.stubGlobal('fetch', mockFetchOnce(jwt));
    await getToken(GEO, DAY, ID_A);
    const result = await getToken(GEO, DAY, ID_A);
    expect(result).toBe(jwt);
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it('fetches separately for different identities (no cross-identity leak)', async () => {
    const jwtA = makeFakeJwt(3600);
    const jwtB = makeFakeJwt(3600);
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: jwtA }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: jwtB }), { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);
    const resultA = await getToken(GEO, DAY, ID_A);
    const resultB = await getToken(GEO, DAY, ID_B);
    expect(resultA).toBe(jwtA);
    expect(resultB).toBe(jwtB);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('does NOT return identity-A token for identity-B (no cross-identity leak)', async () => {
    const jwtA = makeFakeJwt(3600);
    const jwtB = makeFakeJwt(3600);
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: jwtA }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: jwtB }), { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);
    await getToken(GEO, DAY, ID_A);
    const resultB = await getToken(GEO, DAY, ID_B);
    // B must NOT get A's token
    expect(resultB).toBe(jwtB);
  });

  it('re-fetches when cached token is near expiry (exp-5min buffer)', async () => {
    const expiredJwt = makeFakeJwt(240); // 4 min left → within 5-min buffer
    const freshJwt = makeFakeJwt(3600);
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: expiredJwt }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: freshJwt }), { status: 200 }));
    vi.stubGlobal('fetch', mockFetch);
    await getToken(GEO, DAY, ID_A);
    const result = await getToken(GEO, DAY, ID_A);
    expect(result).toBe(freshJwt);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('throws on non-200 response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response('Unauthorized', { status: 401 }),
    ));
    await expect(getToken(GEO, DAY, ID_A)).rejects.toThrow(/401/);
  });
});

describe('getToken — LRU cache bound (TOKEN_CACHE_MAX_SIZE)', () => {
  it('33rd unique entry evicts the oldest entry', async () => {
    // Fill 32 slots (identity 0..31, same geo/day)
    const makeJwt = (i: number) => makeFakeJwt(3600);
    const fetchImpl = vi.fn().mockImplementation((_url: string, opts: RequestInit) => {
      // Return unique JWT per call
      const jwt = makeFakeJwt(3600);
      return Promise.resolve(new Response(JSON.stringify({ token: jwt }), { status: 200 }));
    });
    vi.stubGlobal('fetch', fetchImpl);

    for (let i = 0; i < 32; i++) {
      await getToken(GEO, DAY, `identity-${i}`);
    }
    expect(fetchImpl).toHaveBeenCalledTimes(32);

    // Now add the 33rd — should evict identity-0's slot
    await getToken(GEO, DAY, 'identity-32');
    expect(fetchImpl).toHaveBeenCalledTimes(33);

    // identity-0 should have been evicted — re-fetch triggers fetch call
    await getToken(GEO, DAY, 'identity-0');
    expect(fetchImpl).toHaveBeenCalledTimes(34); // must re-fetch identity-0
  });
});

describe('clearTokens / clearTokensForIdentity', () => {
  it('clearTokens empties all cached tokens (re-fetch required)', async () => {
    const jwt = makeFakeJwt(3600);
    // Use mockImplementation to return a fresh Response each call —
    // a single Response object's body can only be consumed once.
    const mockFetch = vi.fn().mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify({ token: jwt }), { status: 200 })),
    );
    vi.stubGlobal('fetch', mockFetch);
    await getToken(GEO, DAY, ID_A);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    clearTokens();
    await getToken(GEO, DAY, ID_A); // must re-fetch
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('clearTokensForIdentity evicts only that identity', async () => {
    const jwtA = makeFakeJwt(3600);
    const jwtB = makeFakeJwt(3600);
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: jwtA }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: jwtB }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: jwtA }), { status: 200 })); // re-fetch A
    vi.stubGlobal('fetch', mockFetch);
    await getToken(GEO, DAY, ID_A);
    await getToken(GEO, DAY, ID_B);
    expect(mockFetch).toHaveBeenCalledTimes(2);

    clearTokensForIdentity(ID_A);

    // B still cached (no re-fetch)
    await getToken(GEO, DAY, ID_B);
    expect(mockFetch).toHaveBeenCalledTimes(2);

    // A must re-fetch
    await getToken(GEO, DAY, ID_A);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });
});

describe('getToken — true LRU (hit refreshes recency) (M1)', () => {
  it('cache hit on entry-0 keeps it alive; entry-1 evicts instead of entry-0 on 33rd insert', async () => {
    // Fill slots 0..31
    const fetchImpl = vi.fn().mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify({ token: makeFakeJwt(3600) }), { status: 200 })),
    );
    vi.stubGlobal('fetch', fetchImpl);
    for (let i = 0; i < 32; i++) {
      await getToken(GEO, DAY, `identity-${i}`);
    }
    expect(fetchImpl).toHaveBeenCalledTimes(32);

    // Hit entry-0 → must move to MRU position (no fetch, just cache hit)
    const tok0 = await getToken(GEO, DAY, 'identity-0');
    expect(fetchImpl).toHaveBeenCalledTimes(32); // no extra fetch

    // Add 33rd unique entry — now LRU is identity-1, NOT identity-0
    await getToken(GEO, DAY, 'identity-32');
    expect(fetchImpl).toHaveBeenCalledTimes(33);

    // identity-1 must have been evicted (LRU) → requires re-fetch
    await getToken(GEO, DAY, 'identity-1');
    expect(fetchImpl).toHaveBeenCalledTimes(34);

    // identity-0 must STILL be cached (it was hit after the fill, making it MRU)
    await getToken(GEO, DAY, 'identity-0');
    expect(fetchImpl).toHaveBeenCalledTimes(34); // no re-fetch for identity-0
  });
});
