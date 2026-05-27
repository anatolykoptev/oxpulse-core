/**
 * Tests for online-bridge.ts (B-4 Phase).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { bridgeSend } from '../online-bridge.js';

const FAKE_BUNDLE = new Uint8Array([0xc9, 0x01, 0x02]);
const JWT = 'eyJhbGciOiJFZERTQSJ9.test.sig';

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('bridgeSend', () => {
  it('returns ok:true on HTTP 200 with ok result', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'ok' }), { status: 200 }),
    ));
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT });
    expect(res.ok).toBe(true);
  });

  it('includes seq on HTTP 200 with seq in response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'ok', seq: 42 }), { status: 200 }),
    ));
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.seq).toBe(42);
  });

  it('maps 401 to bad_jwt reason', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'bad_jwt' }), { status: 401 }),
    ));
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.status).toBe(401);
      expect(res.reason).toBe('bad_jwt');
    }
  });

  it('maps 403 to channel_mismatch reason', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'channel_mismatch' }), { status: 403 }),
    ));
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('channel_mismatch');
  });

  it('maps 429 to rate_limited reason', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response('', { status: 429 }),
    ));
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('rate_limited');
  });

  it('returns ok:false on network error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('fetch failed')));
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('network_error');
  });

  it('sends Content-Type: application/octet-stream', async () => {
    let capturedInit: RequestInit | undefined;
    vi.stubGlobal('fetch', vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(new Response(JSON.stringify({ result: 'ok' }), { status: 200 }));
    }));
    await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT });
    const headers = capturedInit!.headers as Record<string, string>;
    expect(headers['content-type']).toBe('application/octet-stream');
  });
});

describe('bridgeSend — onResult callback (BLOCKER 4)', () => {
  it('calls onResult exactly once on ok:true', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'ok', seq: 1 }), { status: 200 }),
    ));
    const onResult = vi.fn();
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult });
    expect(onResult).toHaveBeenCalledOnce();
    expect(onResult).toHaveBeenCalledWith(res);
  });

  it('calls onResult exactly once on bad_jwt (401)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'bad_jwt' }), { status: 401 }),
    ));
    const onResult = vi.fn();
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult });
    expect(onResult).toHaveBeenCalledOnce();
    expect(onResult).toHaveBeenCalledWith(res);
    expect(res.ok).toBe(false);
  });

  it('calls onResult exactly once on bad_signature', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'bad_signature' }), { status: 403 }),
    ));
    const onResult = vi.fn();
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult });
    expect(onResult).toHaveBeenCalledOnce();
    if (!res.ok) expect(res.reason).toBe('bad_signature');
  });

  it('calls onResult exactly once on bad_bundle', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'bad_bundle' }), { status: 400 }),
    ));
    const onResult = vi.fn();
    await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult });
    expect(onResult).toHaveBeenCalledOnce();
  });

  it('calls onResult exactly once on channel_mismatch', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'channel_mismatch' }), { status: 403 }),
    ));
    const onResult = vi.fn();
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult });
    expect(onResult).toHaveBeenCalledOnce();
    if (!res.ok) expect(res.reason).toBe('channel_mismatch');
  });

  it('calls onResult exactly once on network_error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('fetch failed')));
    const onResult = vi.fn();
    const res = await bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult });
    expect(onResult).toHaveBeenCalledOnce();
    expect(onResult).toHaveBeenCalledWith(res);
    if (!res.ok) expect(res.reason).toBe('network_error');
  });

  it('does not throw when onResult is omitted', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'ok' }), { status: 200 }),
    ));
    await expect(bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT })).resolves.toBeDefined();
  });
});

describe('bridgeSend — onResult guard (M3)', () => {
  it('bridgeSend does NOT throw when onResult itself throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: 'ok', seq: 1 }), { status: 200 }),
    ));
    const throwingOnResult = () => { throw new Error('onResult internal error'); };
    // Must not propagate — bridgeSend contract says never throws
    await expect(bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult: throwingOnResult })).resolves.toBeDefined();
  });

  it('bridgeSend does NOT throw when onResult throws on network_error path', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('fetch failed')));
    const throwingOnResult = () => { throw new Error('onResult boom'); };
    await expect(bridgeSend({ bundle: FAKE_BUNDLE, jwt: JWT, onResult: throwingOnResult })).resolves.toBeDefined();
  });
});
