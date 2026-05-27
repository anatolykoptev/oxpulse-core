/**
 * Tests for outbox-drainer.ts (Phase 3 T6).
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { startOutboxDrainer } from '../outbox-drainer.js';
import type { OutboxEntry } from '../outbox.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEntry(msgId: string): OutboxEntry {
  return {
    msgId,
    channelId: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
    bundle: new Uint8Array([0xca, 0xfe]),
    attempts: 0,
    lastAttemptMs: 0,
    status: 'pending',
  };
}

function drainMicrotasks(n = 20): Promise<void> {
  // Drain pending microtasks / promise resolutions produced by the drain loop.
  let p: Promise<void> = Promise.resolve();
  for (let i = 0; i < n; i++) p = p.then(() => Promise.resolve());
  return p;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const onlineEvent = new Event('online');

function fireOnline(): void {
  window.dispatchEvent(onlineEvent);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('startOutboxDrainer', () => {
  let addListener: ReturnType<typeof vi.spyOn>;
  let removeListener: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    addListener = vi.spyOn(window, 'addEventListener');
    removeListener = vi.spyOn(window, 'removeEventListener');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Happy path: 3 pending entries all sent
  // -------------------------------------------------------------------------

  it('sends all 3 pending entries when online fires', async () => {
    const entries = [makeEntry('a'), makeEntry('b'), makeEntry('c')];
    let idx = 0;

    const outbox = {
      nextPending: vi.fn(async () => entries[idx] ?? null),
      markSent: vi.fn(async (msgId: string) => {
        // Advance cursor so next call returns the next entry
        idx++;
      }),
      markFailed: vi.fn(async (_msgId: string) => {}),
    };

    const bridgeSend = vi.fn(async (_entry: OutboxEntry) => ({ ok: true as const }));
    const onError = vi.fn();

    startOutboxDrainer({ outbox, bridgeSend, onError });
    fireOnline();
    await drainMicrotasks(40);

    expect(bridgeSend).toHaveBeenCalledTimes(3);
    expect(outbox.markSent).toHaveBeenCalledTimes(3);
    expect(outbox.markSent).toHaveBeenCalledWith('a');
    expect(outbox.markSent).toHaveBeenCalledWith('b');
    expect(outbox.markSent).toHaveBeenCalledWith('c');
    expect(outbox.markFailed).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Hard error on item 2: item 1 sent, items 2+3 retain pending
  // -------------------------------------------------------------------------

  it('stops on first bridgeSend failure — item 1 sent, items 2+3 stay pending', async () => {
    const entries = [makeEntry('x'), makeEntry('y'), makeEntry('z')];
    let idx = 0;

    const outbox = {
      nextPending: vi.fn(async () => entries[idx] ?? null),
      markSent: vi.fn(async (_msgId: string) => { idx++; }),
      markFailed: vi.fn(async (_msgId: string) => { idx++; }),
    };

    const bridgeSend = vi.fn(async (entry: OutboxEntry) => {
      if (entry.msgId === 'y') return { ok: false as const, status: 0, reason: 'network_error' as const };
      return { ok: true as const };
    });

    startOutboxDrainer({ outbox, bridgeSend });
    fireOnline();
    await drainMicrotasks(40);

    // item x sent
    expect(outbox.markSent).toHaveBeenCalledWith('x');
    // item y failed (not sent)
    expect(outbox.markFailed).toHaveBeenCalledWith('y');
    // item z never reached
    expect(bridgeSend).toHaveBeenCalledTimes(2);
    expect(outbox.markSent).not.toHaveBeenCalledWith('z');
  });

  // -------------------------------------------------------------------------
  // Dispose removes 'online' listener
  // -------------------------------------------------------------------------

  it('dispose() removes the online event listener', () => {
    const outbox = {
      nextPending: vi.fn(async () => null),
      markSent: vi.fn(async (_msgId: string) => {}),
      markFailed: vi.fn(async (_msgId: string) => {}),
    };
    const bridgeSend = vi.fn(async (_entry: OutboxEntry) => ({ ok: true as const }));

    const dispose = startOutboxDrainer({ outbox, bridgeSend });
    expect(addListener).toHaveBeenCalledWith('online', expect.any(Function));

    const registeredFn = (addListener.mock.calls[0] as [string, EventListenerOrEventListenerObject])[1];
    dispose();
    expect(removeListener).toHaveBeenCalledWith('online', registeredFn);
  });

  // -------------------------------------------------------------------------
  // SSR-safe: returns noop when window is undefined
  // -------------------------------------------------------------------------

  it('returns noop dispose without error when window is undefined', () => {
    const savedWindow = globalThis.window;
    // Simulate SSR — remove window from globalThis
    // @ts-expect-error intentional SSR simulation
    delete globalThis.window;

    const outbox = {
      nextPending: vi.fn(async () => null),
      markSent: vi.fn(async (_msgId: string) => {}),
      markFailed: vi.fn(async (_msgId: string) => {}),
    };
    const bridgeSend = vi.fn(async (_entry: OutboxEntry) => ({ ok: true as const }));

    let dispose: (() => void) | undefined;
    expect(() => {
      dispose = startOutboxDrainer({ outbox, bridgeSend });
    }).not.toThrow();
    expect(() => dispose?.()).not.toThrow();

    // Restore
    globalThis.window = savedWindow;
  });

  // -------------------------------------------------------------------------
  // B2: concurrent drain guard — two rapid 'online' events must not double-send
  // -------------------------------------------------------------------------

  it('B2: two rapid online events do not double-send the same pending entry (in-flight guard)', async () => {
    // Simulate a scenario where a single entry is pending and both online
    // events could trigger drain() concurrently. Without an in-flight guard,
    // a naive implementation would have both drains pick up the same entry
    // and call bridgeSend twice — because nextPending is stateless async and
    // both drains would call it before markSent removes the entry from the queue.
    //
    // We simulate this by making nextPending return the entry on ALL calls
    // until markSent is called (mimicking a real outbox where the entry is
    // only removed after markSent). This isolates the guard's job.
    const entry = makeEntry('msg-concurrent');
    let sent = false;

    const outbox = {
      nextPending: vi.fn(async () => {
        // Entry is available until markSent is called.
        return sent ? null : entry;
      }),
      markSent: vi.fn(async (_msgId: string) => { sent = true; }),
      markFailed: vi.fn(async (_msgId: string) => {}),
    };

    const bridgeSend = vi.fn(async (_entry: OutboxEntry) => ({ ok: true as const }));

    startOutboxDrainer({ outbox, bridgeSend });

    // Fire two online events synchronously before the event loop runs.
    // With a guard: second drain is dropped immediately.
    // Without a guard: both drains call nextPending and see sent=false → double-send.
    fireOnline();
    fireOnline();

    await drainMicrotasks(60);

    // Guard invariant: bridgeSend called exactly once despite two concurrent drains.
    expect(bridgeSend).toHaveBeenCalledTimes(1);
    expect(outbox.markSent).toHaveBeenCalledWith('msg-concurrent');
  });
});
