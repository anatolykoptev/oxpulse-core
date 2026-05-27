/**
 * outbox-drainer.ts — Phase 3 T6.
 *
 * Drains the pending mesh-outbox when the browser fires the 'online' event.
 * SSR-safe: returns a no-op dispose function when `window` is undefined.
 *
 * API:
 *   startOutboxDrainer(deps) → dispose
 *
 * Drain contract:
 *   - Loops outbox.nextPending() up to MAX_DRAIN_PER_CYCLE times.
 *   - For each entry: calls bridgeSend(entry).
 *       ok:true  → outbox.markSent(id)
 *       ok:false → outbox.markFailed(id) + stop (back-off until next 'online')
 *   - Stops immediately on the first hard error (network drop, etc.).
 */

import type { OutboxEntry } from './outbox.js';

/** Maximum entries drained per single 'online' event (guards runaway loops). */
const MAX_DRAIN_PER_CYCLE = 50;

export interface DrainBridgeSendResult {
  ok: boolean;
  status?: number;
  reason?: string;
}

export interface OutboxDrainerDeps {
  outbox: {
    nextPending(): Promise<OutboxEntry | null>;
    markSent(msgId: string): Promise<void>;
    markFailed(msgId: string): Promise<void>;
  };
  bridgeSend(entry: OutboxEntry): Promise<DrainBridgeSendResult>;
  onError?: (err: unknown) => void;
}

/**
 * Registers a listener on `window.addEventListener('online', drain)`.
 * Returns a dispose function that removes the listener.
 */
export function startOutboxDrainer(deps: OutboxDrainerDeps): () => void {
  // SSR-safe guard.
  if (typeof window === 'undefined') {
    return () => { /* noop */ };
  }

  const { outbox, bridgeSend, onError } = deps;

  // B2: in-flight guard — prevents two concurrent online events from running
  // two drain loops simultaneously and double-sending the same pending entry.
  // Non-re-entrant serial queue: if drain is already running, the second
  // 'online' event is dropped; it will retry on the next event.
  let draining = false;

  async function drain(): Promise<void> {
    if (draining) return;
    draining = true;
    let drained = 0;
    try {
      while (drained < MAX_DRAIN_PER_CYCLE) {
        const entry = await outbox.nextPending();
        if (entry === null) break;

        const result = await bridgeSend(entry);
        if (result.ok) {
          await outbox.markSent(entry.msgId);
        } else {
          // Hard error — mark failed and stop; retry on next 'online' event.
          await outbox.markFailed(entry.msgId);
          break;
        }
        drained++;
      }
    } catch (err) {
      onError?.(err);
    } finally {
      draining = false;
    }
  }

  window.addEventListener('online', drain);
  return () => window.removeEventListener('online', drain);
}
