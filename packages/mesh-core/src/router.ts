/**
 * router.ts — B-4 Phase.
 *
 * Picks transport per bundle. Strategy table:
 *
 *   online && no BLE peers  → online-bridge only
 *   offline && BLE peers    → BLE only
 *   online && BLE peers     → online-bridge (primary) + BLE (concurrent backup)
 *   neither                 → enqueue in outbox, retry later
 *
 * Public API:
 *   routeOutgoing({ bundle, msgId, channelId }, context): Promise<RouteResult>
 *   onIncoming({ handler, sseSubscribe? }): () => void
 */

import { meshState, sendFrame, onFrame } from './transport.js';
import { bridgeSend } from './online-bridge.js';
import { getToken } from './token-client.js';
import { DedupeCache } from './dedupe.js';
import { Outbox, MESH_OUTBOX_DB_NAME } from './outbox.js';
import { emitMeshMetric } from './metrics.js';
import type { Inbox } from './mailbox/inbox.js';
import type { BloomDedup } from './mailbox/dedup-bloom.js';

export interface RouteContext {
  geohash: string;
  dayUtc: string;
  identityKey: string;
}

export type RouteStrategy = 'online' | 'ble' | 'online+ble' | 'queued';

export interface RouteResult {
  strategy: RouteStrategy;
  bridgeResult?: Awaited<ReturnType<typeof bridgeSend>>;
  bleError?: string;
}

export interface RouteOutgoingArgs {
  /** The composed bundle bytes. */
  bundle: Uint8Array;
  /** Message ID — must come from composeBundle result, not re-parsed from bundle bytes. */
  msgId: string;
  /** Channel ID — must come from composeBundle result, not re-parsed from bundle bytes. */
  channelId: Uint8Array;
}

// Handler signature consumed by SseSubscribe (below); internal to this module.
type IncomingHandler = (frame: Uint8Array) => void;

/** SSE subscription hook: receives a handler, returns an unsubscribe function. */
export type SseSubscribe = (handler: IncomingHandler) => () => void;

export interface OnIncomingArgs {
  handler: IncomingHandler;
  /**
   * Optional SSE subscription hook. If provided, the router will also wire the
   * handler to the host app's SSE stream. If absent, only BLE source is active.
   */
  sseSubscribe?: SseSubscribe;
  /**
   * Optional persistent inbox. When provided, every NEW (non-dedup'd) frame
   * is stored as an InboxEntry — fire-and-forget; transient IDB errors are
   * logged but do not block handler delivery.
   *
   * Caveat for B.4 consumers: `handler(frame)` is invoked SYNCHRONOUSLY,
   * before `inbox.put` resolves. If the consumer wants to immediately
   * `inbox.markConsumed(msgId)` from inside the handler, it MUST `await` a
   * microtask first (e.g. `await Promise.resolve()`) or look up the entry
   * via `inbox.unconsumed()` on a later tick — the put may still be in
   * flight when the handler runs.
   */
  inbox?: Inbox;
  /**
   * Optional persistent Bloom dedup. Checked BEFORE the in-memory dedupe,
   * gives durable dedup across page reloads. Marked on every accepted frame.
   */
  bloom?: BloomDedup;
}

// Module-level outbox instance (lazy-opened).
let outbox: Outbox | null = null;

// Module-level dedupe cache (shared across all onIncoming subscriptions).
const dedupe = new DedupeCache();

async function getOutbox(): Promise<Outbox> {
  if (!outbox) {
    outbox = new Outbox(MESH_OUTBOX_DB_NAME);
    await outbox.open();
  }
  return outbox;
}

/**
 * Route an outgoing bundle according to the current transport strategy.
 * Caller provides the msgId and channelId directly from composeBundle result
 * — the router does NOT re-parse them from bundle bytes.
 *
 * State snapshot (online + peers) is captured once at function start so that
 * mid-await mutations do not affect the routing decision.
 */
export async function routeOutgoing(
  args: RouteOutgoingArgs,
  ctx: RouteContext,
): Promise<RouteResult> {
  // MAJOR 6: capture state snapshot once at decision time.
  const online = typeof navigator !== 'undefined' ? navigator.onLine : false;
  const peers = [...meshState.peers]; // snapshot
  const hasBle = peers.length > 0;

  const { bundle, msgId, channelId } = args;

  if (online && !hasBle) {
    // Online-only: bridge to server
    const jwt = await getToken(ctx.geohash, ctx.dayUtc, ctx.identityKey);
    const bridgeResult = await bridgeSend({ bundle, jwt });
    return { strategy: 'online', bridgeResult };
  }

  if (!online && hasBle) {
    // BLE-only: send to each known peer
    await sendToBle(bundle, peers);
    return { strategy: 'ble' };
  }

  if (online && hasBle) {
    // Dual mode (MAJOR 3): online bridge + BLE concurrent via Promise.all.
    const jwt = await getToken(ctx.geohash, ctx.dayUtc, ctx.identityKey);
    let bleError: string | undefined;
    const [bridgeResult] = await Promise.all([
      bridgeSend({ bundle, jwt }),
      sendToBle(bundle, peers).catch((err: unknown) => {
        bleError = err instanceof Error ? err.message : String(err);
      }),
    ]);
    return { strategy: 'online+ble', bridgeResult, bleError };
  }

  // Neither: enqueue for later retry using caller-provided msgId (not re-parsed from bytes).
  const ob = await getOutbox();
  await ob.enqueue({ msgId, channelId, bundle });
  return { strategy: 'queued' };
}

/**
 * Subscribe to incoming frames from BLE (and optionally SSE).
 * Deduplicates incoming bundles via DedupeCache to suppress BLE multi-peer
 * broadcast duplicates.
 * Returns an unsubscribe function that disconnects BOTH BLE and SSE listeners.
 */
export function onIncoming(args: OnIncomingArgs): () => void {
  const { handler, sseSubscribe, inbox, bloom } = args;

  // BLE subscription with dedupe gate
  const unsubBle = onFrame((_peerIdHex, frame) => {
    // Extract msgId (offset 34..50) and channelIdHash (offset 55..59) from frame.
    // Per mesh-bundle-v1 wire layout (packages/wire-codec/src/mesh-bundle.ts):
    //   offset 0:  MAGIC (1)    offset 1: VERSION (1)
    //   offset 2:  senderPubkey (32)       offset 34: msgId (16)
    //   offset 55: channelIdHash (4)
    // We use ONLY msgId + channelId as the dedupe key — not sender bytes.
    // Using offset 0..20 (sender prefix) caused every distinct msgId from the
    // same sender to collide and be silently dropped after the first.
    const msgIdHex     = bytesToHex(frame.slice(34, 50));
    const channelIdHex = bytesToHex(frame.slice(55, 59));

    // Persistent Bloom check first — cheap in-memory bit test, survives reload.
    if (bloom?.hasSeen(msgIdHex)) {
      // eslint-disable-next-line no-console
      console.debug('[router] bloom-hit drop', msgIdHex);
      return;
    }

    // In-memory LRU dedup (B-4 phase).
    if (dedupe.hasSeen(channelIdHex, msgIdHex)) {
      // eslint-disable-next-line no-console
      console.debug('[router] lru-dedup drop', channelIdHex, msgIdHex);
      return;
    }

    // Mark Bloom durable before proceeding.
    bloom?.markSeen(msgIdHex);
    dedupe.markSeen(channelIdHex, msgIdHex);

    // Persist to inbox (fire-and-forget; consumed flag = false).
    // We swallow inbox errors — the in-memory dedupe + handler call still proceed,
    // so a transient IDB hiccup does not lose the user-visible frame.
    if (inbox) {
      // Before persisting, COPY the wire bytes so inbox row owns its buffer
      // (BLE RX buffer may be pooled / re-used after the callback returns).
      const ownedChannelId = new Uint8Array(frame.slice(55, 59));  // copy
      const ownedBundle    = new Uint8Array(frame);                 // copy
      void inbox.put({
        msgId: msgIdHex,
        channelId: ownedChannelId,
        bundle: ownedBundle,
        receivedAtMs: Date.now(),
        consumed: false,
      }).catch((err) => {
        // eslint-disable-next-line no-console
        console.warn('[router] inbox.put failed:', err);
        // Metric per CLAUDE.md write-failure rule: silent IDB drops must be
        // observable. err.name discriminates QuotaExceededError / InvalidStateError /
        // etc. — operators need the specific class, not a message snippet.
        // Truncated to 80 chars; bounded label.
        const reason = err instanceof Error ? err.name : String(err);
        emitMeshMetric('inbox_put_failed', { reason: reason.slice(0, 80) });
      });
    }

    handler(frame);
  });

  // SSE subscription (if provided)
  let unsubSse: (() => void) | undefined;
  if (sseSubscribe) {
    unsubSse = sseSubscribe(handler);
  }

  return () => {
    unsubBle();
    unsubSse?.();
  };
}

// ─── Internal helpers ───────────────────────────────────────────────────────

async function sendToBle(bundle: Uint8Array, peers: typeof meshState.peers): Promise<void> {
  await Promise.all(peers.map((peer) => sendFrame(peer.idHex, bundle)));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
