/**
 * metrics.ts — client-side mesh error counter abstraction (Phase B.2).
 *
 * mesh-core runs in browser / Capacitor (no server-side Prometheus).
 * This module provides a pluggable sink so callers can wire console.warn
 * in dev or push to an analytics endpoint in prod — without coupling
 * mesh-core to any specific observability stack.
 *
 * Usage:
 *   import { setMeshMetricSink, emitMeshMetric } from './metrics.js';
 *   setMeshMetricSink((metric, labels) => { ... });
 */

/** All observable mesh error kinds tracked by the counter system. */
export type MeshMetric =
  | 'handshake_failed'
  | 'replay_rejected'
  | 'sas_mismatch'
  | 'unknown_peer_key'
  | 'tofu_evicted'
  | 'handshake_timeout'
  // B.3 mailbox: IDB write failure during inbox.put() (router.ts fire-and-forget path).
  // label: reason — err.name (e.g. QuotaExceededError, InvalidStateError), max 80 chars.
  | 'inbox_put_failed'
  // B.3 mailbox: entries evicted by bounded put() or evictExcess() to enforce maxEntries cap.
  // label: store — 'inbox' | 'spool'. Value is the count evicted (emit once per eviction batch).
  | 'mailbox_evicted'
  // B.3 mailbox: QuotaExceededError caught during put(), triggering aggressive eviction + retry.
  // label: store — 'inbox' | 'spool'.
  | 'mailbox_quota_exceeded'
  // B.4 router: BLE send failure in dual mode (online+ble). Strategy downgrades to 'online'.
  // label: reason — error message, max 80 chars.
  | 'ble_send_failed'
  // S3: handshake frame dropped because mesh stopped during identity bootstrap.
  // The guard correctly prevents processing, but the drop must be observable.
  | 'handshake_frame_dropped'
  // S7: BLE connection limit reached — new connection attempt skipped.
  | 'ble_connection_limit_reached'
  // #44: backoff/backoffCounts entries cleared on device disconnect to prevent
  // unbounded Map growth on device churn. label: device — BLE MAC string.
  | 'backoff_cleared'
  // #45: Bloom filter params (m, k) changed between sessions — existing bits
  // discarded because they cannot be re-mapped. labels: old_m, new_m, old_k, new_k.
  | 'bloom_params_changed'
  // #46: handshakeFailures counter reset to 0 on successful handshake completion.
  // Enforces the invariant that failures count within a single handshake attempt,
  // not across the lifetime of a CryptoState. label: device — BLE MAC string.
  | 'handshake_failures_reset'
  // #91: outbound handshake init aborted because the peer disconnected during
  // the getLocalIdentity() await. Creating the CryptoState anyway would leak a
  // live NoiseXxHandshake — handshake key material for a connection that is
  // already gone, which nothing reaps before stopMesh().
  //
  // PAIRS WITH handshake_frame_dropped{reason=disconnected}, which the RESPONDER
  // path emits for the identical condition. An operator asking "how often does a
  // handshake abort because the peer vanished mid-bootstrap" must read BOTH:
  // this one counts handshakes we initiated, that one counts handshakes the peer
  // initiated. They are deliberately separate because that metric means an
  // inbound FRAME was discarded, and conflating the two would mislead anyone
  // debugging inbound frame loss.
  // label: device — BLE MAC string.
  | 'handshake_init_aborted';

/** A function that receives each emitted metric (plus optional bounded labels). */
export type MetricSink = (metric: MeshMetric, labels?: Record<string, string>) => void;

// Module-level no-op default — safe before setMeshMetricSink is called.
let sink: MetricSink = () => {};

/**
 * Register a MetricSink to receive all subsequent emitMeshMetric calls.
 * Replaces any previously registered sink. Call once at boot (e.g. +layout.svelte onMount).
 */
export function setMeshMetricSink(fn: MetricSink): void {
  sink = fn;
}

/**
 * Emit a mesh metric event to the currently registered sink.
 * Labels must use bounded values (enums / small enumerables) — no free strings.
 * Safe to call before setMeshMetricSink (no-op default sink absorbs it).
 */
export function emitMeshMetric(metric: MeshMetric, labels?: Record<string, string>): void {
  sink(metric, labels);
}
