/**
 * transport.ts — public mesh façade.
 *
 * Wires together: BLE advertiser + scanner, GATT channel, peer registry,
 * frame reassembler, MAC rotation timer, Noise XX + ML-KEM-768 handshake,
 * and post-handshake AEAD session into a single start/stop API.
 *
 * Security (Phase B.2): first frames per peer = Noise XX handshake
 * (frame_type 0/1/2); subsequent frames = AEAD session (frame_type 3).
 * TOFU registry in localStorage: first pubkey trusted, mismatch flagged.
 */

import { MeshGatt, startAdvertising, stopAdvertising } from './ble-advertiser.js';
import { startScan, stopScan } from './ble-scanner.js';
import { connect, disconnect, writeRx, subscribeTx, negotiateMtu } from './gatt-channel.js';
import { PeerRegistry, generatePeerId } from './peer-registry.js';
import type { Peer } from './peer-registry.js';
import { MacRotationTimer } from './mac-rotation.js';
import { FrameReassembler, chunkFrame, FrameType } from './frame.js';
import { GATT_MTU_DEFAULT, HANDSHAKE_TIMEOUT_MS, TOFU_MAX_ENTRIES, MAX_BLE_CONNECTIONS } from './constants.js';
import { NoiseXxHandshake, NoiseStateError } from './crypto/noise-xx.js';
import type { NoiseSplit } from './crypto/noise-xx.js';
import { RatchetSession } from './crypto/session-ratchet.js';
import { toBufferSource } from './crypto/buffer.js';
import { getOrCreateDeviceIdentity, fromBase64url, getOrCreateX25519Keypair, dhX25519 as identityDhX25519 } from '@oxpulse/identity';
import { ed25519 as nobleEd25519 } from '@noble/curves/ed25519.js';
import { emitMeshMetric } from './metrics.js';

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

/** Classification of startMesh failure modes for UI-driven recovery CTAs (D2).
 * Crypto error kinds (B.2) are a strict subset — see crypto/errors.ts for isCryptoError(). */
export type MeshErrorKind =
  | 'ble-off'
  | 'permission-denied'
  | 'plugin-absent'
  | 'handshake-failed'
  | 'replay-rejected'
  | 'sas-mismatch'
  | 'unknown-peer-key'
  | 'unknown'
  | null;

export const meshState: {
  peers: Peer[];
  advertising: boolean;
  scanning: boolean;
  /** Null when mesh is running or never started. Set on startMesh failure. */
  error: MeshErrorKind;
} = {
  peers: [],
  advertising: false,
  scanning: false,
  error: null,
};

type FrameHandler = (peerIdHex: string, frame: Uint8Array) => void;
const frameHandlers = new Set<FrameHandler>();

// E5: event-driven handshake state notifications.
// Fires when any CryptoState transitions (verdict or sas set).
// Replaces 500ms polling in HandshakePanel.
type HandshakeChangeHandler = () => void;
const handshakeChangeHandlers = new Set<HandshakeChangeHandler>();

/** Subscribe to handshake state changes. Returns unsubscribe function.
 * Fires when any pending handshake's SAS becomes available or verdict changes. */
export function onHandshakeStateChange(handler: HandshakeChangeHandler): () => void {
  handshakeChangeHandlers.add(handler);
  return () => { handshakeChangeHandlers.delete(handler); };
}

function notifyHandshakeChange(): void {
  for (const h of handshakeChangeHandlers) {
    try { h(); } catch { /* ignore listener errors */ }
  }
}

// Per-session singletons — reset on each startMesh/stopMesh cycle.
let registry = new PeerRegistry();
let macRotation: MacRotationTimer | null = null;
let peerId: Uint8Array | null = null;
let gcInterval: ReturnType<typeof setInterval> | undefined;
let handshakeTimeoutInterval: ReturnType<typeof setInterval> | undefined;

// MTU cache: deviceId → negotiated MTU value.
const mtuCache = new Map<string, number>();

// Reassembler cache: deviceId → FrameReassembler.
const reassemblers = new Map<string, FrameReassembler>();

// ── Crypto state ─────────────────────────────────────────────────────────────

type CryptoVerdict = 'pending' | 'accepted' | 'rejected';

/**
 * S1: Verdict state machine — only pending → accepted | rejected allowed.
 * Terminal states (accepted, rejected) are sticky — a late timeout or
 * handshake error cannot override a user's explicit accept/reject decision.
 */
function transitionVerdict(cs: CryptoState, next: CryptoVerdict): boolean {
  if (cs.verdict === 'pending') {
    cs.verdict = next;
    return true;
  }
  // Already in a terminal state — ignore the transition.
  return false;
}

interface CryptoState {
  handshake: NoiseXxHandshake;
  role: 'initiator' | 'responder';
  session: RatchetSession | null;
  sas: string | null;
  verdict: CryptoVerdict;
  /** Peer's long-term Ed25519 pubkey (set after handshake complete). */
  peerPubkeyB64: string | null;
  /** True if TOFU detected a key change for this peer-id. */
  keyChanged: boolean;
  /** peerIdHex derived from the peer's BLE service data. */
  peerIdHex: string;
  /** C2: count of real protocol violations (not replay/out-of-state drops). */
  handshakeFailures?: number;
  /** B.2-handshake-timeout: wall-clock ms when handshake was initiated. */
  handshakeStartedAt: number;
}

// keyed by deviceId (BLE MAC string)
const cryptoStates = new Map<string, CryptoState>();

// TOFU localStorage key.
const TOFU_LS_KEY = 'oxpulse.mesh.tofu';

interface TofuRecord {
  pubkeyB64: string;
  firstSeen: number;
  lastSeen: number;
}

// In-memory fallback for environments without localStorage (Node.js / SSR).
let _tofuMemStore: Record<string, TofuRecord> | null = null;

function tofuLoad(): Record<string, TofuRecord> {
  if (typeof localStorage !== 'undefined') {
    try {
      const raw = localStorage.getItem(TOFU_LS_KEY);
      return raw ? (JSON.parse(raw) as Record<string, TofuRecord>) : {};
    } catch {
      return {};
    }
  }
  // Node.js fallback: module-scoped in-memory store.
  return _tofuMemStore ?? {};
}

function tofuEvict(store: Record<string, TofuRecord>): Record<string, TofuRecord> {
  const entries = Object.entries(store);
  if (entries.length <= TOFU_MAX_ENTRIES) return store;
  // LRU eviction: sort ascending by lastSeen, drop the oldest.
  entries.sort((a, b) => a[1].lastSeen - b[1].lastSeen);
  const kept = entries.slice(entries.length - TOFU_MAX_ENTRIES);
  return Object.fromEntries(kept);
}

function tofuSave(store: Record<string, TofuRecord>): void {
  // B.2-tofu-quota: evict oldest entries before persisting if over the quota.
  const beforeCount = Object.keys(store).length;
  const evicted = tofuEvict(store);
  const evictedCount = beforeCount - Object.keys(evicted).length;
  if (evictedCount > 0) {
    emitMeshMetric('tofu_evicted', { count: String(evictedCount) });
  }
  if (typeof localStorage !== 'undefined') {
    try {
      localStorage.setItem(TOFU_LS_KEY, JSON.stringify(evicted));
    } catch {
      // Storage quota or private-mode — silently skip; TOFU degrades to trust-on-reconnect.
    }
    return;
  }
  // Node.js fallback.
  _tofuMemStore = evicted;
}

/** Reset the TOFU store. Test-only helper (leading `_` per convention). */
export function _resetTofuStore(): void {
  _tofuMemStore = null;
}

/** Expose tofuCheck for tests. Test-only helper (leading `_` per convention). */
export function _tofuCheck(peerIdHex: string, pubkeyB64: string): { trusted: boolean; keyChanged: boolean } {
  return tofuCheck(peerIdHex, pubkeyB64);
}

/**
 * Return the current TOFU store entry count (for testing only).
 * @internal
 */
export function _getTofuStoreSize(): number {
  return Object.keys(tofuLoad()).length;
}

/** Check TOFU: returns true if key is trusted (first-meet or same as stored). */
function tofuCheck(peerIdHex: string, pubkeyB64: string): { trusted: boolean; keyChanged: boolean } {
  const store = tofuLoad();
  const existing = store[peerIdHex];
  if (!existing) {
    // First meeting — trust and store.
    store[peerIdHex] = { pubkeyB64, firstSeen: Date.now(), lastSeen: Date.now() };
    tofuSave(store);
    return { trusted: true, keyChanged: false };
  }
  if (existing.pubkeyB64 === pubkeyB64) {
    existing.lastSeen = Date.now();
    tofuSave(store);
    return { trusted: true, keyChanged: false };
  }
  // Key mismatch — flag it, do NOT update stored key (operator must resolve).
  return { trusted: false, keyChanged: true };
}

// Listener removal handles from native plugin.
const listenerRemovers: Array<() => Promise<void>> = [];

/**
 * Active connections: deviceId → { unsubscribe }.
 * Only populated on successful connect+subscribe — used for:
 *  - Deduplicating concurrent connect attempts (B1.1).
 *  - Teardown in stopMesh (B1.2).
 */
const connectedDevices = new Map<string, { unsubscribe: () => Promise<void> }>();

/**
 * Per-device retry backoff: deviceId → timestamp (ms) after which a retry is allowed.
 * Exponential: 5s → 15s → 60s cap.
 */
const backoff = new Map<string, number>();

const BACKOFF_STEPS_MS = [5_000, 15_000, 60_000];
const backoffCounts = new Map<string, number>();

function nextBackoffMs(deviceId: string): number {
  const count = backoffCounts.get(deviceId) ?? 0;
  // Non-null assertion safe: Math.min clamps index within BACKOFF_STEPS_MS bounds.
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ms = BACKOFF_STEPS_MS[Math.min(count, BACKOFF_STEPS_MS.length - 1)]!;
  backoffCounts.set(deviceId, count + 1);
  return ms;
}

/**
 * #44: Clear backoff/backoffCounts entries for a device on disconnect.
 * Prevents unbounded Map growth in high-churn environments where devices
 * repeatedly connect/disconnect without ever succeeding.
 *
 * F1 (2026-08-04 audit): an ARMED retry window (retryAt > now) must survive a
 * disconnect event — otherwise a device that fails to connect and then emits a
 * disconnect is retried on the very next scan sighting, a hot reconnect loop
 * that defeats exponential backoff (the exact churn scenario #44 was filed
 * about). Only entries whose window has already expired are dropped here; the
 * 30s GC interval (see startMesh) prunes any expired entries left behind when a
 * device disappears without emitting a post-expiry disconnect, so growth stays
 * bounded. Emits a `backoff_cleared` metric only when entries were actually
 * removed (honest semantics).
 */
function clearBackoff(deviceId: string): void {
  // An armed window is still cooling down — keep it so the next scan sighting
  // is still suppressed. The expired-entry case is handled below + by the GC.
  const retryAt = backoff.get(deviceId) ?? 0;
  if (retryAt > Date.now()) return;
  const had = backoff.has(deviceId) || backoffCounts.has(deviceId);
  backoff.delete(deviceId);
  backoffCounts.delete(deviceId);
  if (had) {
    emitMeshMetric('backoff_cleared', { device: deviceId });
  }
}

/** Expose backoff Map size for testing (issue #44). @internal */
export function _getBackoffSize(): number {
  return backoff.size;
}

/** Expose backoffCounts Map size for testing (issue #44). @internal */
export function _getBackoffCountsSize(): number {
  return backoffCounts.size;
}

/** Expose handshakeFailures for a device's CryptoState (issue #46). @internal */
export function _getHandshakeFailures(deviceId: string): number {
  return cryptoStates.get(deviceId)?.handshakeFailures ?? 0;
}

/** Expose whether a CryptoState exists for a device (F2 audit). @internal */
export function _hasCryptoState(deviceId: string): boolean {
  return cryptoStates.has(deviceId);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Classify a raw startMesh error into one of the four canonical UI kinds.
 * Matching is order-sensitive: most-specific first.
 */
function classifyMeshError(err: unknown): MeshErrorKind {
  if (err == null) return 'unknown';
  const msg = err instanceof Error ? err.message : String(err);
  const lower = msg.toLowerCase();
  // Plugin not present (web / iOS where Capacitor plugin returns undefined)
  if (lower.includes('not implemented') || lower.includes('plugin') || lower.includes('undefined')) {
    return 'plugin-absent';
  }
  // Permission denied by OS
  if (
    lower.includes('permission') ||
    lower.includes('missing-bluetooth-permission') ||
    lower.includes('denied')
  ) {
    return 'permission-denied';
  }
  // Bluetooth adapter off / not available
  if (
    lower.includes('bluetooth') ||
    lower.includes('bluetoothnotenabled') ||
    lower.includes('ble not enabled') ||
    lower.includes('disabled') ||
    lower.includes('le advertising not supported')
  ) {
    return 'ble-off';
  }
  return 'unknown';
}

/**
 * Start the mesh: generate a peer-id, begin advertising and scanning,
 * open the GATT server, and wire up all event handlers.
 */
export async function startMesh(): Promise<void> {
  // B1.12: idempotency guard — skip if already running.
  if (meshState.advertising || meshState.scanning) return;

  try {
  // Generate a fresh ephemeral peer-id for this session.
  peerId = generatePeerId();

  // Open GATT server + begin advertising our service UUID with the peer-id
  // embedded in service data (startAdvertising in ble-advertiser calls
  // startGattServer then startAdvertising on the native plugin).
  await startAdvertising(peerId);

  // Begin BLE scan, feeding sightings into the peer registry.
  await startScan(async (sighting) => {
    const deviceId = sighting.deviceId;

    // B1.1: skip if already actively connected — prevents double-connect.
    if (connectedDevices.has(deviceId)) return;

    // S7: enforce BLE connection limit — Android caps at 7, iOS at 8-15.
    // Skip new connections when at limit to avoid error 133 hangs.
    if (connectedDevices.size >= MAX_BLE_CONNECTIONS) {
      emitMeshMetric('ble_connection_limit_reached', { current: String(connectedDevices.size) });
      return;
    }

    // B1.1: skip if still within backoff window.
    const retryAt = backoff.get(deviceId) ?? 0;
    if (Date.now() < retryAt) return;

    // Try connect + negotiate + subscribe in order inside try-block.
    // On success: upsert to registry and record in connectedDevices.
    // On failure: do NOT upsert — allow next sighting to retry after backoff.
    try {
      await connect(deviceId, () => {
        // On disconnect: evict all per-device state (B1.6).
        connectedDevices.delete(deviceId);
        mtuCache.delete(deviceId);
        reassemblers.delete(deviceId);
        cryptoStates.delete(deviceId);
        // #44: clear backoff entries to prevent unbounded Map growth on churn.
        clearBackoff(deviceId);
      });
      const mtu = await negotiateMtu(deviceId);
      mtuCache.set(deviceId, mtu);
      const unsubscribe = await subscribeTx(deviceId, (chunk) => {
        handleIncomingChunk(deviceId, chunk);
      });
      // Only upsert after full success.
      registry.upsert(sighting.peerId, deviceId, sighting.rssi);
      meshState.peers = registry.list();
      connectedDevices.set(deviceId, { unsubscribe });
      // Clear backoff on success.
      backoff.delete(deviceId);
      backoffCounts.delete(deviceId);
      // B.2: initiate Noise XX handshake immediately after connecting.
      // B3: propagate handshake errors to meshState + CryptoState (was swallowed).
      initiateHandshake(deviceId, sighting.peerId).catch((err) => {
        const cs = cryptoStates.get(deviceId);
        failHandshake(cs, deviceId, err);
      });
    } catch (err) {
      console.warn('[mesh] connect failed for', deviceId, err);
      // Set exponential backoff before allowing retry.
      backoff.set(deviceId, Date.now() + nextBackoffMs(deviceId));
    }
  });

  // Register native plugin listener for incoming RX writes (frames peers send
  // to our GATT server's RX characteristic).
  const rxHandle = await MeshGatt.addListener('rx', (ev: unknown) => {
    const e = ev as { deviceAddress: string; data: string };
    const bytes = base64ToBytes(e.data);
    handleIncomingChunk(e.deviceAddress, bytes);
  });
  listenerRemovers.push(async () => rxHandle.remove());

  // Register connection-state listener from the native GATT server.
  const connHandle = await MeshGatt.addListener('connection', (ev: unknown) => {
    const e = ev as { deviceAddress: string; connected: boolean };
    if (!e.connected) {
      // B1.6: evict reassembler, mtu, and connectedDevices on disconnect.
      reassemblers.delete(e.deviceAddress);
      mtuCache.delete(e.deviceAddress);
      connectedDevices.delete(e.deviceAddress);
      cryptoStates.delete(e.deviceAddress);
      // #44: clear backoff entries to prevent unbounded Map growth on churn.
      clearBackoff(e.deviceAddress);
    } else {
      // F2 (2026-08-04 audit): register INBOUND connections — peers that
      // connect TO our GATT server without us also connecting outbound to
      // them. Without this, the responder-handshake guards in
      // handleIncomingChunk (connectedDevices.has) and checkHandshakeTimeouts
      // drop every inbound handshake frame and never time out, so a peer
      // reachable only inbound (connection cap hit, backoff window, MAC
      // rotation) can never complete a handshake. The entry shape matches the
      // outbound path ({ unsubscribe }); an inbound device has no outbound
      // subscription, so unsubscribe is a no-op (stopMesh calls it in a
      // try/catch). Guard against clobbering an existing outbound entry.
      if (!connectedDevices.has(e.deviceAddress)) {
        connectedDevices.set(e.deviceAddress, { unsubscribe: async () => {} });
      }
    }
  });
  listenerRemovers.push(async () => connHandle.remove());

  // B1.3: GC interval — prune stale peers from registry every 30s.
  gcInterval = setInterval(() => {
    registry.gc();
    meshState.peers = registry.list();
    // F1/#44: prune expired backoff entries so the Maps don't grow without
    // bound when a device fails to connect and then disappears without ever
    // emitting a post-expiry disconnect. Armed windows are left untouched.
    const now = Date.now();
    for (const [id, retryAt] of backoff) {
      if (retryAt <= now) {
        backoff.delete(id);
        backoffCounts.delete(id);
      }
    }
  }, 30_000);

  // B.2-handshake-timeout: check for stalled handshakes every 5s.
  // 5s granularity is sufficient for a 15s timeout — adds at most 4.9s extra.
  handshakeTimeoutInterval = setInterval(() => {
    checkHandshakeTimeouts();
  }, 5_000);

  // MAC rotation: every 15 min, restart advertising (MAC randomises on each
  // advertising session start on Android 10+). Peer-id stays stable within
  // the session so discovery continuity is maintained.
  const currentPeerId = peerId;
  macRotation = new MacRotationTimer(
    async () => {
      try {
        await stopAdvertising();
        await startAdvertising(currentPeerId);
      } catch (err) {
        console.warn('[mesh] MAC rotation failed', err);
      }
    },
    { initialJitter: true },
  );
  macRotation.start();

  // Gate MAC rotation on foreground visibility.
  const visibilityHandler = () => {
    macRotation?.onVisibilityChange(document.visibilityState === 'visible');
  };
  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', visibilityHandler);
    // Store removal handle alongside other teardown.
    listenerRemovers.push(async () => {
      document.removeEventListener('visibilitychange', visibilityHandler);
    });
  }

  meshState.advertising = true;
  meshState.scanning = true;
  meshState.error = null;
  } catch (err) {
    // D2: classify the failure so the UI can show an appropriate recovery CTA.
    meshState.error = classifyMeshError(err);
    throw err;
  }
}

/**
 * B.2-handshake-timeout: check all pending CryptoStates for timeout.
 * Called on a 5-second tick. Transitions stalled handshakes to 'rejected'
 * without calling disconnect — the BLE layer handles link teardown.
 */
function checkHandshakeTimeouts(): void {
  const now = Date.now();
  // S2: iterate entries (not values) so we can check connectedDevices by deviceId.
  // If the device already disconnected, skip — don't report a stale timeout.
  for (const [deviceId, cs] of cryptoStates) {
    if (cs.verdict !== 'pending') continue;
    if (cs.session !== null) continue;  // past handshake — session already established
    // S2: skip if device already disconnected — no false timeout report.
    if (!connectedDevices.has(deviceId)) continue;
    if (now - cs.handshakeStartedAt > HANDSHAKE_TIMEOUT_MS) {
      // S1: use state machine — don't override accepted/rejected.
      if (!transitionVerdict(cs, 'rejected')) continue;
      console.warn(`[mesh] handshake timeout for peer ${cs.peerIdHex} after ${HANDSHAKE_TIMEOUT_MS}ms`);
      emitMeshMetric('handshake_timeout', { peer: cs.peerIdHex });
      meshState.error = 'handshake-failed';
      notifyHandshakeChange();
    }
  }
}

/**
 * Stop the mesh: halt scan + advertising, disconnect all peers, clear all state.
 */
export async function stopMesh(): Promise<void> {
  await stopScan();
  await stopAdvertising();

  // B1.3: clear GC interval.
  if (gcInterval !== undefined) {
    clearInterval(gcInterval);
    gcInterval = undefined;
  }

  // B.2-handshake-timeout: clear timeout check interval.
  if (handshakeTimeoutInterval !== undefined) {
    clearInterval(handshakeTimeoutInterval);
    handshakeTimeoutInterval = undefined;
  }

  macRotation?.stop();
  macRotation = null;

  // B1.2: unsubscribe and disconnect every connected peer.
  for (const [deviceId, { unsubscribe }] of connectedDevices) {
    try {
      await unsubscribe();
    } catch {
      // Ignore teardown errors.
    }
    try {
      await disconnect(deviceId);
    } catch {
      // Ignore teardown errors.
    }
  }
  connectedDevices.clear();

  // Remove all native plugin listeners.
  for (const remove of listenerRemovers) {
    try {
      await remove();
    } catch {
      // Ignore teardown errors.
    }
  }
  listenerRemovers.length = 0;

  registry.clear();
  registry = new PeerRegistry();
  mtuCache.clear();
  reassemblers.clear();
  cryptoStates.clear();
  backoff.clear();
  backoffCounts.clear();
  frameHandlers.clear();
  handshakeChangeHandlers.clear();
  peerId = null;

  meshState.peers = [];
  meshState.advertising = false;
  meshState.scanning = false;
  meshState.error = null;
}

/**
 * Register a handler to receive fully reassembled frames from a peer.
 * Returns an unsubscribe function.
 */
export function onFrame(handler: FrameHandler): () => void {
  frameHandlers.add(handler);
  return () => {
    frameHandlers.delete(handler);
  };
}

// ── Handshake public API ──────────────────────────────────────────────────────

export interface PendingHandshake {
  peerIdHex: string;
  sas: string;
  peerPubkeyB64: string;
  /** True if this pubkey is new for this peer-id (TOFU key change). */
  keyChanged: boolean;
}

/** Return all peers whose handshake has completed but not yet been accepted/rejected. */
export function getPendingHandshakes(): PendingHandshake[] {
  const out: PendingHandshake[] = [];
  for (const cs of cryptoStates.values()) {
    if (cs.sas !== null && cs.verdict === 'pending' && cs.peerPubkeyB64 !== null) {
      out.push({
        peerIdHex: cs.peerIdHex,
        sas: cs.sas,
        peerPubkeyB64: cs.peerPubkeyB64,
        keyChanged: cs.keyChanged,
      });
    }
  }
  return out;
}

/** Accept a peer after SAS verification — unblocks sendFrame to that peer. */
export function acceptPeer(peerIdHex: string): void {
  for (const cs of cryptoStates.values()) {
    if (cs.peerIdHex === peerIdHex) {
      // S1: state machine — only pending → accepted.
      if (!transitionVerdict(cs, 'accepted')) return;
      notifyHandshakeChange();
      return;
    }
  }
  console.warn('[mesh] acceptPeer: no pending handshake for', peerIdHex);
}

/** Reject a peer — tears down state, sets error.
 * User action: called when SAS does not match (user clicked «Не совпадает»). */
export function rejectPeer(peerIdHex: string): void {
  for (const cs of cryptoStates.values()) {
    if (cs.peerIdHex === peerIdHex) {
      // S1: state machine — only pending → rejected.
      if (!transitionVerdict(cs, 'rejected')) return;
      emitMeshMetric('sas_mismatch', { peer: peerIdHex });
      meshState.error = 'unknown-peer-key';
      notifyHandshakeChange();
      return;
    }
  }
  console.warn('[mesh] rejectPeer: no pending handshake for', peerIdHex);
}

/**
 * Send a frame to a specific peer (by hex peer-id).
 * Requires handshake to be complete AND peer to have been accepted via acceptPeer().
 * Throws 'unknown-peer-key' if handshake not complete or not accepted.
 */
export async function sendFrame(peerIdHex: string, frame: Uint8Array): Promise<void> {
  const peer = registry.list().find((p) => p.idHex === peerIdHex);

  // Resolve the BLE device address for this peer. The registry covers peers we
  // scanned outbound; an inbound-only peer (#80) has no registry entry, and #80
  // deliberately does not fabricate one — the registry feeds meshState.peers,
  // which router.ts reads to route frames, and we do not know an inbound-only
  // peer's advertised 8-byte peer ID, so a fake entry would misroute. Such a
  // peer can still complete a handshake and be accepted, so sendFrame falls back
  // to the CryptoState, which is keyed by device address and already holds
  // everything the send path needs. This does NOT add the peer to the registry,
  // so the router cannot pick an inbound-only peer as a routing next-hop on the
  // basis of a MAC-shaped identifier (#82).
  let deviceId: string | undefined = peer?.mac;
  if (!deviceId) {
    // Prefer a match that is still CONNECTED. Two cryptoStates entries can hold
    // the same peerIdHex under different device addresses when a peer rotates
    // its MAC and reconnects before the old entry is reaped — cryptoStates is
    // deleted on a disconnect event, and that event is not guaranteed to
    // arrive. Taking the first match in insertion order could then encrypt
    // under the stale session and write to a dead address, and
    // writeWithoutResponse has no ACK, so the frame would be lost in silence.
    //
    // Inbound-only peers cannot be ambiguous here (peerIdHex IS the device
    // address, so it is the Map key), but a caller holding a long-lived 8-byte
    // peer ID can be. Falling back to a disconnected match preserves the old
    // behaviour rather than throwing when nothing is connected.
    let stale: string | undefined;
    for (const [addr, csEntry] of cryptoStates) {
      if (csEntry.peerIdHex !== peerIdHex) continue;
      if (connectedDevices.has(addr)) { deviceId = addr; break; }
      stale ??= addr;
    }
    deviceId ??= stale;
  }
  if (!deviceId) throw new Error(`sendFrame: unknown peer ${peerIdHex}`);

  // Find crypto state for this peer.
  const cs = cryptoStates.get(deviceId);
  if (!cs || cs.verdict !== 'accepted' || !cs.session) {
    throw new Error(`sendFrame: unknown-peer-key — handshake not complete or not accepted for ${peerIdHex}`);
  }

  const mtu = mtuCache.get(deviceId) ?? GATT_MTU_DEFAULT;
  const ciphertext = await cs.session.encrypt(frame);
  const chunks = chunkFrame(ciphertext, mtu, FrameType.SessionData);

  // Serialize writes per peer to avoid ATT queue overflow.
  for (const chunk of chunks) {
    await writeRx(deviceId, chunk);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build a DeviceIdentityProvider adapter wrapping the @oxpulse/identity device identity.
 * Cached lazily to avoid IDB overhead on every handshake.
 */
let localIdentityProvider: import('./crypto/noise-xx.js').NoiseXxOptions['identity'] | null = null;

async function getLocalIdentity(): Promise<import('./crypto/noise-xx.js').NoiseXxOptions['identity']> {
  if (localIdentityProvider) return localIdentityProvider;
  const identity = await getOrCreateDeviceIdentity();
  const pubkeyBytes = fromBase64url(identity.publicKeyB64);
  // B.2-noise-s-key-derivation: pre-fetch X25519 keypair at identity construction
  // so it's available synchronously inside the returned object (IDB access
  // happens only once per session, same pattern as Ed25519 pubkeyBytes).
  const x25519Kp = await getOrCreateX25519Keypair();
  localIdentityProvider = {
    async getPublicKey() { return pubkeyBytes; },
    async sign(msg: Uint8Array) {
      // Use @noble/curves for signing — works on all runtimes including HyperOS/HarmonyOS
      // where WebCrypto Ed25519 is absent (Chrome <137). identity.privateKeyBytes is the
      // raw 32-byte Ed25519 seed; identity.privateKey CryptoKey may be null on old WebViews.
      if (!identity.privateKeyBytes) {
        throw new Error('[identity] Noise XX sign: privateKeyBytes null — identity migration required');
      }
      return nobleEd25519.sign(msg, identity.privateKeyBytes);
    },
    async getX25519PublicKey() { return x25519Kp.publicKey; },
    async dhX25519(remotePub: Uint8Array) { return identityDhX25519(remotePub); },
  };
  return localIdentityProvider;
}

/**
 * B3: Centralized handshake failure handler.
 *
 * Called from the 3 catch sites that previously only console.warn'd.
 * Sets meshState.error, marks the CryptoState as rejected, emits a metric,
 * and notifies handshake change subscribers so the UI refreshes.
 *
 * Idempotent: if verdict is already 'rejected' (inner try/catch in
 * advanceHandshake already handled it), this is a no-op — the error
 * was already propagated and we don't want to overwrite the reason label.
 */
function failHandshake(cs: CryptoState | undefined, deviceId: string, err: unknown): void {
  const reason = err instanceof Error ? err.message : String(err);
  console.warn(`[mesh] handshake failed for ${deviceId}:`, err);
  // S1: state machine — don't override an accepted peer with a late failure.
  if (cs && transitionVerdict(cs, 'rejected')) {
    emitMeshMetric('handshake_failed', { reason: reason.slice(0, 80) });
    notifyHandshakeChange();
  }
  meshState.error = 'handshake-failed';
}

/**
 * Determine handshake role: lexicographic comparison of our peerId vs peer's peerId.
 * Smaller = initiator, larger = responder.
 */
function roleFor(ourPeerId: Uint8Array, peerPeerIdBytes: Uint8Array): 'initiator' | 'responder' {
  for (let i = 0; i < Math.min(ourPeerId.length, peerPeerIdBytes.length); i++) {
    // Non-null assertions: bounds-checked by loop condition.
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    if (ourPeerId[i]! < peerPeerIdBytes[i]!) return 'initiator';
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    if (ourPeerId[i]! > peerPeerIdBytes[i]!) return 'responder';
  }
  return 'initiator'; // tie-break (shouldn't happen with 8-byte peer-ids)
}

/**
 * Initiate the Noise XX handshake immediately after connecting to a peer.
 * If we are the initiator (lexicographically smaller peerId), we send msg-1.
 * If we are the responder, we wait for msg-1 from the peer.
 */
async function initiateHandshake(deviceId: string, peerIdBytes: Uint8Array): Promise<void> {
  const identity = await getLocalIdentity();
  if (!peerId) return;
  // #91: re-check the device is still connected after the async gap. A
  // disconnect landing during getLocalIdentity() deletes
  // connectedDevices[deviceId] but finds no cryptoStates entry to delete
  // (it doesn't exist yet); without this guard we would create a CryptoState
  // for a device that is already gone, leaking a live NoiseXxHandshake
  // (handshake key material) that no reaper touches — the disconnect handler
  // already fired, and checkHandshakeTimeouts skips disconnected entries by
  // design. Bail before creating any state.
  if (!connectedDevices.has(deviceId)) return;

  const peerIdHex = toHex(peerIdBytes);
  const role = roleFor(peerId, peerIdBytes);

  const handshake = new NoiseXxHandshake({ role, identity });
  const cs: CryptoState = {
    handshake,
    role,
    session: null,
    sas: null,
    verdict: 'pending',
    peerPubkeyB64: null,
    keyChanged: false,
    peerIdHex,
    handshakeStartedAt: Date.now(),
  };
  cryptoStates.set(deviceId, cs);

  if (role === 'initiator') {
    const msg1 = await handshake.writeMessage(new Uint8Array(0));
    const mtu = mtuCache.get(deviceId) ?? GATT_MTU_DEFAULT;
    const chunks = chunkFrame(msg1, mtu, FrameType.HandshakeMsg1);
    for (const c of chunks) {
      await writeRx(deviceId, c);
    }
  }
}

/**
 * Advance the handshake state machine on receipt of a handshake message.
 * Sends the next outbound message if it's our turn.
 * On completion, derives session keys, computes SAS, runs TOFU check.
 */
async function advanceHandshake(
  cs: CryptoState,
  deviceId: string,
  frameType: import('./frame.js').FrameType,
  payload: Uint8Array,
): Promise<void> {
  const hs = cs.handshake;
  try {
    await hs.readMessage(payload);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // C2: distinguish replay / out-of-state BLE frames from real protocol violations.
    // Replayed or reordered chunks must be silently dropped — they are expected in
    // lossy BLE environments and must not permanently DoS the connection.
    // B.2-typed-noise-errors: use instanceof instead of fragile regex.
    if (err instanceof NoiseStateError) {
      console.debug(`[mesh] handshake frame ignored (out-of-state): ${msg}`);
      return;
    }
    // Real protocol violation — count toward retry budget (3 strikes before reject).
    cs.handshakeFailures = (cs.handshakeFailures ?? 0) + 1;
    if (cs.handshakeFailures < 3) {
      console.debug(`[mesh] handshake error (retry ${cs.handshakeFailures}/3): ${msg}`);
      return;
    }
    console.warn(`[mesh] handshake permanently rejected after 3 failures: ${msg}`);
    emitMeshMetric('handshake_failed', { reason: msg });
    meshState.error = 'handshake-failed';
    transitionVerdict(cs, 'rejected');
    return;
  }

  const mtu = mtuCache.get(deviceId) ?? GATT_MTU_DEFAULT;

  // Route by (role, received frame) → write next message if applicable.
  //   Responder receives msg-1 → writes msg-2.
  //   Initiator receives msg-2 → writes msg-3.
  //   Responder receives msg-3 → handshake complete (no write).

  if (frameType === FrameType.HandshakeMsg1 && cs.role === 'responder') {
    // Responder just processed msg-1 → send msg-2.
    try {
      const msg2 = await hs.writeMessage(new Uint8Array(0));
      const chunks = chunkFrame(msg2, mtu, FrameType.HandshakeMsg2);
      for (const c of chunks) await writeRx(deviceId, c);
    } catch (err) {
      console.warn('[mesh] handshake writeMsg2 failed', deviceId, err);
      meshState.error = 'handshake-failed';
      transitionVerdict(cs, 'rejected');
      return;
    }
  } else if (frameType === FrameType.HandshakeMsg2 && cs.role === 'initiator') {
    // Initiator just processed msg-2 → send msg-3.
    try {
      const msg3 = await hs.writeMessage(new Uint8Array(0));
      const chunks = chunkFrame(msg3, mtu, FrameType.HandshakeMsg3);
      for (const c of chunks) await writeRx(deviceId, c);
    } catch (err) {
      console.warn('[mesh] handshake writeMsg3 failed', deviceId, err);
      meshState.error = 'handshake-failed';
      transitionVerdict(cs, 'rejected');
      return;
    }
  }
  // frameType=HandshakeMsg3 && role=responder → just read, no write; fall through to split.

  // After msg-3 or after initiator sent msg-3, handshake should be complete.
  if (hs.isComplete()) {
    let split: NoiseSplit;
    try {
      split = hs.split();
    } catch (err) {
      console.warn('[mesh] handshake split failed', deviceId, err);
      meshState.error = 'handshake-failed';
      transitionVerdict(cs, 'rejected');
      return;
    }

    // Session direction: initiator and responder nonces are scoped by direction.
    // cs.role determines which direction label to use.
    const direction: import('./crypto/session-ratchet.js').Direction = cs.role;

    cs.session = new RatchetSession({ sendChainKey: split.sendKey, recvChainKey: split.recvKey, direction });
    cs.sas = hs.sas();

    // #46: reset handshakeFailures on successful session establishment.
    // The counter must count violations within a single handshake attempt,
    // not across the lifetime of a CryptoState. Without this reset, 2 prior
    // failures + a later re-handshake violation would cause premature rejection.
    if ((cs.handshakeFailures ?? 0) > 0) {
      cs.handshakeFailures = 0;
      emitMeshMetric('handshake_failures_reset', { device: deviceId });
    }

    // TOFU: check peer's static pubkey.
    const peerPub = hs.peerStaticPublicKey();
    if (peerPub) {
      // C3: use base64url (matches @oxpulse/identity encoding) so TOFU comparison
      // doesn't silently fail due to +/= vs -/_ encoding mismatch.
      const pubkeyB64 = uint8ToBase64Url(peerPub);
      cs.peerPubkeyB64 = pubkeyB64;
      const { trusted, keyChanged } = tofuCheck(cs.peerIdHex, pubkeyB64);
      cs.keyChanged = keyChanged;
      if (!trusted) {
        // Key changed — surface in error state; leave verdict=pending so UI can decide.
        emitMeshMetric('unknown_peer_key', { peer: cs.peerIdHex });
        meshState.error = 'unknown-peer-key';
        // Still expose via getPendingHandshakes so UI can show the warning.
      }
    }
    // E5: notify subscribers so HandshakePanel can refresh without polling.
    notifyHandshakeChange();
  }
}

/** C3: base64url encoder matching @oxpulse/identity's publicKeyB64 encoding.
 * Using standard base64 (btoa) caused silent TOFU comparison failures. */
function uint8ToBase64Url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function handleIncomingChunk(deviceAddress: string, chunk: Uint8Array): void {
  let r = reassemblers.get(deviceAddress);
  if (!r) {
    r = new FrameReassembler();
    reassemblers.set(deviceAddress, r);
  }

  let res: import('./frame.js').ReassembledFrame | null;
  try {
    res = r.pushWithType(chunk);
  } catch (err) {
    console.warn('[mesh] reassembler error from', deviceAddress, err);
    // Reset the reassembler for this device on parse error.
    reassemblers.set(deviceAddress, new FrameReassembler());
    return;
  }

  if (!res) return;

  const cs = cryptoStates.get(deviceAddress);

  // Handshake messages — route to state machine.
  if (res.frameType !== FrameType.SessionData) {
    if (!cs) {
      // Received a handshake frame from a device we haven't connected to on our side yet.
      // This is the responder path: we didn't initiate; the peer did.
      // We need to create crypto state before advancing.
      // Look up peerIdHex from the registry (peer may not be registered yet).
      const peer = registry.list().find((p) => p.mac === deviceAddress);
      const peerIdHex = peer?.idHex ?? deviceAddress;
      // #59: an inbound-only peer (never connected outbound) has no registry
      // entry, so `peer` is undefined. The responder role does not logically
      // require a prior outbound sighting — receiving a handshake frame with no
      // existing CryptoState means the peer is the initiator and we are the
      // responder. Use the device address as the peerIdHex fallback rather than
      // polluting the registry with a fabricated peer ID (the registry feeds
      // meshState.peers and the router; a fake ID would misroute frames).
      if (peerId) {
        const peerIdBytes = peer ? Uint8Array.from(
          // peer.idHex is hex string → convert back to bytes
          (peer.idHex.match(/.{2}/g) ?? []).map(h => parseInt(h, 16))
        ) : new Uint8Array(8);
        const role = peer ? roleFor(peerId, peerIdBytes) : 'responder';
        // C1: peer initiated before our scan callback fired getLocalIdentity().
        // Await identity resolution instead of null-asserting localIdentityProvider!
        // to avoid a crash when the IDB read hasn't completed yet.
        const capturedPayload = res.payload;
        const capturedFrameType = res.frameType;
        const capturedOurPeerId = peerId;
        getLocalIdentity().then((identity) => {
          // Guard: mesh may have stopped or device reconnected while we awaited IDB.
          // S1: also check connectedDevices — if the device disconnected while we
          // were waiting for IDB, don't create an orphaned cryptoStates entry.
          // S3: emit a metric when a frame is dropped so the silent loss is observable.
          if (!capturedOurPeerId || !connectedDevices.has(deviceAddress)) {
            emitMeshMetric('handshake_frame_dropped', { reason: capturedOurPeerId ? 'disconnected' : 'mesh-stopped' });
            return;
          }
          if (cryptoStates.has(deviceAddress)) {
            emitMeshMetric('handshake_frame_dropped', { reason: 'duplicate' });
            return;
          }
          const csNew: CryptoState = {
            handshake: new NoiseXxHandshake({ role, identity }),
            role,
            session: null,
            sas: null,
            verdict: 'pending',
            peerPubkeyB64: null,
            keyChanged: false,
            peerIdHex,
            handshakeStartedAt: Date.now(),
          };
          cryptoStates.set(deviceAddress, csNew);
          advanceHandshake(csNew, deviceAddress, capturedFrameType, capturedPayload).catch((err) => {
            failHandshake(csNew, deviceAddress, err);
          });
        }).catch((err) => {
          // B3: identity bootstrap failure must propagate to meshState, not just console.warn.
          failHandshake(undefined, deviceAddress, err);
        });
      } else {
        // peerId is null — mesh hasn't completed bootstrap (getLocalIdentity).
        console.warn('[mesh] handshake frame before mesh bootstrap completed', deviceAddress);
      }
      return;
    }
    advanceHandshake(cs, deviceAddress, res.frameType, res.payload).catch((err) => {
      failHandshake(cs, deviceAddress, err);
    });
    return;
  }

  // Session-data frame.
  if (!cs || !cs.session || cs.verdict !== 'accepted') {
    console.warn('[mesh] session-data before acceptPeer; dropping from', deviceAddress);
    return;
  }

  const { payload, frameType: _ft } = res;

  cs.session.decrypt(payload).then((plaintext) => {
    // Look up the peer's idHex by device address (MAC).
    const peerIdHex = cs.peerIdHex;
    for (const handler of frameHandlers) {
      try {
        handler(peerIdHex, plaintext);
      } catch (err) {
        console.warn('[mesh] frame handler error', err);
      }
    }
  }).catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('replay')) {
      emitMeshMetric('replay_rejected');
      meshState.error = 'replay-rejected';
    } else {
      meshState.error = 'handshake-failed';
    }
    console.warn('[mesh] session decrypt error from', deviceAddress, err);
  });
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// toHex is used implicitly via the peerId comparison in older code; keep to avoid dead-code warnings.
void toHex;

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
