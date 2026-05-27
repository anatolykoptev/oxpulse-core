// @oxpulse/mesh-core public surface
// Phase B.1: BLE transport.
// Phase B.7: channel ID derivation + region fallback.
// Phase B.2: error counter sink.

// Metric sink — register in app boot to observe mesh error trends.
export { setMeshMetricSink, emitMeshMetric } from './metrics.js';
export type { MeshMetric, MetricSink } from './metrics.js';

// Constants (generated from mesh-constants.json)
export * from './constants.js';

// Frame protocol
export { chunkFrame, FrameReassembler, FRAME_HEADER_LEN } from './frame.js';

// Peer identity + registry
export { generatePeerId, PeerRegistry } from './peer-registry.js';
export type { Peer } from './peer-registry.js';

// MAC rotation
export { MacRotationTimer } from './mac-rotation.js';

// Transport façade — public API
export {
  startMesh,
  stopMesh,
  onFrame,
  sendFrame,
  meshState,
  acceptPeer,
  rejectPeer,
  getPendingHandshakes,
  onHandshakeStateChange,
} from './transport.js';
export type { MeshErrorKind, PendingHandshake } from './transport.js';
export type { CryptoErrorKind } from './crypto/errors.js';
export { NoiseStateError, NoiseReplayError } from './crypto/noise-xx.js';

// Platform detection re-export (Phase A native shim; isIOS added Phase C)
export { isInCapacitor, isAndroid, isIOS, isNative } from './native/platform.js';

// Settings intents (Phase B.1 Round-2 design fix)
export { openBluetoothSettings, openAppPermissionSettings } from './ble-advertiser.js';

// Channel ID derivation + region fallback (Phase B.7)
export {
  channelIdHash,
  neighboringChannelIds,
  currentChannelId,
  getRegionFallback,
  getRegionDisplayName,
  availableRegions,
} from './channel.js';
export type { ChannelIdResult } from './channel.js';

// B-4: client modules — composer + outbox + dedupe + router + online bridge
export { composeBundle, MESH_BUNDLE_TS_EPOCH_MS } from './bundle-composer.js';
export type { ComposeBundleArgs, ComposeBundleResult } from './bundle-composer.js';

export { Outbox, MESH_OUTBOX_DB_NAME, MESH_OUTBOX_STORE_NAME } from './outbox.js';
export type { OutboxEntry } from './outbox.js';

export { DedupeCache } from './dedupe.js';
export type { DedupeCacheOptions } from './dedupe.js';

export { bridgeSend } from './online-bridge.js';
export type { BridgeResult, BridgeOkResult, BridgeErrorResult, BridgeSendArgs } from './online-bridge.js';

export { startOutboxDrainer } from './outbox-drainer.js';
export type { OutboxDrainerDeps, DrainBridgeSendResult } from './outbox-drainer.js';

export { getToken, clearTokens, clearTokensForIdentity, TOKEN_CACHE_MAX_SIZE, _resetCache } from './token-client.js';

export { routeOutgoing, onIncoming } from './router.js';
export type { RouteResult, RouteStrategy, RouteContext, RouteOutgoingArgs, OnIncomingArgs, SseSubscribe } from './router.js';

// Phase 3 T1: mesh-wrap — envelope-in-bundle helpers
export {
  composeMeshWrap,
  peelMeshWrap,
  MESH_WRAP_MAGIC,
  MESH_WRAP_FLAG_SEALED_1TO1,
} from './wrap.js';
export type { ComposeMeshWrapArgs, PeeledMeshWrap } from './wrap.js';

export * from './mailbox/index.ts';
