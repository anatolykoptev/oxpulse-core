// @oxpulse/identity — long-term Ed25519 identity for oxpulse-chat
// Extracted from web/src/lib/{device,host}-identity.ts per
// docs/architecture/identity-extraction-adr.md Step 2.

// Long-term device identity (Ed25519, IDB-persisted, AES-KW wrapped)
export {
	getOrCreateDeviceIdentity,
	generateDeviceIdentity,
	signWithDeviceIdentity,
	verifyDeviceSignature,
	clearDeviceIdentity,
	hasDeviceIdentity,
	exportRawDeviceSecret,
	replaceDeviceIdentity,
	probeBrowserSupport,
	type DeviceIdentity,
} from './device-identity.js';

// X25519 static keypair for Noise XX es/se DH (B.2-noise-s-key-derivation)
export {
	getOrCreateX25519Keypair,
	dhX25519,
} from './device-identity.js';

// Profile seed (32-byte secret driving profile_id derivation)
export {
	getOrCreateProfileSeed,
	setProfileSeed,
	clearProfileSeed,
} from './device-identity.js';

// Room-host (operator) identity, in-memory only + HKDF-derived (PR-3)
export {
	generateHostKeypair,
	getOrCreateRoomHostKey,
	signHostAction,
	buildKickPayload,
	buildLockPayload,
	buildUnlockPayload,
	buildPinMintPayload,
	buildShortlinkMintPayload,
	hostKeypairCache,
	type HostKeypair,
} from './host-identity.js';

// Room-host seed (dedicated derivation root, PR-3)
export {
	getOrCreateRoomHostSeed,
	exportRoomHostSeed,
} from './room-host-seed.js';

// X25519 identity keypair + self-sig binding (Phase 2 T0.5)
export {
	generateX25519Identity,
	verifyX25519SelfSig,
	getOrCreateX25519Identity,
	type X25519Identity,
} from './x25519-identity.js';

// base64url helpers (canonical, single copy across workspace)
export { toBase64url, fromBase64url } from './base64url.js';

// Shared IDB error types (cross-module instanceof works only with a single class source)
export { IDBUnavailableError } from './idb-errors.js';

// Analytics injection (consumed by web/ at startup via setIdentityTracker(track))
export { setIdentityTracker, type IdentityTracker } from './tracker-shim.js';
