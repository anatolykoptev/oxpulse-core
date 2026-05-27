// @generated DO NOT EDIT — see mesh-constants.json + scripts/gen-mesh-constants.mjs
export const MESH_SERVICE_UUID = 'f0f10000-6f78-7075-6c73-65000000c8b1';
export const MESH_RX_CHARACTERISTIC_UUID = 'f0f10001-6f78-7075-6c73-65000000c8b1';
export const MESH_TX_CHARACTERISTIC_UUID = 'f0f10002-6f78-7075-6c73-65000000c8b1';
export const FRAME_MAGIC = 0xc8;
export const MAX_FRAME_SIZE = 65536;
export const GATT_MTU_DEFAULT = 23;
export const GATT_MTU_TARGET = 247;
export const PEER_ID_BYTES = 8;
export const NOISE_PATTERN_ID = "xx_25519_aesgcm_sha256" as const;
export const MLKEM_PARAM_SET = "ml-kem-768" as const;
export const MLKEM_PUBLIC_KEY_BYTES = 1184 as const;
export const MLKEM_CIPHERTEXT_BYTES = 1088 as const;
export const MLKEM_SHARED_SECRET_BYTES = 32 as const;
export const AEAD_NONCE_BYTES = 12 as const;
export const AEAD_KEY_BYTES = 16 as const;
export const SAS_DIGIT_COUNT = 5 as const;
export const IDENTITY_KEY_VERSION = 1 as const;
export const REPLAY_WINDOW_SIZE = 64 as const;
/** Target distinct msgId count before Bloom FP rate degrades. */
export const DEDUP_BLOOM_CAPACITY = 50000 as const;
/** Acceptable false-positive rate at capacity (1-in-1000). */
export const DEDUP_BLOOM_FP_RATE = 0.001 as const;
/** Schema version for the Bloom IndexedDB store. */
export const DEDUP_BLOOM_DB_VERSION = 1 as const;
export const MAX_HANDSHAKE_MSG_BYTES = 1500 as const;
export const HANDSHAKE_TIMEOUT_MS = 15000 as const;
/** Maximum number of TOFU entries; oldest evicted when exceeded. */
export const TOFU_MAX_ENTRIES = 1000 as const;
/** Number of bytes taken from BLAKE3 output for channel IDs. */
export const CHANNEL_ID_HASH_BYTE_COUNT = 4;
/** Geohash precision (character count). 4 chars ≈ 20×20 km cell. */
export const GEOHASH_LENGTH = 4;
/** Base-32 alphabet for geohash encoding. MUST match server-side derivation. */
export const GEOHASH_ALPHABET = '0123456789bcdefghjkmnpqrstuvwxyz';
/** Max inbox entries before eviction; ~48 MB proxy at 1.6 KB average bundle (roadmap §B.3). */
export const MESH_INBOX_MAX_ENTRIES = 30000 as const;
/** Max spool entries before eviction; same 50 MB proxy as inbox. */
export const MESH_SPOOL_MAX_ENTRIES = 30000 as const;
