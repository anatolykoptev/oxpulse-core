/**
 * room_host_seed_v1 — the dedicated root secret from which every per-room
 * host key is HKDF-derived (see host-identity.ts getOrCreateRoomHostKey).
 *
 * Dedicated on purpose: it is NOT profile_seed (that is the at-rest
 * profile-encryption ikm — deriving signing keys from it would be
 * cross-purpose key reuse). 32 CSPRNG bytes, AES-KW-wrapped at rest in
 * IndexedDB, mirroring the device-identity raw-seed storage pattern.
 *
 * Exportable: cross-device host support re-derives every room key on
 * another device once that device holds this seed. The export accessor
 * exists now; the cross-device SYNC flow is a separate future increment.
 *
 * Phase 5 (key-hygiene): the KEK is now persisted as a non-extractable
 * CryptoKey via structured-clone (raw-bytes fallback on WebViews without
 * CryptoKey structured-clone support), and seed wrap/unwrap routes through
 * the shared aes-kw.ts helpers. The dedicated IDB database is retained
 * (ADR-9 isolation) — the KEK is NOT moved to a separate DB. The seed is
 * exportable by design and is NOT wrapped in OpaquePrivateKey.
 */

import { createIdbStore } from './idb-store.js';
import { wrapSecretBytes, unwrapSecretBytes, generateAesKwKey, importAesKwRaw, classifyKekEntry } from './aes-kw.js';

// LOAD-BEARING: dedicated IDB database — separate from oxpulse-device-id
// so the room-host root secret is isolated from the device identity store.
// Never rename after first user. (ADR-9: isolation is intentional — the KEK
// stays in this same dedicated DB, it is NOT moved to a separate KEK DB.)
const DB_NAME = 'oxpulse-room-host-seed';
const STORE_NAME = 'seed';
const KEY = 'room_host_seed_v1';     // LOAD-BEARING — DO NOT RENAME
const WRAPPING_KEY = 'wrapping_key'; // wrapping key for this store only

const idb = createIdbStore({ dbName: DB_NAME, storeName: STORE_NAME });

let cachedSeed: Uint8Array | null = null;
let cachedWrappingKey: CryptoKey | null = null;

/**
 * Cached probe result for CryptoKey structured-clone support.
 *
 * Some WebViews (older Android WebView, HarmonyOS ArkWeb) cannot structured-clone
 * a CryptoKey, which means it cannot be persisted to IDB as a CryptoKey object.
 * On those runtimes we fall back to persisting the raw KEK bytes (extractable
 * during the bootstrap window only) and re-importing as non-extractable on load.
 * The probe is run once per process; the result is cached.
 *
 * Duplicated from device-identity.ts (one consumer — not worth a shared module).
 */
let structuredCloneSupported: boolean | null = null;

async function probeStructuredClone(): Promise<boolean> {
	if (structuredCloneSupported !== null) return structuredCloneSupported;
	try {
		const throwaway = await crypto.subtle.generateKey(
			{ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey'],
		);
		structuredClone(throwaway); // throws on WebViews without CryptoKey structured-clone
		structuredCloneSupported = true;
	} catch {
		structuredCloneSupported = false;
	}
	return structuredCloneSupported;
}

/**
 * Get or create the AES-KW wrapping key (KEK) for this store.
 *
 * The KEK lives in the same dedicated IDB database as the seed (ADR-9: the
 * room-host root secret and its KEK share one isolated DB, distinct from the
 * device-identity store). When the runtime supports CryptoKey structured-clone,
 * the KEK is persisted as a non-extractable CryptoKey — the raw bytes never
 * re-enter the JS heap on reload. On runtimes without structured-clone support,
 * the raw bytes are persisted (extractable during the bootstrap window only)
 * and re-imported as non-extractable on load.
 *
 * One-shot copy-only migration: if the KEK entry exists as legacy raw bytes
 * (ArrayBuffer — the pre-Phase-5 storage form), it is imported as
 * non-extractable and persisted as a CryptoKey. The seed entry is never
 * touched by the migration.
 */
async function getWrappingKey(): Promise<CryptoKey> {
	if (cachedWrappingKey) return cachedWrappingKey;

	const canClone = await probeStructuredClone();

	// One entry, one form. As in device-identity there is no legacy layout to
	// migrate from and no raw-bytes duplicate kept as a safety net — a net that
	// stores the very bytes #95 exists to remove is not a net.
	const existing = await idb.load<CryptoKey | ArrayBuffer>(WRAPPING_KEY);
	if (existing) {
		// Same classification as device-identity, from the same helper — this file
		// carried a verbatim copy of the #108 defect and shipped it in 0.2.0.
		// Fixing one call site and leaving the sibling is how that class recurs.
		const entry = classifyKekEntry(existing);
		if (!entry) {
			throw new Error(
				'[room-host-seed] KEK entry is neither an AES-KW CryptoKey nor raw bytes',
			);
		}
		cachedWrappingKey =
			entry.kind === 'raw'
				// Raw bytes — the fallback form on runtimes without CryptoKey
				// structured-clone. Re-imported non-extractable.
				? await importAesKwRaw(entry.bytes, false)
				: entry.key;
		return cachedWrappingKey;
	}

	// Fresh generation: no KEK yet. Generate non-extractable and persist as a
	// CryptoKey when structured-clone is supported; otherwise persist raw bytes
	// (extractable during the bootstrap window only) and re-import non-extractable.
	const kek = await generateAesKwKey(false);
	if (canClone) {
		await idb.save(WRAPPING_KEY, kek);
		cachedWrappingKey = kek;
	} else {
		const extractableKek = await generateAesKwKey(true);
		const raw = await crypto.subtle.exportKey('raw', extractableKek);
		await idb.save(WRAPPING_KEY, raw);
		cachedWrappingKey = await importAesKwRaw(raw, false);
	}
	return cachedWrappingKey;
}

/** Get the room-host seed, generating + persisting it on first use. */
export async function getOrCreateRoomHostSeed(): Promise<Uint8Array> {
	if (cachedSeed) return cachedSeed;

	const wrappingKey = await getWrappingKey();

	const existing = await idb.load<ArrayBuffer>(KEY);
	if (existing) {
		// Unwrap via the shared aes-kw helper. Wire format is plain AES-KW
		// ciphertext (RFC 3394), independent of the wrapped key's declared
		// algorithm — so pre-Phase-5 entries (old AES-256-import trick)
		// unwrap correctly.
		cachedSeed = await unwrapSecretBytes(wrappingKey, existing);
		return cachedSeed;
	}

	// First use: generate 32 CSPRNG bytes.
	const seed = crypto.getRandomValues(new Uint8Array(32));

	// Wrap via the shared aes-kw helper (HMAC-import trick) and persist.
	const wrapped = await wrapSecretBytes(wrappingKey, seed);
	await idb.save(KEY, wrapped);

	cachedSeed = seed;
	return cachedSeed;
}

/** Raw seed bytes for a future cross-device sync flow. Null if never created. */
export async function exportRoomHostSeed(): Promise<Uint8Array | null> {
	if (!(await idb.load<ArrayBuffer>(KEY))) return null;
	return getOrCreateRoomHostSeed();
}

/** Test-only: wipe the seed store and in-memory cache. */
export async function __clearRoomHostSeed(): Promise<void> {
	cachedSeed = null;
	cachedWrappingKey = null;
	await idb.clear();
}
