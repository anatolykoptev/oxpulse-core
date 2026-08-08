// Stage B: Persistent Ed25519 Device Identity (Layer 1)
//
// Provides long-lived cryptographic identity stored in IndexedDB.
// Keys are wrapped with AES-KW (AES-256 Key Wrapping) before storage,
// making them non-extractable during runtime but recoverable across
// page reloads.
//
// Browser support: Ed25519 in WebCrypto — Chrome 137+, Firefox 130+, Safari 17+
// On older engines (Xiaomi HyperOS frozen WebView, HarmonyOS ArkWeb ≤M132)
// WebCrypto Ed25519/X25519 throw NotSupportedError. All sign/verify/DH
// operations fall back to @noble/curves which is RFC 8032 / RFC 7748 compliant
// and produces byte-identical results accepted by ed25519_dalek::verify_strict
// on the server. AES-KW wrapping stays WebCrypto (universal support).
//
// Observability: every lifecycle transition emits a `client.identity_*`
// analytics event via tracker.ts. The server side (analytics ingest →
// device_identity_lifecycle_total / device_identity_failure_total) lets
// us answer "is the key created on first launch and reused on reload"
// without ever sending the pubkey itself. Payloads carry only bucketed
// numbers (duration_ms) and bounded enum strings (error_class).

import { ed25519 as nobleEd25519, x25519 as nobleX25519 } from '@noble/curves/ed25519.js';
import { emit as track } from './tracker-shim.js';
import { createIdbStore, IDBUnavailableError } from './idb-store.js';
import { toArrayBuffer } from './crypto-utils.js';
import { toBase64url, fromBase64url } from './base64url.js';
import { wrapSecretBytes, unwrapSecretBytes, generateAesKwKey, importAesKwRaw, classifyKekEntry } from './aes-kw.js';
import { OpaquePrivateKey } from './opaque-private-key.js';

// PKCS#8 DER prefix for a bare 32-byte Ed25519 private key seed.
// Structure: SEQUENCE { version=0, AlgorithmIdentifier { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { seed } } }
// This is the encoding WebCrypto importKey('pkcs8') expects for Ed25519.
// Verified against replaceDeviceIdentity() usage in this same file.
const ED25519_PKCS8_PREFIX = new Uint8Array([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
	0x06, 0x03, 0x2b, 0x65, 0x70,
	0x04, 0x22, 0x04, 0x20,
]);

// LOAD-BEARING: pre-existing user data uses these exact strings.
// Changing them strands every installed user's identity. NEVER rename.
// See identity-extraction-adr.md §3.4 and __tests__/storage-keys.test.ts.
const WRAPPING_KEY_NAME = 'wrapping-key';      // LOAD-BEARING — DO NOT RENAME, see ADR §3.4
const DEVICE_KEY_NAME = 'device-key';          // LOAD-BEARING — DO NOT RENAME, see ADR §3.4
const PROFILE_SEED_NAME = 'profile_seed_v1';   // LOAD-BEARING — DO NOT RENAME, see ADR §3.4
// Raw Ed25519 seed stored alongside the PKCS8-wrapped CryptoKey.
// New in W7-P2b1 followup: needed by @noble/curves sendSealedMessage path.
// AES-KW wrapped with the same wrapping key as DEVICE_KEY_NAME.
// Existing identities (CryptoKey-only) will lack this key → migration banner.
const DEVICE_PRIV_RAW_NAME = 'oxp/identity/ed25519-priv-raw'; // DO NOT RENAME after first user
// B.2-noise-s-key-derivation: X25519 static keypair for Noise XX es/se DH tokens.
// New key — existing users get a fresh X25519 keypair on first B.2 boot.
// NOT load-bearing for Ed25519 signing identity — safe to rename/regenerate.
const X25519_KEYPAIR_NAME = 'x25519-keypair-v1';

// LOAD-BEARING: IDB database + store name used by all installed users. NEVER rename.
// See identity-extraction-adr.md §3.4 and __tests__/storage-keys.test.ts.
export const IDB_DB_NAME = 'oxpulse-device-id'; // LOAD-BEARING — DO NOT RENAME, see ADR §3.4
export const IDB_STORE_NAME = 'identity';        // LOAD-BEARING — DO NOT RENAME, see ADR §3.4

const idb = createIdbStore({ dbName: IDB_DB_NAME, storeName: IDB_STORE_NAME });

// KEK lives in a separate IDB database for rotation/corruption isolation (#98).
// The identity record store and the KEK have different lifecycles — a corrupted
// identity store must not take the KEK with it. Dedicated-DB pattern per
// room-host-seed.ts:17-18 precedent.
const KEK_DB_NAME = 'oxpulse-device-id-kek';
const KEK_STORE_NAME = 'kek';
const KEK_KEY_NAME = 'wrapping-key';
const kekIdb = createIdbStore({ dbName: KEK_DB_NAME, storeName: KEK_STORE_NAME });

export interface DeviceIdentity {
	publicKeyB64: string; // base64url, 32 bytes Ed25519 public key
	/**
	 * WebCrypto Ed25519 public key handle. null when WebCrypto Ed25519 is absent
	 * (e.g. HyperOS/HarmonyOS frozen WebView). Callers that use this for
	 * crypto.subtle operations MUST check for null and fall back to noble or
	 * use publicKeyB64 directly (32-byte raw key = fromBase64url(publicKeyB64)).
	 */
	publicKey: CryptoKey | null;
	/**
	 * WebCrypto Ed25519 private key handle. null when WebCrypto Ed25519 is absent.
	 * Use privateKeySeed.bytes() + @noble/curves for signing on all runtimes.
	 */
	privateKey: CryptoKey | null;
	/**
	 * Opaque wrapper around the 32-byte raw Ed25519 private key seed.
	 * For @noble/curves sign() usage — callers use `.bytes()` to obtain the
	 * raw 32-byte seed. null for pre-W7-P2b1 identities that lack the
	 * raw-bytes IDB entry. Callers MUST check for null and show migration
	 * banner + disable sealed send. DO NOT use zero-byte sentinel —
	 * noble/curves signs known-key deterministically.
	 *
	 * SECURITY NOTE — OpaquePrivateKey hardening (ADR-5):
	 * The raw seed is wrapped in OpaquePrivateKey to prevent accidental
	 * exfiltration through logging (toString redacts, toJSON throws,
	 * util.inspect redacts). `.bytes()` returns a fresh copy on every call
	 * so callers cannot retain an alias. The raw bytes remain resident in
	 * the JS heap and cannot be explicitly zeroed (no zeroize equivalent) —
	 * the wrapper stops *accidental* exfiltration, not a determined in-process
	 * attacker. @noble/curves requires the raw seed for Ed25519 signing;
	 * HyperOS/HarmonyOS support requires noble, so this tradeoff is load-bearing.
	 */
	privateKeySeed: OpaquePrivateKey | null;
}

interface StoredIdentity {
	publicKeyB64: string;
	wrappedPrivateKey: ArrayBuffer; // AES-KW wrapped PKCS8 Ed25519 private key
}

// In-memory cache for the current session
let cachedIdentity: DeviceIdentity | null = null;
let cachedWrappingKey: CryptoKey | null = null;

/**
 * Cached probe result for CryptoKey structured-clone support.
 *
 * Some WebViews (older Android WebView, HarmonyOS ArkWeb) cannot structured-clone
 * a CryptoKey, which means it cannot be persisted to IDB as a CryptoKey object.
 * On those runtimes we fall back to persisting the raw KEK bytes (extractable
 * during the bootstrap window only) and re-importing as non-extractable on load.
 * The probe is run once per process; the result is cached.
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
 * Get or create the AES-KW wrapping key (KEK).
 *
 * The KEK lives in a dedicated IDB database (`oxpulse-device-id-kek`) separate
 * from the identity records, for rotation/corruption isolation (#98). When the
 * runtime supports CryptoKey structured-clone, the KEK is persisted as a
 * non-extractable CryptoKey — the raw bytes never re-enter the JS heap on
 * reload. On runtimes without structured-clone support, the raw bytes are
 * persisted (extractable during the bootstrap window only) and re-imported as
 * non-extractable on load.
 *
 * ## The pre-#98 layout IS migrated, and the reason is an incident
 *
 * This comment used to say: "There is deliberately NO migration from the
 * pre-#98 layout. Nothing has this package installed in the field yet, so a
 * legacy KEK cannot exist on any device that is not a developer's own browser
 * profile. If a developer has a pre-#98 identity in their profile, clear site
 * data."
 *
 * That premise was false. `@oxpulse/identity ^0.1.5` was live in oxpulse-chat
 * production from v0.16.0, and v0.17.0 shipped 0.2.0 into it on 2026-08-06.
 * The result, measured on that deployment:
 *
 *   device_identity_failure_total{error_class="unwrap_failed", stage="unwrap"}
 *     08-06, every bucket, all day and after the deploy:  0.0
 *     08-07 06h  2.0    10h  45.4    18h  35.3
 *
 * Zero for a full day, then tens — users with a perfectly good identity in
 * IndexedDB, locked out of it, because this function found no KEK in the new
 * database, generated a fresh one, and nothing could then unwrap what the old
 * one had wrapped.
 *
 * The reasoning about complexity was sound; only the fact was wrong. So the
 * migration here is the narrowest one that discharges it: it ADOPTS the legacy
 * wrapping key and touches nothing else. It does not rewrite identity records,
 * does not delete the legacy entry (the forget path already owns that), and
 * has exactly one branch. The delicate paths that produced the HIGH findings —
 * re-wrapping and fallback — are not reintroduced.
 *
 * The legacy key lives under `WRAPPING_KEY_NAME` in the IDENTITY database, and
 * `forgetDeviceIdentity` already calls it "old entry — kept by migration". The
 * intent to keep it for exactly this was recorded; the code that uses it was
 * not written. This is that code.
 */
/**
 * Adopt a pre-#98 wrapping key if this device has one; `null` otherwise.
 *
 * Returns a usable KEK and copies it into the dedicated database so this runs
 * once per device. The legacy entry is deliberately left in place: a migration
 * that deletes the only thing that can decrypt a user's identity, in the same
 * step that first tries to use it, has no second attempt if the copy fails.
 *
 * Never throws. A device with no legacy key is the common case and must reach
 * the generate path; an unreadable legacy key must ALSO reach it rather than
 * failing the whole app, since on a genuinely-new device there is nothing to
 * lose. The one thing it must not do is return a key that cannot unwrap the
 * stored identity — and it cannot, because the key it returns is the one that
 * wrapped it.
 */
async function adoptLegacyWrappingKey(canClone: boolean): Promise<CryptoKey | null> {
	let legacy: CryptoKey | ArrayBuffer | null = null;
	try {
		legacy = await idb.load<CryptoKey | ArrayBuffer>(WRAPPING_KEY_NAME);
	} catch {
		// The identity DB is unreadable. The caller's own load already handles
		// that case; here it just means "no legacy key to adopt".
		return null;
	}
	if (!legacy) return null;

	const entry = classifyKekEntry(legacy);
	if (!entry) {
		// Something is under the legacy name that is neither shape. Do not throw:
		// a first-run device must still get an identity.
		track('client.identity_kek_legacy_unusable', undefined, {});
		return null;
	}

	const key = entry.kind === 'raw'
		? await importAesKwRaw(entry.bytes, false)
		: entry.key;

	// Copy forward. Failure here is survivable — the adoption already worked for
	// THIS session, so the user is not locked out; the next load simply adopts
	// again. Reporting it matters: a device that can never complete the copy
	// would otherwise look identical to one that migrated cleanly.
	let copied = false;
	try {
		// A CryptoKey can only be persisted where structured-clone works. On a
		// runtime without it, keep using the adopted key and re-adopt next load
		// rather than exporting raw bytes — the legacy key stays where it is,
		// and re-deriving raw material to "finish" a migration is exactly the
		// kind of extra path that produced the earlier HIGH findings.
		if (entry.kind === 'raw') {
			await kekIdb.save(KEK_KEY_NAME, entry.bytes);
			copied = true;
		} else if (canClone) {
			await kekIdb.save(KEK_KEY_NAME, entry.key);
			copied = true;
		}
	} catch {
		copied = false;
	}

	track('client.identity_kek_migrated', undefined, { shape: entry.kind, copied });
	return key;
}

async function getOrCreateWrappingKey(): Promise<CryptoKey> {
	if (cachedWrappingKey) return cachedWrappingKey;

	const canClone = await probeStructuredClone();

	// Load the KEK. A read can throw: IndexedDB deserialises a stored CryptoKey
	// on READ, so a runtime that could structured-clone one when it was written
	// may fail to reconstruct it later (WebView downgrade, OS update). We do
	// NOT swallow that. There is no second copy of this key by design — keeping
	// a raw-bytes duplicate as a safety net is exactly what #95 removed, and a
	// net that defeats the thing it protects is not a net. So an unreadable KEK
	// is a hard error, and the identity it wrapped is gone.
	//
	// That is the honest trade for non-extractable key storage, and it is the
	// same one every platform keystore makes. What must never happen is
	// silently generating a fresh KEK on top of an unreadable one: the wrapped
	// seed would stay in IDB, permanently undecryptable, while the app reported
	// a brand-new device.
	const existing = await kekIdb.load<CryptoKey | ArrayBuffer>(KEK_KEY_NAME);
	if (existing) {
		// Shape classification is realm-safe and shared with room-host-seed — see
		// classifyKekEntry for why neither `instanceof CryptoKey` (#108) nor
		// `instanceof ArrayBuffer` can be used here.
		//
		// `canClone` deliberately plays no part: it measures what THIS runtime can
		// WRITE, and this branch reads what a PREVIOUS session wrote.
		const entry = classifyKekEntry(existing);
		if (!entry) {
			throw new Error(
				'[device-identity] KEK entry is neither an AES-KW CryptoKey nor raw bytes',
			);
		}
		cachedWrappingKey =
			entry.kind === 'raw'
				// Persisted as raw bytes (fallback path) — re-import non-extractable.
				? await importAesKwRaw(entry.bytes, false)
				// Persisted as a non-extractable CryptoKey — use directly.
				: entry.key;
		return cachedWrappingKey;
	}

	// No KEK in the dedicated database. That is either a first run on this
	// device, or a device carrying the pre-#98 layout — and those two must not
	// be confused, because for the second one "first run" means locking the
	// user out of an identity that is sitting right there.
	//
	// Read-only and non-destructive: adopt the legacy key, copy it forward so
	// the next load takes the fast path above, and leave the original where it
	// is. `forgetDeviceIdentity` remains the only thing that deletes it.
	const adopted = await adoptLegacyWrappingKey(canClone);
	if (adopted) {
		cachedWrappingKey = adopted;
		return cachedWrappingKey;
	}

	// Genuinely first run on this device.
	if (canClone) {
		// Persist the non-extractable CryptoKey directly — raw bytes never
		// touch the JS heap.
		const kek = await generateAesKwKey(false);
		await kekIdb.save(KEK_KEY_NAME, kek);
		cachedWrappingKey = kek;
		return cachedWrappingKey;
	} else {
		// Fallback: export raw bytes to persist, then re-import as
		// non-extractable for the cached handle. The extractable handle is
		// dropped after export; the bootstrap window is one tick.
		const extractableKek = await generateAesKwKey(true);
		const raw = await crypto.subtle.exportKey('raw', extractableKek);
		await kekIdb.save(KEK_KEY_NAME, raw);
		cachedWrappingKey = await importAesKwRaw(raw, false);
		return cachedWrappingKey;
	}
}

/**
 * Get or create the device identity.
 * This is the main entry point - call this on app initialization.
 */
export async function getOrCreateDeviceIdentity(): Promise<DeviceIdentity> {
	if (cachedIdentity) return cachedIdentity;

	const t0 = nowMs();

	// Try to load existing identity from IDB
	let stored: StoredIdentity | null = null;
	try {
		stored = await idb.load<StoredIdentity>(DEVICE_KEY_NAME);
	} catch (e) {
		// WEBVIEW-GUARD: IndexedDB absent or broken (Instagram/TikTok in-app WebViews).
		// Emit telemetry and return an ephemeral in-memory identity so the SPA loads.
		// The identity is NOT cached (cachedIdentity stays null) so a page reload
		// that finds IDB restored will pick up persistent storage automatically.
		// Callers that depend on identity persistence (signaling join signature)
		// will produce a fresh key per session — acceptable degradation vs. no load.
		if (e instanceof IDBUnavailableError) {
			track('client.idb_unavailable', undefined, { reason: e.reason });
			const ephemeral = await generateDeviceIdentity();
			return ephemeral;
		}
		// WEBVIEW-GUARD note: if IDB drops mid-call after probe success
		// (probe-cached as available, then storage layer fails on actual save/load),
		// this catch handles it as legacy identity_unwrap_failed rather than
		// IDBUnavailableError. Probe TTL (5min) makes this extremely unlikely;
		// users see "session works, identity didn't persist" — acceptable degradation.
		track('client.identity_unwrap_failed', undefined, { error_class: 'idb_open_failed' });
		throw e;
	}

	if (stored) {
		try {
			const identity = await unwrapIdentity(stored);
			cachedIdentity = identity;
			track('client.identity_loaded', undefined, { duration_ms: nowMs() - t0 });
			return identity;
		} catch (e) {
			track('client.identity_unwrap_failed', undefined, {
				error_class: classifyIdentityError(e, 'unwrap'),
			});
			throw e;
		}
	}

	// Generate new identity (extractable=true for wrapKey during bootstrap).
	// persistIdentity wraps the key for IDB and immediately unwraps it as
	// non-extractable — the returned identity carries the safe handle.
	try {
		const extractableIdentity = await generateDeviceIdentity();
		const identity = await persistIdentity(extractableIdentity);
		cachedIdentity = identity;
		track('client.identity_created', undefined, { duration_ms: nowMs() - t0 });
		return identity;
	} catch (e) {
		// WEBVIEW-GUARD: IDB became unavailable between the probe (load above) and
		// the persist attempt. Treat same as the load-path fallback.
		if (e instanceof IDBUnavailableError) {
			track('client.idb_unavailable', undefined, { reason: e.reason });
			const ephemeral = await generateDeviceIdentity();
			return ephemeral;
		}
		// S9: QuotaExceededError — IDB quota full. Treat same as IDBUnavailable:
		// emit ephemeral identity so the app can boot, with a distinct metric
		// so operators can alert on quota pressure.
		if ((e as { name?: string })?.name === 'QuotaExceededError') {
			track('client.identity_quota_exceeded_fallback', undefined, {
				error_class: 'idb_quota_exceeded',
			});
			const ephemeral = await generateDeviceIdentity();
			return ephemeral;
		}
		track('client.identity_create_failed', undefined, {
			error_class: classifyIdentityError(e, 'create'),
		});
		throw e;
	}
}

function nowMs(): number {
	if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
		return performance.now();
	}
	return Date.now();
}

/**
 * Thrown when the stored identity data is missing or malformed — as opposed to
 * the runtime lacking a capability.
 *
 * It exists because classifyIdentityError sniffs the message for /Ed25519/i to
 * detect WebCrypto's "Ed25519 is not supported", and two of this file's own
 * error messages contain the word Ed25519 while meaning the opposite:
 * "No Ed25519 private key in IDB" and "Unexpected PKCS#8 length for Ed25519
 * key" are a missing entry and a corrupt one. Both were being reported as
 * ed25519_unsupported, so an operator investigating a spike of "this runtime
 * cannot do Ed25519" would have found data corruption mixed in.
 */
export class IdentityDataError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'IdentityDataError';
	}
}

/**
 * Map a thrown error to one of the bounded enum values mirrored in
 * `crates/server/src/analytics/mod.rs:sanitize_identity_error_class`.
 * Anything we cannot classify becomes `unknown` server-side. Strings
 * here MUST stay in lockstep with the server's allowlist — Prometheus
 * cardinality is bounded by that, not by what we send.
 */
function classifyIdentityError(e: unknown, stage: 'create' | 'unwrap'): string {
	const name = (e as { name?: string })?.name ?? '';
	const message = String((e as { message?: string })?.message ?? '');
	if (name === 'QuotaExceededError') return 'idb_quota_exceeded';
	// Ours, and typed — checked BEFORE the message sniffing below, which would
	// otherwise read the word Ed25519 in a missing-data message as a capability
	// failure. See IdentityDataError.
	if (name === 'IdentityDataError') return stage === 'create' ? 'wrap_failed' : 'unwrap_failed';
	if (name === 'NotSupportedError' || /Ed25519/i.test(message)) return 'ed25519_unsupported';
	if (name === 'InvalidAccessError' && stage === 'create') return 'extractable_unsupported';
	if (stage === 'create') return 'wrap_failed';
	return 'unwrap_failed';
}

/**
 * Generate a new Ed25519 device identity.
 *
 * Uses @noble/curves::ed25519.keygen() to obtain raw 32-byte seed material
 * (required by sendSealedMessage and other @noble/curves callers — there is
 * no path from a non-extractable WebCrypto CryptoKey to raw bytes).
 *
 * The raw seed is then imported as PKCS8 into WebCrypto with extractable=true
 * so persistIdentity() can wrapKey() it for IDB. The extractable CryptoKey
 * handle is dropped after wrapping; the returned identity carries only the
 * non-extractable runtime handle. Bootstrap window ≈1 ms (same risk surface
 * as Signal desktop). See also: FOLLOWUPS.md #10.
 *
 * Both raw bytes and the PKCS8-wrapped CryptoKey are persisted to IDB so
 * both forms survive page reload.
 */
export async function generateDeviceIdentity(): Promise<DeviceIdentity> {
	// Use @noble/curves keygen so we have access to raw seed bytes.
	// keygen() returns { secretKey: Uint8Array(32), publicKey: Uint8Array(32) }.
	const kp = nobleEd25519.keygen();
	const rawSeed = kp.secretKey; // 32-byte raw Ed25519 seed
	const publicKeyB64 = toBase64url(kp.publicKey);

	// Attempt to import into WebCrypto for callers that hold a CryptoKey reference
	// (e.g. mesh-core/transport.ts Noise XX sign path). On HyperOS/HarmonyOS and
	// other runtimes that lack WebCrypto Ed25519 (Chrome <137), these calls throw
	// NotSupportedError — we degrade gracefully to null and rely on @noble/curves
	// for all signing/verification. Signing via signWithDeviceIdentity() always uses
	// noble (see below), so the null CryptoKey never reaches verify_strict.

	let privateKey: CryptoKey | null = null;
	let publicKey: CryptoKey | null = null;
	try {
		// Build PKCS8 envelope to import into WebCrypto (Ed25519 'raw' import not
		// supported for private keys — only public keys accept 'raw' format).
		const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.byteLength + 32);
		pkcs8.set(ED25519_PKCS8_PREFIX, 0);
		pkcs8.set(rawSeed, ED25519_PKCS8_PREFIX.byteLength);

		// extractable: true — required for wrapKey in persistIdentity (plan §B.1)
		privateKey = await crypto.subtle.importKey(
			'pkcs8',
			pkcs8.buffer.slice(0, pkcs8.byteLength),
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			true,
			['sign']
		);

		// Import public key via WebCrypto for verify usage.
		publicKey = await crypto.subtle.importKey(
			'raw',
			toArrayBuffer(kp.publicKey),
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false,
			['verify']
		);
	} catch (e) {
		// WebCrypto Ed25519 absent (HyperOS/HarmonyOS, Chrome <137).
		// sign/verify routes through @noble/curves — CryptoKey fields stay null.
		// Log once per session to surface in Loki without spamming.
		if ((e as { name?: string })?.name === 'NotSupportedError') {
			console.info('[identity] WebCrypto Ed25519 unavailable — using @noble/curves fallback');
		} else {
			// Re-throw unexpected errors (e.g. malformed key material)
			throw e;
		}
	}

	return {
		publicKeyB64,
		publicKey,
		privateKey,
		privateKeySeed: new OpaquePrivateKey(rawSeed),
	};
}

/**
 * Persist identity to IDB (wrapped with AES-KW).
 *
 * Stores two IDB entries:
 *   DEVICE_KEY_NAME       — AES-KW wrapped PKCS8 CryptoKey (pre-existing, null when
 *                           WebCrypto Ed25519 absent — noble-only path still stores
 *                           an empty ArrayBuffer sentinel so the IDB key exists)
 *   DEVICE_PRIV_RAW_NAME  — AES-KW wrapped raw 32-byte Ed25519 seed (authoritative)
 *
 * Returns a new DeviceIdentity whose privateKey is the unwrapped
 * non-extractable handle (or null on noble-only runtimes).
 */
async function persistIdentity(identity: DeviceIdentity): Promise<DeviceIdentity> {
	const wrappingKey = await getOrCreateWrappingKey();

	// persistIdentity is only called from generateDeviceIdentity which always
	// sets privateKeySeed from the noble Ed25519 keypair — never null.
	if (!identity.privateKeySeed) {
		throw new Error('[identity] persistIdentity called with null privateKeySeed — invariant violation');
	}

	// Wrap raw 32-byte seed via the algorithm-agnostic aes-kw helper (HMAC-import
	// trick). This is the authoritative storage — the PKCS8 path below is
	// best-effort. Wire format changed from the old inline AES-256-import trick;
	// old entries still unwrap correctly because AES-KW ciphertext is
	// independent of the wrapped key's declared algorithm.
	const wrappedRawSeed = await wrapSecretBytes(wrappingKey, identity.privateKeySeed.bytes());
	await idb.save(DEVICE_PRIV_RAW_NAME, wrappedRawSeed);

	// PKCS8 wrap path: only possible when WebCrypto Ed25519 is available (non-null
	// privateKey). On noble-only runtimes store a zero-length sentinel so
	// unwrapIdentity can detect the noble-only case and skip unwrapKey.
	let nonExtractablePrivKey: CryptoKey | null = null;
	if (identity.privateKey !== null) {
		// Wrap the extractable private key for storage (PKCS8 format — Ed25519 'raw' not supported).
		const wrappedPrivateKey = await crypto.subtle.wrapKey(
			'pkcs8',
			identity.privateKey,
			wrappingKey,
			'AES-KW'
		);

		const stored: StoredIdentity = {
			publicKeyB64: identity.publicKeyB64,
			wrappedPrivateKey,
		};
		await idb.save(DEVICE_KEY_NAME, stored);

		// Immediately unwrap to obtain the non-extractable runtime handle.
		// The extractable CryptoKey in `identity.privateKey` goes out of scope
		// after this function returns — callers must use the returned identity.
		nonExtractablePrivKey = await crypto.subtle.unwrapKey(
			'pkcs8',
			wrappedPrivateKey,
			wrappingKey,
			'AES-KW',
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false, // non-extractable from this point forward
			['sign']
		);
	} else {
		// Noble-only runtime: persist publicKeyB64 + zero-length wrappedPrivateKey
		// so the DEVICE_KEY_NAME entry exists and unwrapIdentity knows the record.
		const stored: StoredIdentity = {
			publicKeyB64: identity.publicKeyB64,
			wrappedPrivateKey: new ArrayBuffer(0),
		};
		await idb.save(DEVICE_KEY_NAME, stored);
	}

	// Import the WebCrypto public key for callers that hold CryptoKey (best-effort).
	let publicKey: CryptoKey | null = identity.publicKey;
	if (publicKey === null) {
		try {
			publicKey = await crypto.subtle.importKey(
				'raw',
				toArrayBuffer(fromBase64url(identity.publicKeyB64)),
				{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
				false,
				['verify']
			);
		} catch {
			// Still absent — stay null.
		}
	}

	return {
		publicKeyB64: identity.publicKeyB64,
		publicKey,
		privateKey: nonExtractablePrivKey,
		privateKeySeed: identity.privateKeySeed,
	};
}

/**
 * Unwrap identity from storage.
 *
 * Loads both the PKCS8-wrapped CryptoKey (best-effort, null on noble-only
 * runtimes) and the AES-KW-wrapped raw seed (authoritative for signing).
 * If the raw seed is absent (pre-W7-P2b1 identity), logs a warning and
 * emits a migration-needed event — DO NOT silently regenerate (that would
 * invalidate the user's enrolled pubkey on the server).
 */
async function unwrapIdentity(stored: StoredIdentity): Promise<DeviceIdentity> {
	const wrappingKey = await getOrCreateWrappingKey();

	// Import the public key via WebCrypto (best-effort).
	// On noble-only runtimes this throws NotSupportedError — we fall back to null.
	// The raw bytes are always available via fromBase64url(stored.publicKeyB64).
	let publicKey: CryptoKey | null = null;
	try {
		const publicKeyBytes = fromBase64url(stored.publicKeyB64);
		publicKey = await crypto.subtle.importKey(
			'raw',
			toArrayBuffer(publicKeyBytes),
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false,
			['verify']
		);
	} catch (e) {
		if ((e as { name?: string })?.name !== 'NotSupportedError') throw e;
		// Noble-only runtime — publicKey stays null.
	}

	// Unwrap the PKCS8 private key (best-effort).
	// Zero-length wrappedPrivateKey = noble-only identity persisted by a new client.
	// Skip unwrapKey in that case — only raw seed matters for signing.
	let privateKey: CryptoKey | null = null;
	if (stored.wrappedPrivateKey.byteLength > 0) {
		try {
			privateKey = await crypto.subtle.unwrapKey(
				'pkcs8',
				stored.wrappedPrivateKey,
				wrappingKey,
				'AES-KW',
				{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
				false,
				['sign']
			);
		} catch (e) {
			if ((e as { name?: string })?.name !== 'NotSupportedError') throw e;
			// Noble-only runtime — privateKey stays null.
		}
	}

	// Load raw seed (new in W7-P2b1 followup).
	// Absent on pre-W7-P2b1 identities — signal migration, don't regenerate.
	const wrappedRawSeed = await idb.load<ArrayBuffer>(DEVICE_PRIV_RAW_NAME);
	if (wrappedRawSeed) {
		// Unwrap via the algorithm-agnostic aes-kw helper (HMAC-import trick).
		// Works for both old entries (wrapped with the inline AES-256-import
		// trick) and new entries (wrapped with wrapSecretBytes) — AES-KW
		// ciphertext is independent of the wrapped key's declared algorithm.
		const rawSeed = await unwrapSecretBytes(wrappingKey, wrappedRawSeed);
		return { publicKeyB64: stored.publicKeyB64, publicKey, privateKey, privateKeySeed: new OpaquePrivateKey(rawSeed) };
	} else {
		// Pre-W7-P2b1 identity: raw seed unavailable.
		// Return null so callers can show migration banner + disable sealed send.
		// NEVER use a zero sentinel — noble/curves signs the known all-zero key
		// deterministically, producing correlatable signatures that recipients drop.
		console.warn(
			'[identity] Ed25519 raw seed absent — pre-W7-P2b1 identity.' +
			' Re-registration required for sealed message support.'
		);
		track('client.identity_migration_needed', undefined, { reason: 'no_raw_seed' });
		return {
			publicKeyB64: stored.publicKeyB64,
			publicKey,
			privateKey,
			privateKeySeed: null,
		};
	}

}

/**
 * Sign a message with the device identity.
 * Used for WebSocket Join handshake.
 *
 * Uses @noble/curves ed25519.sign() — RFC 8032 non-prehash Ed25519.
 * Produces byte-identical signatures accepted by ed25519_dalek::verify_strict
 * on the server. Works on all runtimes including HyperOS/HarmonyOS where
 * WebCrypto Ed25519 is absent (Chrome <137).
 *
 * Requires privateKeySeed to be non-null (pre-W7-P2b1 identities without
 * raw seed must re-register — checked by the caller).
 */
export async function signWithDeviceIdentity(
	identity: DeviceIdentity,
	message: string
): Promise<string> {
	if (!identity.privateKeySeed) {
		throw new Error('[identity] signWithDeviceIdentity: privateKeySeed is null — identity migration required');
	}
	const msg = new TextEncoder().encode(message);
	const sig = nobleEd25519.sign(msg, identity.privateKeySeed.bytes());
	return toBase64url(sig);
}

/**
 * Verify an Ed25519 signature against raw public key bytes.
 * Used by contact-bootstrap.ts to verify incoming BootstrapPayload signatures.
 *
 * Uses @noble/curves ed25519.verify() — works on all runtimes including
 * HyperOS/HarmonyOS where WebCrypto Ed25519 throws NotSupportedError.
 *
 * @param pubkeyBytes - 32-byte Ed25519 public key (raw, not wrapped)
 * @param message     - UTF-8 string that was signed
 * @param sigBytes    - 64-byte Ed25519 signature
 */
export async function verifyDeviceSignature(
	pubkeyBytes: Uint8Array,
	message: string,
	sigBytes: Uint8Array
): Promise<boolean> {
	try {
		const msgBuf = new TextEncoder().encode(message);
		// zip215:false aligns with server ed25519_dalek::verify_strict — both enforce
		// RFC 8032 strict semantics (reject small-order / non-canonical pubkeys).
		return nobleEd25519.verify(sigBytes, msgBuf, pubkeyBytes, { zip215: false });
	} catch {
		return false;
	}
}

/**
 * Clear the device identity (user-initiated "forget this device").
 *
 * Also wipes the profile_seed (plan §1.1) so the encryption-key root is
 * destroyed atomically with the signing identity — leaving the seed behind
 * would let a fresh identity decrypt orphaned profile blobs.
 *
 * Also wipes the X25519 static keypair (B.2-noise-s-key-derivation) so
 * the Noise XX DH key is invalidated with the rest of the identity.
 */
export async function clearDeviceIdentity(): Promise<void> {
	cachedIdentity = null;
	cachedWrappingKey = null;
	cachedProfileSeed = null;
	cachedX25519Keypair = null;
	await idb.delete(DEVICE_KEY_NAME);
	await idb.delete(DEVICE_PRIV_RAW_NAME);
	await idb.delete(WRAPPING_KEY_NAME);  // old entry — kept by migration, cleared on explicit forget
	await idb.delete(PROFILE_SEED_NAME);
	await idb.delete(X25519_KEYPAIR_NAME);
	await kekIdb.clear();  // new KEK DB
	track('client.identity_wiped');
}

// ─── X25519 static keypair (B.2-noise-s-key-derivation) ──────────────────────
//
// Used for the Noise XX `es`/`se` DH tokens. Separate from the Ed25519 signing
// keypair: Ed25519 is non-extractable (WebCrypto) and cannot perform X25519 DH
// directly. We store an independent X25519 keypair (Option B per B.2 design doc).
//
// The X25519 private key is AES-KW wrapped (same wrapping key as Ed25519).
// The public key is stored as raw 32 bytes — it is public anyway.
//
// Migration: existing users (Ed25519-only) get a fresh X25519 keypair on first
// call to getOrCreateX25519Keypair() after B.2 upgrade. No disruption to existing
// session or Ed25519 identity — only the Noise handshake gains static DH binding.
//
// Noble fallback: WebCrypto X25519 is Chrome 133+ only. On older runtimes
// (HyperOS/HarmonyOS), generateKey('X25519') throws NotSupportedError.
// We fall back to @noble/curves x25519 for both keygen and DH — RFC 7748
// compliant, produces byte-identical shared secrets.

/** Cached X25519 keypair for this session. */
interface X25519KeypairCache {
	publicKey: Uint8Array;                  // raw 32-byte X25519 public key
	privateKey: CryptoKey | null;           // non-extractable ECDH (X25519) private key, null on noble-only runtimes
	privateKeySeed: Uint8Array | null;     // raw 32-byte X25519 private key for @noble/curves DH, null when WebCrypto available
}

interface StoredX25519Keypair {
	publicKey: ArrayBuffer;         // raw 32-byte X25519 public key
	wrappedPrivateKey: ArrayBuffer; // AES-KW wrapped PKCS#8 X25519 private key (zero-length on noble-only)
}

interface StoredX25519NobleKeypair extends StoredX25519Keypair {
	wrappedPrivateKeyRaw?: ArrayBuffer; // AES-KW wrapped raw 32-byte private key (noble-only path)
}

let cachedX25519Keypair: X25519KeypairCache | null = null;

/**
 * Get or create the X25519 static keypair for Noise XX es/se DH.
 *
 * Idempotent: first call generates + persists; subsequent calls return cached.
 * Wiped by clearDeviceIdentity() along with the rest of the identity.
 *
 * Falls back to @noble/curves x25519 when WebCrypto X25519 is absent (Chrome <133).
 *
 * @returns { publicKey: Uint8Array (32 bytes), privateKey: CryptoKey | null }
 */
export async function getOrCreateX25519Keypair(): Promise<{ publicKey: Uint8Array; privateKey: CryptoKey | null }> {
	if (cachedX25519Keypair) return cachedX25519Keypair;

	const wrappingKey = await getOrCreateWrappingKey();

	const existing = await idb.load<StoredX25519NobleKeypair>(X25519_KEYPAIR_NAME);
	if (existing) {
		const pub = new Uint8Array(existing.publicKey);

		// Noble-only identity: wrappedPrivateKey is zero-length, wrappedPrivateKeyRaw has the seed.
		if (existing.wrappedPrivateKey.byteLength === 0 && existing.wrappedPrivateKeyRaw) {
			const rawBuf = await unwrapSecretBytes(wrappingKey, existing.wrappedPrivateKeyRaw);
			cachedX25519Keypair = { publicKey: pub, privateKey: null, privateKeySeed: rawBuf };
			return cachedX25519Keypair;
		}

		// WebCrypto path: unwrap PKCS#8 private key.
		try {
			const priv = await crypto.subtle.unwrapKey(
				'pkcs8',
				existing.wrappedPrivateKey,
				wrappingKey,
				'AES-KW',
				'X25519',
				false, // non-extractable at runtime
				['deriveBits'],
			);
			cachedX25519Keypair = { publicKey: pub, privateKey: priv, privateKeySeed: null };
			return cachedX25519Keypair;
		} catch (e) {
			if ((e as { name?: string })?.name !== 'NotSupportedError') throw e;
			// S8: WebCrypto X25519 newly absent (runtime downgrade).
			// If the original generation persisted wrappedPrivateKeyRaw (S8 fix),
			// recover the existing key via the noble path instead of regenerating
			// and breaking TOFU trust with all peers.
			if (existing.wrappedPrivateKeyRaw && existing.wrappedPrivateKeyRaw.byteLength > 0) {
				const rawBuf = await unwrapSecretBytes(wrappingKey, existing.wrappedPrivateKeyRaw);
				cachedX25519Keypair = { publicKey: pub, privateKey: null, privateKeySeed: rawBuf };
				console.info('[identity] WebCrypto X25519 downgrade — recovered existing keypair via noble fallback');
				return cachedX25519Keypair;
			}
			// No raw fallback persisted (pre-S8 keypair) — fall through to regenerate.
			// Existing keypair bytes are lost; generate fresh (noble path).
		}
	}

	// Try WebCrypto generateKey first (Chrome 133+, Firefox 130+, Safari 17+).
	try {
		// Generate a fresh X25519 keypair.
		// extractable: true is required so we can wrapKey (PKCS#8) for IDB storage.
		// The private key is immediately wrapped and re-imported as non-extractable.
		const kp = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;

		const rawPub = await crypto.subtle.exportKey('raw', kp.publicKey);
		const pub = new Uint8Array(rawPub);

		const wrappedPriv = await crypto.subtle.wrapKey('pkcs8', kp.privateKey, wrappingKey, 'AES-KW');

		// S8: also export the raw private key bytes and wrap them as AES-KW.
		// Persisting wrappedPrivateKeyRaw alongside wrappedPrivateKey means a
		// later WebCrypto X25519 downgrade (browser update removes X25519
		// support) can recover via the noble path at line 654-666 instead of
		// regenerating a fresh keypair and breaking TOFU trust with all peers.
		const rawPrivBytes = await crypto.subtle.exportKey('raw', kp.privateKey);
		const wrappedPrivRaw = await wrapSecretBytes(wrappingKey, new Uint8Array(rawPrivBytes));

		// Persist before re-importing as non-extractable (window ≈ one tick, only WebCrypto awaits).
		await idb.save<StoredX25519NobleKeypair>(X25519_KEYPAIR_NAME, {
			publicKey: rawPub,
			wrappedPrivateKey: wrappedPriv,
			wrappedPrivateKeyRaw: wrappedPrivRaw,
		});

		// Re-import non-extractable — drop the extractable handle.
		const nonExtractPriv = await crypto.subtle.unwrapKey(
			'pkcs8',
			wrappedPriv,
			wrappingKey,
			'AES-KW',
			'X25519',
			false,
			['deriveBits'],
		);

		cachedX25519Keypair = { publicKey: pub, privateKey: nonExtractPriv, privateKeySeed: null };
		return cachedX25519Keypair;
	} catch (e) {
		if ((e as { name?: string })?.name !== 'NotSupportedError') throw e;
		// WebCrypto X25519 absent — fall back to @noble/curves.
		console.info('[identity] WebCrypto X25519 unavailable — using @noble/curves fallback');
	}

	// Noble fallback: generate X25519 keypair via @noble/curves.
	const privBytes = nobleX25519.utils.randomSecretKey();
	const pubBytes = nobleX25519.getPublicKey(privBytes);

	// Wrap private key bytes via the algorithm-agnostic aes-kw helper for IDB persistence.
	const wrappedPrivRaw = await wrapSecretBytes(wrappingKey, privBytes);

	await idb.save<StoredX25519NobleKeypair>(X25519_KEYPAIR_NAME, {
		publicKey: toArrayBuffer(pubBytes),
		wrappedPrivateKey: new ArrayBuffer(0), // zero-length = noble-only sentinel
		wrappedPrivateKeyRaw: wrappedPrivRaw,
	});

	cachedX25519Keypair = { publicKey: pubBytes, privateKey: null, privateKeySeed: privBytes };
	return cachedX25519Keypair;
}

/**
 * Perform X25519 Diffie-Hellman with the device's static X25519 private key.
 *
 * Uses WebCrypto deriveBits when available, falls back to @noble/curves
 * x25519.getSharedSecret() on old runtimes (HyperOS/HarmonyOS, Chrome <133).
 * Both produce identical results per RFC 7748.
 *
 * @param remotePub - 32-byte X25519 public key of the remote party
 */
export async function dhX25519(remotePub: Uint8Array): Promise<Uint8Array> {
	const kp = await getOrCreateX25519Keypair();

	// Noble-only path: private key is raw bytes.
	if (kp.privateKey === null) {
		const cached = cachedX25519Keypair;
		if (!cached?.privateKeySeed) {
			throw new Error('[identity] dhX25519: no X25519 private key available');
		}
		return nobleX25519.getSharedSecret(cached.privateKeySeed, remotePub);
	}

	// WebCrypto path.
	// Import remote public key for ECDH deriveBits.
	// toArrayBuffer() ensures we pass an ArrayBuffer (not SharedArrayBuffer) to WebCrypto.
	const remoteCryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(remotePub), 'X25519', false, []);

	const sharedBits = await crypto.subtle.deriveBits(
		{ name: 'X25519', public: remoteCryptoKey },
		kp.privateKey,
		256, // 32 bytes
	);
	return new Uint8Array(sharedBits);
}

// ─── Profile seed (plan §1.1) ─────────────────────────────────────────────
//
// 32 random bytes generated on first use and persisted in the same identity
// IDB store. Used as HKDF ikm when deriving the at-rest profile encryption
// key (see profile-crypto.ts:deriveProfileKey). Distinct from the Ed25519
// keypair so the signing identity stays non-extractable while the profile
// key derivation has access to genuinely secret material — the device pubkey
// is public (it's the room-handshake identity) and must NOT be the ikm.

let cachedProfileSeed: Uint8Array | null = null;

/**
 * Get or create the 32-byte profile_seed for this device.
 *
 * Idempotent: first call generates random bytes and persists; subsequent
 * calls return the same bytes. Wiped by clearDeviceIdentity() and
 * clearProfileSeed().
 */
export async function getOrCreateProfileSeed(): Promise<Uint8Array> {
	if (cachedProfileSeed) return cachedProfileSeed;

	const existing = await idb.load<ArrayBuffer>(PROFILE_SEED_NAME);
	if (existing) {
		cachedProfileSeed = new Uint8Array(existing);
		return cachedProfileSeed;
	}

	const seed = new Uint8Array(32);
	crypto.getRandomValues(seed);
	// Persist as ArrayBuffer (structured-clone safe) — match wrapping-key style.
	await idb.save(PROFILE_SEED_NAME, seed.buffer);
	cachedProfileSeed = seed;
	return cachedProfileSeed;
}

/**
 * Wipe the profile_seed without touching the Ed25519 identity.
 *
 * Defensive helper for callers that want to roll the encryption-key root
 * without invalidating the device's signing identity. Not on the standard
 * "delete profile" path — `clearLocalProfile` keeps the seed so that
 * re-creating a profile under the same identity stays a no-op for the
 * room-handshake layer.
 */
export async function clearProfileSeed(): Promise<void> {
	cachedProfileSeed = null;
	await idb.delete(PROFILE_SEED_NAME);
}

/**
 * One-shot probe: does this runtime support WebCrypto Ed25519?
 *
 * Emits `client.identity_browser_support` once per session-and-process
 * (gated by sessionStorage so SPA navigations don't re-fire). Surfaces
 * a `device_identity_browser_support_total{ed25519=ok|missing}` gauge.
 *
 * NOTE: after the noble-universal swap, `ed25519=missing` no longer means
 * "identity creation will fail" — @noble/curves provides the fallback.
 * The gauge now means "what fraction of our fleet has native WebCrypto Ed25519?"
 * (i.e. Chrome 137+) — useful telemetry for deprecating the noble path
 * once old HyperOS/HarmonyOS WebViews age out. Never throws.
 *
 * Should be called from app bootstrap (e.g. +layout.svelte onMount).
 * Idempotent and cheap; skips the actual generateKey on subsequent
 * sessions to avoid extra entropy draw.
 */
let browserSupportProbed = false;
export async function probeBrowserSupport(): Promise<void> {
	if (browserSupportProbed) return;
	browserSupportProbed = true;
	const sentinelKey = 'oxpulse:identity:browser-support:probed-v1';
	if (typeof sessionStorage !== 'undefined') {
		try {
			if (sessionStorage.getItem(sentinelKey) === '1') return;
			sessionStorage.setItem(sentinelKey, '1');
		} catch {
			/* storage disabled — fall through, probe each session */
		}
	}
	let ed25519 = false;
	try {
		await crypto.subtle.generateKey(
			{ name: 'Ed25519' } as unknown as AlgorithmIdentifier,
			false,
			['sign', 'verify']
		);
		ed25519 = true;
	} catch {
		ed25519 = false;
	}
	track('client.identity_browser_support', undefined, { ed25519 });
}

/**
 * Check if device identity exists in IDB.
 */
export async function hasDeviceIdentity(): Promise<boolean> {
	const stored = await idb.load<StoredIdentity>(DEVICE_KEY_NAME);
	return stored !== null;
}

// base64url helpers are now in ./base64url.js — imported at top of file.
// Re-exported here for API compatibility with existing test imports.
export { toBase64url, fromBase64url } from './base64url.js';

// ─── Identity backup helpers ───────────────────────────────────────────────
//
// These internal helpers are for the identity-backup restore path only.
// They are NOT part of the normal identity lifecycle.

/**
 * Export the raw 32-byte Ed25519 secret scalar for backup purposes.
 *
 * The runtime CryptoKey is non-extractable, so we must:
 *   1. Load the raw AES-KW wrapping key bytes from IDB.
 *   2. Re-import with wrapKey+unwrapKey usage.
 *   3. unwrapKey with extractable=true to get an extractable private key.
 *   4. exportKey("pkcs8") -> 48-byte PKCS#8 envelope.
 *   5. Strip the 16-byte OID header to get the raw 32-byte secret.
 *
 * Public API, narrow scope: use only on the identity-backup export path.
 * Re-exported from `index.ts`. The leading paragraphs document the threat
 * model that gates lawful use; do not call this from product feature code.
 *
 * Every call is audited — see the exported wrapper below.
 */
async function exportRawDeviceSecretImpl(): Promise<{ secret: Uint8Array; publicB64u: string }> {
	const stored = await idb.load<{ publicKeyB64: string; wrappedPrivateKey: ArrayBuffer }>(DEVICE_KEY_NAME);
	if (!stored) {
		throw new IdentityDataError("No device identity in IDB");
	}

	// ADR-8: the KEK is now a non-extractable CryptoKey in the dedicated KEK DB
	// (no raw bytes in the identity DB). getOrCreateWrappingKey() returns the
	// non-extractable handle; unwrapKey's extractability is independent of the
	// KEK's extractability, so we can still unwrap as extractable here.
	const wrappingKey = await getOrCreateWrappingKey();

	// On noble-only runtimes (HyperOS/HarmonyOS) wrappedPrivateKey is zero-length
	// (no PKCS8 wrap was possible). Fall back to unwrapping the raw seed from
	// DEVICE_PRIV_RAW_NAME — same secret, different wrap format.
	if (stored.wrappedPrivateKey.byteLength === 0) {
		// Noble-only: unwrap raw seed via aes-kw.ts
		const wrappedRawSeed = await idb.load<ArrayBuffer>(DEVICE_PRIV_RAW_NAME);
		if (!wrappedRawSeed) {
			throw new IdentityDataError("No Ed25519 private key in IDB (noble-only identity, no raw seed stored)");
		}
		const secret = await unwrapSecretBytes(wrappingKey, wrappedRawSeed);
		return { secret, publicB64u: stored.publicKeyB64 };
	}

	// WebCrypto path: unwrap PKCS8 with extractable=true, export, strip 16-byte OID header.
	// unwrapKey's extractability is independent of the KEK's extractability.
	const extractablePrivKey = await crypto.subtle.unwrapKey(
		"pkcs8",
		stored.wrappedPrivateKey,
		wrappingKey,
		"AES-KW",
		{ name: "Ed25519" } as unknown as AlgorithmIdentifier,
		true,
		["sign"],
	);

	const pkcs8 = await crypto.subtle.exportKey("pkcs8", extractablePrivKey);
	const pkcs8Bytes = new Uint8Array(pkcs8);
	// UNREACHABLE BY CONSTRUCTION, kept as a guard against a WebCrypto bug.
	//
	// Measured rather than assumed. A test tried to reach it by storing a
	// wrappedPrivateKey that unwraps to a 40-byte buffer; the unwrap rejects
	// first with `DataError: Invalid keyData`, because unwrapKey('pkcs8', ...,
	// Ed25519) validates the envelope structure. So the only way past that line
	// is a valid Ed25519 CryptoKey, and exportKey('pkcs8') on one of those is
	// always >= 48 bytes.
	//
	// That test was deleted rather than kept: it passed, but on the unwrap
	// error, not this branch — coverage advertised and not delivered. Mutating
	// either this throw's type or the 48 to a 1 is invisible to the suite, and
	// that is a property of the branch being unreachable, not of a missing test.
	if (pkcs8Bytes.byteLength < 48) {
		throw new IdentityDataError("Unexpected PKCS#8 length for Ed25519 key");
	}
	const secret = pkcs8Bytes.slice(16);

	return { secret, publicB64u: stored.publicKeyB64 };
}

/**
 * Audited entry point for raw-secret export (#103).
 *
 * The event is emitted by this WRAPPER, not at each return inside the
 * implementation. There are two success paths today — noble-only and WebCrypto —
 * and a third would silently escape a hand-placed emit. That is the same
 * "the code is right and nothing observes it" failure this package hit four
 * times during #108; a wrapper cannot be bypassed by a new return statement.
 *
 * A FAILED export is emitted too. Repeated failures are what probing looks
 * like, and a silent failure is exactly what an attacker would prefer.
 *
 * The payload carries NO key material. The auditable fact is that an export
 * happened, which is the only thing a defender can act on.
 *
 * SCOPE — read this before treating the event as an exfiltration alarm.
 * It audits the BACKUP path, not access to the seed in general. The same 32
 * bytes are reachable from the ordinary public API as
 * `getOrCreateDeviceIdentity().privateKeySeed.bytes()`, measured byte-identical
 * to this function's output. `generateDeviceIdentity()` is a second route of the
 * same shape — a different seed, since it mints a fresh keypair, but equally
 * unaudited. That path is on the signing hot path and cannot be
 * audited without emitting an event per signature, so it is deliberately not
 * instrumented. In-page code that wants the seed will take that route and this
 * event will not fire. What this buys is a record of deliberate backup exports —
 * useful for "was this identity exported before it appeared elsewhere" — and it
 * should not be described as closing the #103 hole.
 */
export async function exportRawDeviceSecret(): Promise<{ secret: Uint8Array; publicB64u: string }> {
	const t0 = nowMs();
	try {
		const result = await exportRawDeviceSecretImpl();
		track('client.identity_raw_export', undefined, {
			outcome: 'ok',
			duration_ms: nowMs() - t0,
		});
		return result;
	} catch (e) {
		track('client.identity_raw_export', undefined, {
			outcome: 'error',
			error_class: classifyIdentityError(e, 'unwrap'),
			duration_ms: nowMs() - t0,
		});
		throw e;
	}
}

/**
 * Replace the stored device identity with the provided Ed25519 secret + pubkey.
 * Public API, narrow scope: use only on the identity-backup restore path.
 * Re-exported from `index.ts`. Do not call from product feature code.
 */
export async function replaceDeviceIdentity(
	secret: Uint8Array,
	publicB64u: string,
): Promise<void> {
	cachedIdentity = null;
	cachedWrappingKey = null;

	const wrappingKey = await getOrCreateWrappingKey();

	// Always persist the raw seed (authoritative for noble-only runtimes).
	const wrappedRawSeed = await wrapSecretBytes(wrappingKey, secret);
	await idb.save(DEVICE_PRIV_RAW_NAME, wrappedRawSeed);

	// Try WebCrypto PKCS8 wrap (best-effort — not available on HyperOS/HarmonyOS).
	// On noble-only runtimes, store zero-length wrappedPrivateKey sentinel.
	let wrappedPrivateKey: ArrayBuffer = new ArrayBuffer(0);
	try {
		const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.byteLength + secret.byteLength);
		pkcs8.set(ED25519_PKCS8_PREFIX, 0);
		pkcs8.set(secret, ED25519_PKCS8_PREFIX.byteLength);

		const extractableKey = await crypto.subtle.importKey(
			"pkcs8",
			pkcs8.buffer.slice(0, pkcs8.byteLength),
			{ name: "Ed25519" } as unknown as AlgorithmIdentifier,
			true,
			["sign"],
		);
		wrappedPrivateKey = await crypto.subtle.wrapKey("pkcs8", extractableKey, wrappingKey, "AES-KW");
	} catch (e) {
		if ((e as { name?: string })?.name !== 'NotSupportedError') throw e;
		// Noble-only runtime — keep zero-length sentinel.
	}

	await idb.save(DEVICE_KEY_NAME, {
		publicKeyB64: publicB64u,
		wrappedPrivateKey,
	});

	cachedIdentity = null;
}

/**
 * Overwrite the profile_seed with the provided bytes.
 * Public API, narrow scope: use only on the identity-backup restore path.
 * Re-exported from `index.ts`. Do not call from product feature code.
 */
export async function setProfileSeed(seed: Uint8Array): Promise<void> {
	cachedProfileSeed = null;
	const buf = new ArrayBuffer(seed.byteLength);
	new Uint8Array(buf).set(seed);
	await idb.save(PROFILE_SEED_NAME, buf);
	cachedProfileSeed = new Uint8Array(buf);
}
