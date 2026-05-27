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
 */

import { createIdbStore } from './idb-store.js';

// LOAD-BEARING: dedicated IDB database — separate from oxpulse-device-id
// so the room-host root secret is isolated from the device identity store.
// Never rename after first user.
const DB_NAME = 'oxpulse-room-host-seed';
const STORE_NAME = 'seed';
const KEY = 'room_host_seed_v1';     // LOAD-BEARING — DO NOT RENAME
const WRAPPING_KEY = 'wrapping_key'; // wrapping key for this store only

const idb = createIdbStore({ dbName: DB_NAME, storeName: STORE_NAME });

let cachedSeed: Uint8Array | null = null;
let cachedWrappingKey: CryptoKey | null = null;

/**
 * Get or create the AES-KW wrapping key for this store.
 * Mirrors the device-identity getOrCreateWrappingKey pattern.
 */
async function getWrappingKey(): Promise<CryptoKey> {
    if (cachedWrappingKey) return cachedWrappingKey;

    const existing = await idb.load<ArrayBuffer>(WRAPPING_KEY);
    if (existing) {
        cachedWrappingKey = await crypto.subtle.importKey(
            'raw',
            existing,
            { name: 'AES-KW', length: 256 },
            false,
            ['wrapKey', 'unwrapKey'],
        );
        return cachedWrappingKey;
    }

    // Bootstrap: generate extractable, persist raw bytes, re-import as
    // non-extractable — same window-of-one-tick pattern as device-identity.
    const wk = await crypto.subtle.generateKey(
        { name: 'AES-KW', length: 256 },
        true,
        ['wrapKey', 'unwrapKey'],
    );
    const raw = await crypto.subtle.exportKey('raw', wk);
    await idb.save(WRAPPING_KEY, raw);
    cachedWrappingKey = await crypto.subtle.importKey(
        'raw',
        raw,
        { name: 'AES-KW', length: 256 },
        false,
        ['wrapKey', 'unwrapKey'],
    );
    return cachedWrappingKey;
}

/** Get the room-host seed, generating + persisting it on first use. */
export async function getOrCreateRoomHostSeed(): Promise<Uint8Array> {
    if (cachedSeed) return cachedSeed;

    const wrappingKey = await getWrappingKey();

    const existing = await idb.load<ArrayBuffer>(KEY);
    if (existing) {
        // Unwrap: the seed was stored as an AES-256 key (same 32-byte length)
        // so wrapKey could encode it — mirrors the device-identity raw-seed
        // persistence pattern in persistIdentity().
        const seedKey = await crypto.subtle.unwrapKey(
            'raw',
            existing,
            wrappingKey,
            'AES-KW',
            { name: 'AES-KW', length: 256 },
            true,
            ['wrapKey', 'unwrapKey'],
        );
        const raw = await crypto.subtle.exportKey('raw', seedKey);
        cachedSeed = new Uint8Array(raw);
        return cachedSeed;
    }

    // First use: generate 32 CSPRNG bytes.
    const seed = crypto.getRandomValues(new Uint8Array(32));

    // Wrap: import seed bytes as AES-256 (same byte-length, opaque to AES-KW),
    // wrapKey to produce ciphertext, persist. Pattern from persistIdentity().
    const seedKey = await crypto.subtle.importKey(
        'raw',
        seed,
        { name: 'AES-KW', length: 256 },
        true, // must be extractable so wrapKey can encode it
        ['wrapKey', 'unwrapKey'],
    );
    const wrapped = await crypto.subtle.wrapKey('raw', seedKey, wrappingKey, 'AES-KW');
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
