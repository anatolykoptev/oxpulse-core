/**
 * packages/mesh-core/src/channel.ts
 *
 * Derives a 32-bit channel ID from geohash + day_utc.
 * 4-char geohash precision (~20 km × 20 km cell) — coarser than BLE range
 * so density-per-cell stays high; cell boundary effect mitigated by
 * 3×3 neighboring subscription.
 *
 * Phase B mesh broadcast transport.
 * Spec: docs/superpowers/specs/2026-05-16-mesh-phase-b-public-broadcast-design.md
 *
 * Constants (GEOHASH_ALPHABET, GEOHASH_LENGTH, CHANNEL_ID_HASH_BYTE_COUNT)
 * are sourced from mesh-constants.json via the generated constants file.
 * Do NOT hardcode them here — edit mesh-constants.json and run
 * `node scripts/gen-mesh-constants.mjs`.
 */

import { blake3 } from '@noble/hashes/blake3.js';
import {
  GEOHASH_ALPHABET,
  GEOHASH_LENGTH,
  CHANNEL_ID_HASH_BYTE_COUNT,
} from './constants.generated.js';

/**
 * ~20 km offset between adjacent geohash cells at 4-char precision (~20×20 km).
 * Derived from: 1° latitude ≈ 111 km → 20 km / 111 km ≈ 0.18°.
 */
const GEOHASH_CELL_OFFSET_DEG = 0.18;

function encodeGeohash(lat: number, lon: number, precision: number): string {
  let latLo = -90;
  let latHi = 90;
  let lonLo = -180;
  let lonHi = 180;
  let geohash = '';
  let bits = 0;
  let bit = 0;
  let evenBit = true;
  while (geohash.length < precision) {
    if (evenBit) {
      const mid = (lonLo + lonHi) / 2;
      if (lon >= mid) {
        bits = (bits << 1) | 1;
        lonLo = mid;
      } else {
        bits = bits << 1;
        lonHi = mid;
      }
    } else {
      const mid = (latLo + latHi) / 2;
      if (lat >= mid) {
        bits = (bits << 1) | 1;
        latLo = mid;
      } else {
        bits = bits << 1;
        latHi = mid;
      }
    }
    evenBit = !evenBit;
    bit++;
    if (bit === 5) {
      geohash += GEOHASH_ALPHABET[bits]!;
      bits = 0;
      bit = 0;
    }
  }
  return geohash;
}

/**
 * Derives a channel ID hash from lat/lon and a UTC date.
 *
 * Wire format: BLAKE3(geohash || dayUtc) where || is raw string concatenation.
 * dayUtc is derived from date.toISOString().slice(0, 10) — caller MUST pass a
 * Date object; do not pre-format the date as a string.
 *
 * Spec: Phase B-1 — BLAKE3(geohash || day_utc), mathematical concatenation
 * (no separator byte). The absence of a separator is intentional and must
 * match any server-side derivation.
 */
export function channelIdHash(
  lat: number,
  lon: number,
  date: Date = new Date(),
): { hash: Uint8Array; hex: string; geohash: string; dayUtc: string } {
  if (!(date instanceof Date)) {
    throw new TypeError(
      `channelIdHash: 'date' must be a Date object, got ${typeof date}. ` +
        `Do not pre-format the date as a string.`,
    );
  }
  const geohash = encodeGeohash(lat, lon, GEOHASH_LENGTH);
  const dayUtc = date.toISOString().slice(0, 10);
  // Wire format: raw concat — no separator (B-1 spec: BLAKE3(geohash || day_utc))
  const input = new TextEncoder().encode(`${geohash}${dayUtc}`);
  const full = blake3(input);
  const hash = full.slice(0, CHANNEL_ID_HASH_BYTE_COUNT);
  const hex = Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('');
  return { hash, hex, geohash, dayUtc };
}

export function neighboringChannelIds(lat: number, lon: number, date?: Date): string[] {
  const ids = new Set<string>();
  for (let dLat = -1; dLat <= 1; dLat++) {
    for (let dLon = -1; dLon <= 1; dLon++) {
      const adjLat = lat + dLat * GEOHASH_CELL_OFFSET_DEG;
      const adjLon = lon + dLon * GEOHASH_CELL_OFFSET_DEG;
      ids.add(channelIdHash(adjLat, adjLon, date).hex);
    }
  }
  return Array.from(ids);
}

export type ChannelIdResult =
  | { channelId: string; reason: 'granted' }
  | { channelId: null; reason: 'denied' | 'timeout' | 'unavailable' };

/**
 * Wrapper around navigator.geolocation.
 * Distinguishes between denied permission, timeout, and unavailability so
 * the UI can offer an appropriate fallback (e.g. retry on timeout, show
 * region-picker on denied).
 */
export async function currentChannelId(date?: Date): Promise<ChannelIdResult> {
  if (typeof navigator === 'undefined' || !navigator.geolocation) {
    return { channelId: null, reason: 'unavailable' };
  }

  return new Promise((resolve) => {
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        const hex = channelIdHash(pos.coords.latitude, pos.coords.longitude, date).hex;
        resolve({ channelId: hex, reason: 'granted' });
      },
      async (err) => {
        // GeolocationPositionError.PERMISSION_DENIED = 1, TIMEOUT = 3
        // Use optional chaining on navigator.permissions — it may be undefined
        // in older browsers, embedded webviews, or test environments. Without
        // optional chaining, accessing .query on undefined throws synchronously
        // inside the async callback, which leaves resolve() uncalled → hang.
        const isDenied =
          err.code === 1 ||
          (await navigator.permissions
            ?.query({ name: 'geolocation' })
            .then((s) => s.state === 'denied')
            .catch(() => false) ?? false);
        resolve({ channelId: null, reason: isDenied ? 'denied' : 'timeout' });
      },
      { timeout: 5000, maximumAge: 3_600_000 }, // accept up to 1h-old fix
    );
  });
}

// ─── B-7: Manual region fallback ─────────────────────────────────────────────

/**
 * Display names for known region keys.
 * Keys are lowercase ASCII (e.g. 'moscow'); values are the localised display name.
 */
const REGION_DISPLAY_NAMES: Record<string, string> = {
  moscow: 'Москва',
  spb: 'Санкт-Петербург',
  novosibirsk: 'Новосибирск',
  yekaterinburg: 'Екатеринбург',
  kazan: 'Казань',
  chelyabinsk: 'Челябинск',
  omsk: 'Омск',
  samara: 'Самара',
  rostov: 'Ростов-на-Дону',
  ufa: 'Уфа',
  krasnoyarsk: 'Красноярск',
  perm: 'Пермь',
  voronezh: 'Воронеж',
  volgograd: 'Волгоград',
  krasnodar: 'Краснодар',
  saratov: 'Саратов',
  tyumen: 'Тюмень',
  tolyatti: 'Тольятти',
  izhevsk: 'Ижевск',
  barnaul: 'Барнаул',
  // International — protest-relevant
  tehran: 'Тегеран',
  minsk: 'Минск',
  kyiv: 'Київ',
  tbilisi: 'Тбилиси',
  yerevan: 'Ереван',
  almaty: 'Алматы',
  tashkent: 'Ташкент',
  baku: 'Баку',
  bishkek: 'Бишкек',
  dushanbe: 'Душанбе',
  // EU
  berlin: 'Берлин',
  paris: 'Париж',
  london: 'Лондон',
  warsaw: 'Варшава',
  prague: 'Прага',
  riga: 'Рига',
  tallinn: 'Таллин',
  vilnius: 'Вильнюс',
  helsinki: 'Хельсинки',
  vienna: 'Вена',
};

/**
 * Known city centroids for manual region selection when GPS is denied.
 * Top cities relevant to OxPulse use cases (RU/EU/protest-relevant).
 * Extensible — add new entries without changing API.
 */
const REGION_FALLBACKS: Record<string, { lat: number; lon: number }> = {
  moscow: { lat: 55.7558, lon: 37.6173 },
  spb: { lat: 59.9343, lon: 30.3351 },
  novosibirsk: { lat: 55.0084, lon: 82.9357 },
  yekaterinburg: { lat: 56.8389, lon: 60.6057 },
  kazan: { lat: 55.7963, lon: 49.1088 },
  chelyabinsk: { lat: 55.1644, lon: 61.4368 },
  omsk: { lat: 54.9885, lon: 73.3242 },
  samara: { lat: 53.2001, lon: 50.15 },
  rostov: { lat: 47.2357, lon: 39.7015 },
  ufa: { lat: 54.7388, lon: 55.9721 },
  krasnoyarsk: { lat: 56.0153, lon: 92.8932 },
  perm: { lat: 58.0105, lon: 56.2502 },
  voronezh: { lat: 51.6717, lon: 39.2106 },
  volgograd: { lat: 48.7194, lon: 44.5018 },
  krasnodar: { lat: 45.0355, lon: 38.9753 },
  saratov: { lat: 51.5924, lon: 46.0342 },
  tyumen: { lat: 57.1553, lon: 65.5619 },
  tolyatti: { lat: 53.5303, lon: 49.3461 },
  izhevsk: { lat: 56.8526, lon: 53.2048 },
  barnaul: { lat: 53.3606, lon: 83.7636 },
  // International — protest-relevant
  tehran: { lat: 35.6892, lon: 51.389 },
  minsk: { lat: 53.9006, lon: 27.559 },
  kyiv: { lat: 50.4501, lon: 30.5234 },
  tbilisi: { lat: 41.6938, lon: 44.8015 },
  yerevan: { lat: 40.1872, lon: 44.5152 },
  almaty: { lat: 43.2551, lon: 76.9126 },
  tashkent: { lat: 41.2995, lon: 69.2401 },
  baku: { lat: 40.4093, lon: 49.8671 },
  bishkek: { lat: 42.8746, lon: 74.5698 },
  dushanbe: { lat: 38.5598, lon: 68.7735 },
  // EU
  berlin: { lat: 52.52, lon: 13.405 },
  paris: { lat: 48.8566, lon: 2.3522 },
  london: { lat: 51.5074, lon: -0.1278 },
  warsaw: { lat: 52.2297, lon: 21.0122 },
  prague: { lat: 50.0755, lon: 14.4378 },
  riga: { lat: 56.9496, lon: 24.1052 },
  tallinn: { lat: 59.437, lon: 24.7536 },
  vilnius: { lat: 54.6872, lon: 25.2797 },
  helsinki: { lat: 60.1699, lon: 24.9384 },
  vienna: { lat: 48.2082, lon: 16.3738 },
};

/**
 * Returns centroid for a known region key, or null if not found.
 * Region keys are lowercase ASCII (e.g. 'moscow', 'berlin').
 */
export function getRegionFallback(regionKey: string): { lat: number; lon: number } | null {
  return REGION_FALLBACKS[regionKey] ?? null;
}

/**
 * Returns the display name for a region key, or the key itself if not mapped.
 */
export function getRegionDisplayName(regionKey: string): string {
  return REGION_DISPLAY_NAMES[regionKey] ?? regionKey;
}

/**
 * Returns sorted list of all known region keys.
 * Used by RegionPicker.svelte to populate the dropdown.
 */
export function availableRegions(): string[] {
  return Object.keys(REGION_FALLBACKS).sort();
}
