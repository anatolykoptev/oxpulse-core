/**
 * sas.ts — 5-digit Short Authentication String.
 *
 * Defense against active MITM during the initial Noise XX handshake.
 * After handshake completion both peers compute the same SAS over the
 * final Noise handshake hash; users verbally compare. Forge probability
 * per honest handshake = 1/100_000 (16.6 bits entropy).
 *
 * Trade-off vs Briar (6 digits / 20 bits): we drop one digit for a
 * shorter spoken sentence (5 RU syllables ≈ 1.5 sec). Acceptable for
 * mesh's audience (panic-context, brief encounters).
 */

import { SAS_DIGIT_COUNT } from '../constants.generated.js';

const MODULUS = 10n ** BigInt(SAS_DIGIT_COUNT); // 100_000

export function computeSas(handshakeHash: Uint8Array): string {
  if (handshakeHash.length !== 32) {
    throw new Error(`sas: expected 32-byte hash, got ${handshakeHash.length}`);
  }
  // Take first 8 bytes as big-endian u64, reduce mod 10^N.
  let n = 0n;
  for (let i = 0; i < 8; i++) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    n = (n << 8n) | BigInt(handshakeHash[i]!);
  }
  const truncated = n % MODULUS;
  return truncated.toString(10).padStart(SAS_DIGIT_COUNT, '0');
}
