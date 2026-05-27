import { describe, it, expect } from 'vitest';
import type { MeshErrorKind } from '../../transport.js';
import { CryptoErrorKind, isCryptoError } from '../../crypto/errors.js';

describe('CryptoErrorKind', () => {
  it('all values are assignable to MeshErrorKind', () => {
    const cases: CryptoErrorKind[] = [
      'handshake-failed', 'replay-rejected', 'sas-mismatch', 'unknown-peer-key',
    ];
    cases.forEach((c) => {
      const m: MeshErrorKind = c;
      expect(m).toBeTruthy();
    });
  });

  it('isCryptoError returns true for all CryptoErrorKind values', () => {
    expect(isCryptoError('handshake-failed')).toBe(true);
    expect(isCryptoError('replay-rejected')).toBe(true);
    expect(isCryptoError('sas-mismatch')).toBe(true);
    expect(isCryptoError('unknown-peer-key')).toBe(true);
  });

  it('isCryptoError returns false for non-crypto kinds', () => {
    expect(isCryptoError('ble-off')).toBe(false);
    expect(isCryptoError('unknown')).toBe(false);
    expect(isCryptoError(null)).toBe(false);
    expect(isCryptoError('garbage')).toBe(false);
  });
});
