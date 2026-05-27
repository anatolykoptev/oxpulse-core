import { describe, it, expect } from 'vitest';
import { computeSas } from '../../crypto/sas.js';
import { SAS_DIGIT_COUNT } from '../../constants.generated.js';

describe('SAS (short authentication string)', () => {
  it('returns 5-digit zero-padded ASCII string', () => {
    const hash = new Uint8Array(32).fill(0xff);
    const sas = computeSas(hash);
    expect(sas).toMatch(/^[0-9]{5}$/);
    expect(sas.length).toBe(SAS_DIGIT_COUNT);
  });

  it('zero hash → all zeros', () => {
    const sas = computeSas(new Uint8Array(32));
    expect(sas).toBe('00000');
  });

  it('different hashes yield different SAS (high probability)', () => {
    const h1 = new Uint8Array(32); h1[0] = 1;
    const h2 = new Uint8Array(32); h2[0] = 2;
    expect(computeSas(h1)).not.toBe(computeSas(h2));
  });

  it('deterministic: same input → same output', () => {
    const h = new Uint8Array(32).fill(0x42);
    expect(computeSas(h)).toBe(computeSas(h));
  });

  it('rejects non-32-byte hash', () => {
    expect(() => computeSas(new Uint8Array(31))).toThrow();
    expect(() => computeSas(new Uint8Array(33))).toThrow();
  });
});
