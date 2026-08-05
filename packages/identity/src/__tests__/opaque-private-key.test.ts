import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';
import { OpaquePrivateKey } from '../opaque-private-key';

describe('OpaquePrivateKey', () => {
  const seed = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  ]);

  it('bytes() returns equal-but-not-same-reference', () => {
    const op = new OpaquePrivateKey(seed);
    const a = op.bytes();
    const b = op.bytes();
    expect(a).not.toBe(b);
    expect(a).toEqual(b);
  });

  it('mutation of a returned copy does not affect the held bytes', () => {
    const op = new OpaquePrivateKey(seed);
    const a = op.bytes();
    a[0] = 99;
    expect(op.bytes()[0]).toBe(seed[0]);
  });

  it('constructor defensive-copies its input', () => {
    const input = new Uint8Array(seed);
    const op = new OpaquePrivateKey(input);
    input[0] = 99;
    expect(op.bytes()[0]).toBe(seed[0]);
  });

  it('toJSON() throws', () => {
    const op = new OpaquePrivateKey(seed);
    expect(() => op.toJSON()).toThrow();
  });

  it('toString() returns the redaction marker', () => {
    const op = new OpaquePrivateKey(seed);
    expect(op.toString()).toBe('[OpaquePrivateKey REDACTED]');
  });

  it('util.inspect does not leak the seed and contains REDACTED', () => {
    const op = new OpaquePrivateKey(seed);
    const out = inspect(op);
    expect(out).toContain('REDACTED');
    // No hex of any seed byte should appear.
    for (const b of seed) {
      expect(out).not.toContain(b.toString(16).padStart(2, '0'));
    }
  });

  it('JSON.stringify(op) throws', () => {
    const op = new OpaquePrivateKey(seed);
    expect(() => JSON.stringify(op)).toThrow();
  });

  it('JSON.stringify({ key: op }) throws', () => {
    const op = new OpaquePrivateKey(seed);
    expect(() => JSON.stringify({ key: op })).toThrow();
  });
});
