import { describe, it, expect } from 'vitest';
import { Session, ReplayWindow } from '../../crypto/session.js';

function pairKeys(): { a: Uint8Array; b: Uint8Array } {
  const k1 = crypto.getRandomValues(new Uint8Array(16));
  const k2 = crypto.getRandomValues(new Uint8Array(16));
  return { a: k1, b: k2 };
}

describe('Session AEAD round-trip', () => {
  it('encrypt then decrypt returns original plaintext', async () => {
    const { a, b } = pairKeys();
    const alice = new Session({ sendKey: a, recvKey: b, direction: 'initiator' });
    const bob = new Session({ sendKey: b, recvKey: a, direction: 'responder' });
    const msg = new TextEncoder().encode('hello mesh');
    const ct = await alice.encrypt(msg);
    const pt = await bob.decrypt(ct);
    expect(new TextDecoder().decode(pt)).toBe('hello mesh');
  });

  it('rejects tampered ciphertext', async () => {
    const { a, b } = pairKeys();
    const alice = new Session({ sendKey: a, recvKey: b, direction: 'initiator' });
    const bob = new Session({ sendKey: b, recvKey: a, direction: 'responder' });
    const ct = await alice.encrypt(new Uint8Array([1, 2, 3]));
    ct[ct.length - 1] ^= 0xff;
    await expect(bob.decrypt(ct)).rejects.toThrow();
  });

  it('rejects replay of the same counter', async () => {
    const { a, b } = pairKeys();
    const alice = new Session({ sendKey: a, recvKey: b, direction: 'initiator' });
    const bob = new Session({ sendKey: b, recvKey: a, direction: 'responder' });
    const ct = await alice.encrypt(new Uint8Array([1]));
    await bob.decrypt(ct);
    await expect(bob.decrypt(ct)).rejects.toThrow(/replay/i);
  });
});

describe('ReplayWindow', () => {
  it('accepts strictly increasing counters', () => {
    const w = new ReplayWindow();
    expect(w.checkAndAccept(0n)).toBe(true);
    expect(w.checkAndAccept(1n)).toBe(true);
    expect(w.checkAndAccept(2n)).toBe(true);
  });
  it('rejects duplicates', () => {
    const w = new ReplayWindow();
    expect(w.checkAndAccept(5n)).toBe(true);
    expect(w.checkAndAccept(5n)).toBe(false);
  });
  it('accepts in-window reordering', () => {
    const w = new ReplayWindow();
    expect(w.checkAndAccept(10n)).toBe(true);
    expect(w.checkAndAccept(8n)).toBe(true);
    expect(w.checkAndAccept(9n)).toBe(true);
    expect(w.checkAndAccept(8n)).toBe(false); // duplicate within window
  });
  it('rejects out-of-window (too old)', () => {
    const w = new ReplayWindow();
    expect(w.checkAndAccept(100n)).toBe(true);
    expect(w.checkAndAccept(0n)).toBe(false); // > 64 behind
  });
});
