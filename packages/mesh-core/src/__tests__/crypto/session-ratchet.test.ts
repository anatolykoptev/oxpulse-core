/**
 * Tests for per-frame AEAD key ratcheting (B.2-sframe-per-frame).
 *
 * Forward secrecy at frame granularity: compromise of the key used at
 * frame N does NOT reveal frames 0..N-1. Each frame derives a fresh
 * AEAD key from the previous frame's key via HKDF, then the old key
 * material is discarded.
 *
 * Wire-compat note: this is intentionally incompatible with the B.2
 * static-key Session class. Session and RatchetSession are separate.
 */

import { describe, it, expect } from 'vitest';
import { RatchetSession } from '../../crypto/session-ratchet.js';

function randomKey(len = 32): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(len));
}

// ---------------------------------------------------------------------------
// Basic round-trip
// ---------------------------------------------------------------------------

describe('RatchetSession — basic round-trip', () => {
  it('encrypts and decrypts a single frame', async () => {
    const initKey = randomKey();
    const alice = new RatchetSession({ sendChainKey: initKey, recvChainKey: initKey, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: initKey, recvChainKey: initKey, direction: 'responder' });

    const plaintext = new TextEncoder().encode('hello ratchet');
    const ct = await alice.encrypt(plaintext);
    const pt = await bob.decrypt(ct);
    expect(new TextDecoder().decode(pt)).toBe('hello ratchet');
  });

  it('encrypts and decrypts multiple frames in sequence', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const messages = ['frame-0', 'frame-1', 'frame-2', 'frame-3', 'frame-4'];
    for (const msg of messages) {
      const ct = await alice.encrypt(new TextEncoder().encode(msg));
      const pt = await bob.decrypt(ct);
      expect(new TextDecoder().decode(pt)).toBe(msg);
    }
  });

  it('uses direction-split send/recv chains (Alice→Bob independent of Bob→Alice)', async () => {
    const aCk = randomKey();
    const bCk = randomKey();
    // Alice sends with aCk, Bob sends with bCk
    const alice = new RatchetSession({ sendChainKey: aCk, recvChainKey: bCk, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: bCk, recvChainKey: aCk, direction: 'responder' });

    // Both directions work independently.
    const ct1 = await alice.encrypt(new TextEncoder().encode('alice→bob'));
    const ct2 = await bob.encrypt(new TextEncoder().encode('bob→alice'));
    const pt1 = await bob.decrypt(ct1);
    const pt2 = await alice.decrypt(ct2);
    expect(new TextDecoder().decode(pt1)).toBe('alice→bob');
    expect(new TextDecoder().decode(pt2)).toBe('bob→alice');
  });
});

// ---------------------------------------------------------------------------
// Key ratcheting — per-frame forward secrecy
// ---------------------------------------------------------------------------

describe('RatchetSession — forward secrecy after key extraction', () => {
  it('each frame is encrypted with a different key (encrypt key ID advances)', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });

    const ct0 = await alice.encrypt(new TextEncoder().encode('f0'));
    const ct1 = await alice.encrypt(new TextEncoder().encode('f1'));
    const ct2 = await alice.encrypt(new TextEncoder().encode('f2'));

    // The counter embedded in each frame must be distinct.
    const ctr0 = new DataView(ct0.buffer, ct0.byteOffset).getBigUint64(0, false);
    const ctr1 = new DataView(ct1.buffer, ct1.byteOffset).getBigUint64(0, false);
    const ctr2 = new DataView(ct2.buffer, ct2.byteOffset).getBigUint64(0, false);
    expect(ctr0).toBe(0n);
    expect(ctr1).toBe(1n);
    expect(ctr2).toBe(2n);
  });

  it('forward secrecy at window boundary — keys pruned after RECV_WINDOW_SIZE frames', async () => {
    // With window-based eviction (Option B), key material is retained for
    // the replay-window range (64 frames). Forward secrecy kicks in once
    // the highest decrypted counter advances more than 64 frames beyond a
    // given counter — at that point the key is gone from the cache.
    //
    // This test verifies that compromise at frame N+65 cannot decrypt
    // frames 0..N (they are outside the 64-counter window).
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });

    // Alice sends 70 frames.
    const frames: Uint8Array[] = [];
    for (let i = 0; i < 70; i++) {
      frames.push(await alice.encrypt(new TextEncoder().encode(`secret-${i}`)));
    }

    // Bob processes all 70 frames in order.
    const bob = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });
    for (let i = 0; i < 70; i++) {
      await bob.decrypt(frames[i]);
    }

    // Attacker steals Bob's chain at lowestCounter (now advanced past the window).
    const stolenChainKey = bob.snapshotRecvChain();
    const stolenCounter = bob.recvCounter; // = lowestCounter = 69 - 64 + 1 = 6

    // Compromised session can decrypt frames at or after lowestCounter.
    const compromised = RatchetSession.fromCompromisedState({
      recvChainKey: stolenChainKey,
      nextCounter: stolenCounter,
      direction: 'responder',
    });

    // Frames before lowestCounter are outside the window — keys are gone.
    // Counter 0 is well below stolenCounter (6): "key no longer available".
    await expect(compromised.decrypt(frames[0])).rejects.toThrow(/no longer available|replay/i);
  });
});

// ---------------------------------------------------------------------------
// Replay protection (still required alongside ratcheting)
// ---------------------------------------------------------------------------

describe('RatchetSession — replay protection', () => {
  it('rejects replay of a frame with the same counter', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const ct = await alice.encrypt(new TextEncoder().encode('frame'));
    await bob.decrypt(ct);
    await expect(bob.decrypt(ct)).rejects.toThrow(/replay/i);
  });

  it('rejects tampered ciphertext', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const ct = await alice.encrypt(new Uint8Array([1, 2, 3]));
    ct[ct.length - 1] ^= 0xff;
    await expect(bob.decrypt(ct)).rejects.toThrow();
  });

  it('rejects frames with a counter far behind the receiver window', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    // Save an old frame before bob's window advances.
    const oldFrame = await alice.encrypt(new TextEncoder().encode('old'));

    // Alice sends 70 more frames — pushes oldFrame outside the 64-entry window.
    for (let i = 0; i < 70; i++) {
      const ct = await alice.encrypt(new Uint8Array([i]));
      await bob.decrypt(ct);
    }

    // oldFrame (counter 0) is now outside the replay window.
    await expect(bob.decrypt(oldFrame)).rejects.toThrow(/replay/i);
  });
});

// ---------------------------------------------------------------------------
// Reorder tolerance (Fix 2.1 — Option B: window-based eviction)
// [report: PR #1068 code-quality review, Fix 2.1]
// ---------------------------------------------------------------------------

describe('RatchetSession — reorder tolerance within replay window', () => {
  it('decrypts frame N-1 after frame N within the replay window (BLE reorder scenario)', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const ct0 = await alice.encrypt(new TextEncoder().encode('frame-0'));
    const ct1 = await alice.encrypt(new TextEncoder().encode('frame-1'));

    // Bob receives frame 1 first (reorder), then frame 0.
    const pt1 = await bob.decrypt(ct1);
    expect(new TextDecoder().decode(pt1)).toBe('frame-1');

    // frame-0 key must still be available — it's within the replay window.
    const pt0 = await bob.decrypt(ct0);
    expect(new TextDecoder().decode(pt0)).toBe('frame-0');
  });

  it('decrypts frames arriving in arbitrary order within window size', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    // Encrypt 5 frames.
    const cts: Uint8Array[] = [];
    for (let i = 0; i < 5; i++) {
      cts.push(await alice.encrypt(new TextEncoder().encode(`f${i}`)));
    }

    // Deliver in reversed order — all within window.
    for (let i = 4; i >= 0; i--) {
      const pt = await bob.decrypt(cts[i]);
      expect(new TextDecoder().decode(pt)).toBe(`f${i}`);
    }
  });

  it('drops key for counter well outside replay window after higher frames arrive', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const oldFrame = await alice.encrypt(new TextEncoder().encode('very-old'));

    // Advance receiver by more than REPLAY_WINDOW_SIZE (64) frames.
    for (let i = 0; i < 70; i++) {
      const ct = await alice.encrypt(new Uint8Array([i]));
      await bob.decrypt(ct);
    }

    // oldFrame key should be gone (forward secrecy beyond window).
    await expect(bob.decrypt(oldFrame)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// fromCompromisedState — low-counter rejection via key cache (Fix 2.3-A)
// [report: PR #1068 code-quality review, Fix 2.3]
// ---------------------------------------------------------------------------

describe('RatchetSession — fromCompromisedState validation parity (R3.4)', () => {
  /**
   * fromCompromisedState uses Object.create(RatchetSession.prototype) which
   * bypasses the constructor. Validation must be explicitly duplicated so
   * callers see the same error behaviour as the constructor.
   */
  it('throws on short recvChainKey — same guard as constructor', () => {
    expect(() =>
      RatchetSession.fromCompromisedState({
        recvChainKey: new Uint8Array(16), // too short — must be 32
        nextCounter: 0n,
        direction: 'initiator',
      }),
    ).toThrow(/recvChainKey must be 32 bytes, got 16/);
  });
});

describe('RatchetSession — fromCompromisedState low-counter rejection', () => {
  it('rejects counters below lowestCounter via key cache (no key available)', async () => {
    // With window-based eviction, lowestCounter only advances once the
    // receiver has processed more than RECV_WINDOW_SIZE (64) frames.
    // We process 70 frames so the window has evicted the early counters.
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const frames: Uint8Array[] = [];
    for (let i = 0; i < 70; i++) {
      frames.push(await alice.encrypt(new TextEncoder().encode(`s${i}`)));
    }
    for (let i = 0; i < 70; i++) {
      await bob.decrypt(frames[i]);
    }

    const stolenChain = bob.snapshotRecvChain();
    const stolenCounter = bob.recvCounter; // lowestCounter = 69 - 64 + 1 = 6

    const compromised = RatchetSession.fromCompromisedState({
      recvChainKey: stolenChain,
      nextCounter: stolenCounter,
      direction: 'responder',
    });

    // Frames below stolenCounter: key cache starts at stolenCounter, returns null.
    await expect(compromised.decrypt(frames[0])).rejects.toThrow(/no longer available|replay/i);
    await expect(compromised.decrypt(frames[3])).rejects.toThrow(/no longer available|replay/i);
  });
});

// ---------------------------------------------------------------------------
// Additional data (AAD)
// ---------------------------------------------------------------------------

describe('RatchetSession — additional data', () => {
  it('accepts correct AAD', async () => {
    const ck = randomKey();
    const ad = new TextEncoder().encode('peer-id:alice');
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const ct = await alice.encrypt(new TextEncoder().encode('msg'), ad);
    const pt = await bob.decrypt(ct, ad);
    expect(new TextDecoder().decode(pt)).toBe('msg');
  });

  it('rejects mismatched AAD', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    const ct = await alice.encrypt(new TextEncoder().encode('msg'), new TextEncoder().encode('real-ad'));
    await expect(bob.decrypt(ct, new TextEncoder().encode('wrong-ad'))).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------

describe('RatchetSession — replay-after-AEAD DoS gadget (R3.3)', () => {
  /**
   * Regression: replay state must NOT be mutated before AEAD succeeds.
   *
   * Attack scenario: adversary spoofs a frame at counter N with a bad AEAD
   * tag. If checkAndAccept runs before decryption, counter N is marked seen.
   * The legitimate sender's frame at counter N is then rejected as a replay —
   * permanent DoS for that counter without a session reset.
   *
   * Fix: canAccept (read-only) runs before AEAD; commit (mutation) runs only
   * on AEAD success. A bad-tag frame must NOT poison replay state.
   */
  it('spoofed frame with bad AEAD tag does not poison replay state', async () => {
    const ck = randomKey();
    const alice = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'initiator' });
    const bob   = new RatchetSession({ sendChainKey: ck, recvChainKey: ck, direction: 'responder' });

    // alice encrypts a legitimate frame at counter 0
    const legitimateCt = await alice.encrypt(new TextEncoder().encode('real'));

    // Attacker clones the counter bytes but corrupts the AEAD tag
    const spoofed = new Uint8Array(legitimateCt);
    spoofed[spoofed.length - 1] ^= 0xff; // flip last byte of tag

    // bob receives the spoofed frame — must throw on AEAD failure
    await expect(bob.decrypt(spoofed)).rejects.toThrow();

    // Legitimate frame at the same counter must still be accepted (replay NOT poisoned)
    const pt = await bob.decrypt(legitimateCt);
    expect(new TextDecoder().decode(pt)).toBe('real');
  });
});
