/**
 * noise-errors.test.ts — typed Noise error classes (B.2-typed-noise-errors).
 *
 * RED phase: these tests fail until NoiseStateError / NoiseReplayError are
 * exported from noise-xx.ts and thrown from the relevant code paths.
 */

import { describe, it, expect } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { NoiseXxHandshake, NoiseStateError, NoiseReplayError } from '../../crypto/noise-xx.js';

// B.2-noise-s-key-derivation: include X25519 static keypair in test identity.
function mkIdentity() {
  const edSk = ed25519.utils.randomSecretKey();
  const edPk = ed25519.getPublicKey(edSk);
  const xSk = ed25519.utils.toMontgomerySecret(edSk);
  const xPk = x25519.getPublicKey(xSk);
  return {
    async getPublicKey() { return edPk; },
    async sign(msg: Uint8Array) { return ed25519.sign(msg, edSk); },
    async getX25519PublicKey() { return xPk; },
    async dhX25519(remotePub: Uint8Array) { return x25519.getSharedSecret(xSk, remotePub); },
  };
}

describe('NoiseStateError / NoiseReplayError typed errors', () => {
  it('NoiseStateError is exported from noise-xx', () => {
    expect(NoiseStateError).toBeDefined();
    const err = new NoiseStateError('test');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(NoiseStateError);
    expect(err.name).toBe('NoiseStateError');
  });

  it('NoiseReplayError is a subclass of NoiseStateError', () => {
    expect(NoiseReplayError).toBeDefined();
    const err = new NoiseReplayError('test');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(NoiseStateError);
    expect(err).toBeInstanceOf(NoiseReplayError);
    expect(err.name).toBe('NoiseReplayError');
  });

  it('readMessage in wrong state throws NoiseStateError (not plain Error)', async () => {
    // Initiator can only read msg-2 (after sending msg-1). Trying to read before that is invalid.
    // Strategy: complete a full handshake on initiator side up through msg-2, then try to call
    // readMessage again when msgIdx is already past that — that must throw NoiseStateError.
    const alice = new NoiseXxHandshake({ role: 'initiator', identity: mkIdentity() });
    const bob = new NoiseXxHandshake({ role: 'responder', identity: mkIdentity() });

    const m1 = await alice.writeMessage(new Uint8Array(0));
    await bob.readMessage(m1);
    const m2 = await bob.writeMessage(new Uint8Array(0));
    await alice.readMessage(m2);           // msgIdx → 2 (alice expects to write msg-3 now)
    // Now alice's readMessage is invalid — she should be writing, not reading.
    let thrown: unknown;
    try {
      await alice.readMessage(m2);         // invalid state: msgIdx=2, role=initiator
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(NoiseStateError);
  });

  it('writeMessage in wrong state throws NoiseStateError', async () => {
    // Initiator trying to write msg-1 twice (msgIdx already = 1 after first write).
    const initiator = new NoiseXxHandshake({ role: 'initiator', identity: mkIdentity() });
    await initiator.writeMessage(new Uint8Array(0)); // advances msgIdx to 1
    // Now writeMessage is invalid (initiator writes msg-3 at msgIdx=2, not msg-1 at msgIdx=1).
    let thrown: unknown;
    try {
      await initiator.writeMessage(new Uint8Array(0));
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(NoiseStateError);
  });

  it('replayed msg-1 throws NoiseStateError (responder sees same e twice)', async () => {
    const a = new NoiseXxHandshake({ role: 'initiator', identity: mkIdentity() });
    const b = new NoiseXxHandshake({ role: 'responder', identity: mkIdentity() });
    const m1 = await a.writeMessage(new Uint8Array(0));
    await b.readMessage(m1); // valid first read
    // Second read of the same msg — must throw NoiseStateError (out-of-state replay).
    await expect(b.readMessage(m1)).rejects.toBeInstanceOf(NoiseStateError);
  });
});
