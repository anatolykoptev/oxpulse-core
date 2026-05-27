import { describe, it, expect } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { NoiseXxHandshake } from '../../crypto/noise-xx.js';

// B.2-noise-s-key-derivation: include X25519 static keypair in test identity
// so the handshake can perform real es/se DH (not the old ephemeral-only path).
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

describe('Noise XX + ML-KEM-768 hybrid handshake', () => {
  it('completes in 3 messages, both sides derive same session key + same SAS', async () => {
    const aliceIdentity = mkIdentity();
    const bobIdentity = mkIdentity();

    const alice = new NoiseXxHandshake({ role: 'initiator', identity: aliceIdentity });
    const bob = new NoiseXxHandshake({ role: 'responder', identity: bobIdentity });

    // → msg-1
    const m1 = await alice.writeMessage(new Uint8Array(0));
    const p1 = await bob.readMessage(m1);
    expect(p1.length).toBe(0);

    // ← msg-2
    const m2 = await bob.writeMessage(new Uint8Array(0));
    const p2 = await alice.readMessage(m2);
    expect(p2.length).toBe(0);

    // → msg-3
    const m3 = await alice.writeMessage(new Uint8Array(0));
    const p3 = await bob.readMessage(m3);
    expect(p3.length).toBe(0);

    expect(alice.isComplete()).toBe(true);
    expect(bob.isComplete()).toBe(true);

    const aSplit = alice.split();
    const bSplit = bob.split();

    expect(aSplit.sendKey).toEqual(bSplit.recvKey);
    expect(aSplit.recvKey).toEqual(bSplit.sendKey);
    expect(alice.sas()).toBe(bob.sas());
    expect(alice.sas()).toMatch(/^[0-9]{5}$/);
  });

  it('rejects replay of msg-1 (responder sees same e twice)', async () => {
    const a = new NoiseXxHandshake({ role: 'initiator', identity: mkIdentity() });
    const b = new NoiseXxHandshake({ role: 'responder', identity: mkIdentity() });
    const m1 = await a.writeMessage(new Uint8Array(0));
    await b.readMessage(m1);
    await expect(b.readMessage(m1)).rejects.toThrow(/state|replay|order/i);
  });

  it('detects active MITM: substituted msg-1 → different SAS at both peers', async () => {
    const a = new NoiseXxHandshake({ role: 'initiator', identity: mkIdentity() });
    const b = new NoiseXxHandshake({ role: 'responder', identity: mkIdentity() });
    const m = new NoiseXxHandshake({ role: 'initiator', identity: mkIdentity() }); // attacker
    const mResp = new NoiseXxHandshake({ role: 'responder', identity: mkIdentity() });

    const m1Alice = await a.writeMessage(new Uint8Array(0));
    await mResp.readMessage(m1Alice);
    const m1AttackerToBob = await m.writeMessage(new Uint8Array(0));
    await b.readMessage(m1AttackerToBob);

    const m2BobToAttacker = await b.writeMessage(new Uint8Array(0));
    await m.readMessage(m2BobToAttacker);
    const m2AttackerToAlice = await mResp.writeMessage(new Uint8Array(0));
    await a.readMessage(m2AttackerToAlice);

    const m3Alice = await a.writeMessage(new Uint8Array(0));
    await mResp.readMessage(m3Alice);
    const m3AttackerToBob = await m.writeMessage(new Uint8Array(0));
    await b.readMessage(m3AttackerToBob);

    // SAS at alice and bob will diverge — that's the MITM signal.
    expect(a.sas()).not.toBe(b.sas());
  });
});
