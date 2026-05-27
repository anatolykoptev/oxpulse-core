import { describe, it, expect } from 'vitest';
import { generateMlkemKeypair, encapsulate, decapsulate } from '../../crypto/mlkem-wrap.js';
import {
  MLKEM_PUBLIC_KEY_BYTES,
  MLKEM_CIPHERTEXT_BYTES,
  MLKEM_SHARED_SECRET_BYTES,
} from '../../constants.generated.js';

describe('mlkem-wrap (ML-KEM-768)', () => {
  it('keypair has expected sizes', () => {
    const { publicKey, secretKey } = generateMlkemKeypair();
    expect(publicKey.length).toBe(MLKEM_PUBLIC_KEY_BYTES);
    expect(secretKey.length).toBeGreaterThan(0);
  });

  it('encapsulate / decapsulate round-trip', () => {
    const kp = generateMlkemKeypair();
    const { ciphertext, sharedSecret } = encapsulate(kp.publicKey);
    expect(ciphertext.length).toBe(MLKEM_CIPHERTEXT_BYTES);
    expect(sharedSecret.length).toBe(MLKEM_SHARED_SECRET_BYTES);

    const recovered = decapsulate(kp.secretKey, ciphertext);
    expect(recovered).toEqual(sharedSecret);
  });

  it('tampered ciphertext yields a different shared secret (implicit rejection)', () => {
    const kp = generateMlkemKeypair();
    const { ciphertext } = encapsulate(kp.publicKey);
    const bad = new Uint8Array(ciphertext);
    bad[0] ^= 0xff;
    const recovered = decapsulate(kp.secretKey, bad);
    // ML-KEM-768 implements implicit rejection: tampered ct produces a
    // pseudorandom key, NOT an exception. Downstream HKDF mix means the
    // session key diverges → AEAD decrypt will fail in session.ts.
    const honest = decapsulate(kp.secretKey, ciphertext);
    expect(recovered).not.toEqual(honest);
  });

  it('wrong secret key yields a different shared secret', () => {
    const a = generateMlkemKeypair();
    const b = generateMlkemKeypair();
    const { ciphertext, sharedSecret } = encapsulate(a.publicKey);
    const wrong = decapsulate(b.secretKey, ciphertext);
    expect(wrong).not.toEqual(sharedSecret);
  });
});
