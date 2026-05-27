/**
 * mlkem-wrap.ts — ML-KEM-768 KEM wrapper.
 *
 * Hybrid with Noise XX: initiator encapsulates to the responder's
 * ephemeral ML-KEM pubkey (carried as a payload in handshake msg-1).
 * Responder decapsulates during msg-2. The resulting 32-byte shared
 * secret is HKDF-mixed into the Noise SymmetricState in noise-xx.ts.
 *
 * Implicit rejection: ML-KEM-768 (FIPS 203) returns a pseudorandom
 * 32-byte value on invalid ciphertext, never throws. Bad ciphertexts
 * surface downstream as AEAD-decrypt failures in session.ts.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  MLKEM_PUBLIC_KEY_BYTES,
  MLKEM_CIPHERTEXT_BYTES,
  MLKEM_SHARED_SECRET_BYTES,
} from '../constants.generated.js';

export interface MlkemKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface MlkemEncap {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export function generateMlkemKeypair(): MlkemKeypair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  // Defensive: validate sizes match SoT constants.
  if (publicKey.length !== MLKEM_PUBLIC_KEY_BYTES) {
    throw new Error('mlkem-wrap: keygen public key size mismatch');
  }
  return { publicKey, secretKey };
}

export function encapsulate(peerPublicKey: Uint8Array): MlkemEncap {
  if (peerPublicKey.length !== MLKEM_PUBLIC_KEY_BYTES) {
    throw new Error(
      `mlkem-wrap: expected ${MLKEM_PUBLIC_KEY_BYTES}-byte pubkey, got ${peerPublicKey.length}`,
    );
  }
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(peerPublicKey);
  if (cipherText.length !== MLKEM_CIPHERTEXT_BYTES) {
    throw new Error('mlkem-wrap: encapsulate ciphertext size mismatch');
  }
  if (sharedSecret.length !== MLKEM_SHARED_SECRET_BYTES) {
    throw new Error('mlkem-wrap: encapsulate shared-secret size mismatch');
  }
  return { ciphertext: cipherText, sharedSecret };
}

export function decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length !== MLKEM_CIPHERTEXT_BYTES) {
    throw new Error(
      `mlkem-wrap: expected ${MLKEM_CIPHERTEXT_BYTES}-byte ciphertext, got ${ciphertext.length}`,
    );
  }
  const sharedSecret = ml_kem768.decapsulate(ciphertext, secretKey);
  if (sharedSecret.length !== MLKEM_SHARED_SECRET_BYTES) {
    throw new Error('mlkem-wrap: decapsulate shared-secret size mismatch');
  }
  return sharedSecret;
}
