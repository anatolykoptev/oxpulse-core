export type CryptoErrorKind =
  | 'handshake-failed'
  | 'replay-rejected'
  | 'sas-mismatch'
  | 'unknown-peer-key';

export function isCryptoError(k: unknown): k is CryptoErrorKind {
  return k === 'handshake-failed'
    || k === 'replay-rejected'
    || k === 'sas-mismatch'
    || k === 'unknown-peer-key';
}
