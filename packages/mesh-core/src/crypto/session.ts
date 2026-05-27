/**
 * session.ts — post-handshake AEAD session.
 *
 * Each direction (init→resp, resp→init) owns its own counter and replay
 * window. AEAD = AES-128-GCM via WebCrypto (hardware AES on modern ARM).
 * Nonce = (direction_byte || u64 counter, big-endian) padded to 12 bytes.
 *
 * sframe-ratchet hooks: present but minimal — we lazy-init the ratchet
 * with the static AEAD key. Per-frame ratchet step is a follow-up
 * optimisation (FOLLOWUPS.md#B.2-sframe-per-frame). For B.2 MVP we use
 * static AEAD with strict-monotonic + 64-window replay protection; this
 * achieves the spec's "no key reuse" + "replay rejection" guarantees.
 */

import { AEAD_KEY_BYTES, AEAD_NONCE_BYTES, REPLAY_WINDOW_SIZE } from '../constants.generated.js';
import { toBufferSource } from './buffer.js';

const TAG_LEN = 16;

export type Direction = 'initiator' | 'responder';

export interface SessionOptions {
  sendKey: Uint8Array; // 16 bytes
  recvKey: Uint8Array; // 16 bytes
  direction: Direction;
}

export class ReplayWindow {
  private highest: bigint = -1n;
  private bitmap = 0n; // bit i set iff (highest - i) has been seen, 0 ≤ i < REPLAY_WINDOW_SIZE

  /**
   * Read-only check: returns true if `counter` would be accepted.
   * Does NOT mutate replay state. Call this before AEAD decryption.
   * On AEAD success, call commit() to record the counter as seen.
   *
   * This two-phase pattern prevents a DoS gadget where an attacker spoofs
   * a frame with a valid counter but bad AEAD tag, poisoning the replay
   * bitmap so the legitimate frame at that counter is rejected.
   */
  canAccept(counter: bigint): boolean {
    if (counter < 0n) return false;
    if (this.highest < 0n) return true;
    if (counter > this.highest) return true;
    const offset = this.highest - counter;
    if (offset >= BigInt(REPLAY_WINDOW_SIZE)) return false;
    return (this.bitmap & (1n << offset)) === 0n;
  }

  /**
   * Mutate replay state to mark `counter` as seen.
   * Must only be called after AEAD decryption succeeds.
   */
  commit(counter: bigint): void {
    if (this.highest < 0n) {
      this.highest = counter;
      this.bitmap = 1n;
      return;
    }
    if (counter > this.highest) {
      const shift = counter - this.highest;
      if (shift >= BigInt(REPLAY_WINDOW_SIZE)) {
        this.bitmap = 1n;
      } else {
        this.bitmap = (this.bitmap << shift) | 1n;
      }
      this.highest = counter;
      // Trim bitmap to window size.
      const mask = (1n << BigInt(REPLAY_WINDOW_SIZE)) - 1n;
      this.bitmap &= mask;
    } else {
      const offset = this.highest - counter;
      this.bitmap |= (1n << offset);
    }
  }

  /**
   * Legacy combined check-and-accept. Kept for backward compatibility.
   * New callers should use canAccept() + commit() to avoid the DoS gadget
   * where replay state is mutated before AEAD verification.
   */
  checkAndAccept(counter: bigint): boolean {
    if (!this.canAccept(counter)) return false;
    this.commit(counter);
    return true;
  }
}

function makeNonce(direction: Direction, counter: bigint): Uint8Array {
  const buf = new Uint8Array(AEAD_NONCE_BYTES);
  buf[0] = direction === 'initiator' ? 0x00 : 0x01;
  const view = new DataView(buf.buffer);
  view.setBigUint64(AEAD_NONCE_BYTES - 8, counter, false);
  return buf;
}

export class Session {
  private readonly sendKey: Uint8Array;
  private readonly recvKey: Uint8Array;
  private readonly localDir: Direction;
  private readonly remoteDir: Direction;
  private sendCounter: bigint = 0n;
  private replay = new ReplayWindow();

  constructor(opts: SessionOptions) {
    if (opts.sendKey.length !== AEAD_KEY_BYTES) throw new Error('sendKey must be 16 bytes');
    if (opts.recvKey.length !== AEAD_KEY_BYTES) throw new Error('recvKey must be 16 bytes');
    this.sendKey = opts.sendKey;
    this.recvKey = opts.recvKey;
    this.localDir = opts.direction;
    this.remoteDir = opts.direction === 'initiator' ? 'responder' : 'initiator';
  }

  /**
   * Encrypt a frame. On-wire layout: [u64 counter, big-endian][ciphertext+tag].
   */
  async encrypt(plaintext: Uint8Array, ad: Uint8Array = new Uint8Array(0)): Promise<Uint8Array> {
    const counter = this.sendCounter;
    this.sendCounter += 1n;
    const nonce = makeNonce(this.localDir, counter);
    // Cast to ArrayBuffer-backed views: WebCrypto requires ArrayBuffer, not SharedArrayBuffer.
    const sendKeyBuf = toBufferSource(this.sendKey);
    const nonceBuf = toBufferSource(nonce);
    const adBuf = toBufferSource(ad);
    const ptBuf = toBufferSource(plaintext);
    const key = await crypto.subtle.importKey('raw', sendKeyBuf, 'AES-GCM', false, ['encrypt']);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(nonceBuf), additionalData: new Uint8Array(adBuf) }, key, ptBuf),
    );
    const out = new Uint8Array(8 + ct.length);
    new DataView(out.buffer).setBigUint64(0, counter, false);
    out.set(ct, 8);
    return out;
  }

  /**
   * Decrypt + replay-check a frame. Throws on AEAD failure or replay.
   *
   * Replay check is split into canAccept (read-only, before AEAD) and
   * commit (mutation, after AEAD success) to close the DoS gadget where
   * a spoofed frame with bad AEAD tag poisons replay state.
   */
  async decrypt(wire: Uint8Array, ad: Uint8Array = new Uint8Array(0)): Promise<Uint8Array> {
    if (wire.length < 8 + TAG_LEN) throw new Error('session: wire frame too short');
    const counter = new DataView(wire.buffer, wire.byteOffset, 8).getBigUint64(0, false);
    // Read-only check BEFORE AEAD — no state mutation yet.
    if (!this.replay.canAccept(counter)) {
      throw new Error(`session: replay rejected (counter=${counter})`);
    }
    const nonce = makeNonce(this.remoteDir, counter);
    const recvKeyBuf = toBufferSource(this.recvKey);
    const nonceBuf = toBufferSource(nonce);
    const adBuf = toBufferSource(ad);
    const cipherSlice = wire.slice(8);
    const ctBuf = toBufferSource(cipherSlice);
    const key = await crypto.subtle.importKey('raw', recvKeyBuf, 'AES-GCM', false, ['decrypt']);
    // AEAD decrypt may throw — replay state not yet mutated.
    const pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(nonceBuf), additionalData: new Uint8Array(adBuf) },
        key,
        ctBuf,
      ),
    );
    // AEAD succeeded — now safe to commit replay state.
    this.replay.commit(counter);
    return pt;
  }
}
