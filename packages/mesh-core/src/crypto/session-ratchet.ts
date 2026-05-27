// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ CRYPTO-INTERNAL — DO NOT call snapshotRecvChain or fromCompromisedState ║
// ║ from production code. They expose chain-key material for testing only.  ║
// ║ A compliance test grepping non-__tests__/ for these identifiers         ║
// ║ exists in session-ratchet-compliance.test.ts.                           ║
// ╚══════════════════════════════════════════════════════════════════════════╝

/**
 * session-ratchet.ts — per-frame AEAD key ratcheting (B.2-sframe-per-frame).
 *
 * Each frame is encrypted under a *distinct* AEAD key derived from the
 * previous frame's chain key via one HKDF-SHA-256 step. After the key is
 * used the chain key advances (irreversibly).
 *
 * **Window forward secrecy** (NOT per-frame FS). Keys for the trailing
 * RECV_WINDOW_SIZE = 64 frames are retained in memory to tolerate BLE
 * reorder. Compromise of the receiver's state at frame T therefore reveals
 * frames in [T-63, T]; frames older than T-64 are unrecoverable because
 * their keys + chain state have been evicted via pruneOlderThan.
 *
 * Trade-off: 64-frame compromise blast radius traded for the ability to
 * decrypt out-of-order BLE delivery within the same window. Per-frame FS
 * (Option A) was rejected because BLE GATT notifications can reorder under
 * congestion — strict in-order delivery dropped legitimate frames.
 *
 * Design choices
 * --------------
 * • Ratchet function: HKDF-SHA-256 with a domain-separated info string.
 *   @noble/hashes is already a peer dep; avoids a second WebCrypto await
 *   per frame and keeps the key schedule synchronous.
 * • Chain key size: 32 bytes (deliberately wider than AEAD key so the
 *   ratchet and key derivation draw from non-overlapping HKDF output).
 * • AEAD: AES-128-GCM via WebCrypto. Nonce = direction_byte || u64
 *   counter, big-endian, zero-padded to 12 bytes — same layout as
 *   Session in session.ts for consistency.
 * • Replay window: 64-entry bitmap identical to Session. Frames behind
 *   the window are rejected regardless of key generation.
 * • Out-of-order delivery: the receiver maintains a key cache covering
 *   the same 64-counter window as the replay bitmap. Frames that arrive
 *   reordered within the window can be decrypted. Keys for counters
 *   more than RECV_WINDOW_SIZE (64) frames behind the highest decrypted
 *   counter are pruned — forward secrecy beyond the window.
 *
 * Wire format (same as Session):
 *   [u64 counter big-endian][AES-128-GCM ciphertext+tag]
 *
 * Wire incompatibility
 * --------------------
 * RatchetSession is NOT compatible with the static-key Session class.
 * Old B.2 peers that run Session cannot interoperate with RatchetSession
 * peers. At the time this ships there are no Session peers in production,
 * so this is a clean break.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { AEAD_NONCE_BYTES, REPLAY_WINDOW_SIZE } from '../constants.generated.js';
import { ReplayWindow } from './session.js';
import { toBufferSource } from './buffer.js';

// ─── Constants ───────────────────────────────────────────────────────────────

const AEAD_KEY_BYTES = 16; // AES-128-GCM
const TAG_LEN = 16;
const CHAIN_KEY_BYTES = 32; // wider than AEAD key; holds both key + ratchet material

// Domain-separated HKDF info strings.
const INFO_FRAME_KEY = new TextEncoder().encode('mesh/frame-ratchet/v1/key');
const INFO_FRAME_RATCHET = new TextEncoder().encode('mesh/frame-ratchet/v1/ratchet');

// Key cache window. Keys are retained for counters within
// [highestDecrypted - RECV_WINDOW_SIZE + 1 .. highestDecrypted + RECV_LOOKAHEAD].
// This matches the replay window scope so any counter the ReplayWindow
// accepts also has a key available. Keys outside this range are pruned
// for forward secrecy.
//
// RECV_WINDOW_SIZE must equal REPLAY_WINDOW_SIZE (both 64) so that
// the key cache and replay bitmap cover the same counter range.
const RECV_WINDOW_SIZE = REPLAY_WINDOW_SIZE; // parity with ReplayWindow bitmap
// How many keys to derive ahead of the highest ever requested.
const RECV_LOOKAHEAD = 8;

export type Direction = 'initiator' | 'responder';

// ─── Options ─────────────────────────────────────────────────────────────────

export interface RatchetSessionOptions {
  /** 32-byte initial send chain key (from Noise split, direction-specific). */
  sendChainKey: Uint8Array;
  /** 32-byte initial recv chain key (from Noise split, direction-specific). */
  recvChainKey: Uint8Array;
  direction: Direction;
}

export interface CompromisedStateOptions {
  /** Chain key captured from a live receiver at the moment of compromise. */
  recvChainKey: Uint8Array;
  /** The next counter value the compromised receiver expects. */
  nextCounter: bigint;
  direction: Direction;
}

// ─── Key derivation helpers ───────────────────────────────────────────────────

/**
 * Derive the AES-GCM AEAD key bytes for a given chain key.
 * Does NOT advance the chain — call `ratchetChain()` separately.
 */
function deriveFrameKey(chainKey: Uint8Array): Uint8Array {
  return hkdf(sha256, chainKey, undefined, INFO_FRAME_KEY, AEAD_KEY_BYTES);
}

/**
 * Advance the chain key by one HKDF step.
 * The old chain key must be discarded by the caller (overwrite or GC).
 */
function ratchetChain(chainKey: Uint8Array): Uint8Array {
  return hkdf(sha256, chainKey, undefined, INFO_FRAME_RATCHET, CHAIN_KEY_BYTES);
}

// ─── Nonce construction ───────────────────────────────────────────────────────

function makeNonce(direction: Direction, counter: bigint): Uint8Array {
  const buf = new Uint8Array(AEAD_NONCE_BYTES);
  buf[0] = direction === 'initiator' ? 0x00 : 0x01;
  new DataView(buf.buffer).setBigUint64(AEAD_NONCE_BYTES - 8, counter, false);
  return buf;
}

// ─── Lookahead key cache ──────────────────────────────────────────────────────

/**
 * A rolling cache of (counter → AEAD key bytes) pairs for the receive
 * direction. Covers the replay window [highestSeen - RECV_WINDOW_SIZE + 1
 * .. highestSeen + RECV_LOOKAHEAD] so that any counter accepted by
 * ReplayWindow also has a key available.
 *
 * Eviction policy (window-based, not strict in-order):
 *   After decrypting counter N, prune all keys older than
 *   (N - RECV_WINDOW_SIZE + 1). Keys within the window are retained to
 *   allow reordered frames — matching what the replay bitmap tracks.
 *   This is the correct behaviour for lossy transports (BLE mesh) where
 *   frames arrive out-of-order within a window.
 *
 * Forward secrecy: keys older than RECV_WINDOW_SIZE frames behind the
 * highest decrypted counter are gone. Those counters will be rejected by
 * the replay window anyway.
 *
 * `chainAtLowest` tracks the chain state just before deriving the key at
 * `lowestCounter`, allowing snapshotRecvChain() to return a compact
 * representation of the current key-schedule position.
 */
class RecvKeyCache {
  /** counter → 16-byte AEAD key material */
  private readonly keys = new Map<bigint, Uint8Array>();
  /** The lowest counter for which we still hold a key. */
  lowestCounter: bigint = 0n;
  /**
   * Chain state at `lowestCounter`. deriveFrameKey(chainAtLowest) yields
   * the key for lowestCounter; ratchetChain(chainAtLowest) yields the
   * chain for lowestCounter+1, and so on.
   */
  private chainAtLowest: Uint8Array;
  /** Chain pointer for deriving new forward keys (always ≥ highestDerived). */
  private chain: Uint8Array;
  /** Highest counter for which we have derived a key. */
  private highestDerived: bigint;

  constructor(initialChain: Uint8Array, startCounter: bigint = 0n) {
    this.lowestCounter = startCounter;
    this.chainAtLowest = initialChain.slice();
    this.chain = initialChain.slice();
    this.highestDerived = startCounter - 1n; // nothing derived yet
    this.fill(startCounter + BigInt(RECV_LOOKAHEAD) - 1n);
  }

  /** Derive keys up to and including `upTo`, extending the forward cache. */
  private fill(upTo: bigint): void {
    while (this.highestDerived < upTo) {
      const ctr = this.highestDerived + 1n;
      this.keys.set(ctr, deriveFrameKey(this.chain));
      this.chain = ratchetChain(this.chain);
      this.highestDerived = ctr;
    }
  }

  /**
   * Look up the AEAD key for `counter`. Returns null if:
   *   - counter < lowestCounter (key pruned — forward secrecy), or
   *   - counter is too far ahead of the cache head (anomalous jump).
   * Extends the forward cache if counter is within a normal lookahead.
   */
  get(counter: bigint): Uint8Array | null {
    if (counter < this.lowestCounter) return null;
    // Extend forward if within a reasonable range beyond current cache.
    const maxExtend = this.highestDerived + BigInt(RECV_LOOKAHEAD * 2);
    if (counter > this.highestDerived && counter <= maxExtend) {
      this.fill(counter + BigInt(RECV_LOOKAHEAD));
    }
    return this.keys.get(counter) ?? null;
  }

  /**
   * Called after a frame at `counter` has been successfully decrypted.
   * Prunes keys for counters older than (counter - RECV_WINDOW_SIZE + 1),
   * matching the replay window scope. Keys within the window are kept to
   * allow reordered frames. Replenishes the forward cache after pruning.
   */
  pruneOlderThan(counter: bigint): void {
    // The oldest counter we must still retain (replay window boundary).
    const windowFloor = counter - BigInt(RECV_WINDOW_SIZE) + 1n;
    const pruneBelow = windowFloor > this.lowestCounter ? windowFloor : this.lowestCounter;

    // Prune and advance chainAtLowest.
    for (let c = this.lowestCounter; c < pruneBelow; c += 1n) {
      this.keys.delete(c);
      this.chainAtLowest = ratchetChain(this.chainAtLowest);
    }
    if (pruneBelow > this.lowestCounter) {
      this.lowestCounter = pruneBelow;
    }

    // Ensure forward cache covers at least RECV_LOOKAHEAD beyond counter.
    this.fill(counter + BigInt(RECV_LOOKAHEAD));
  }

  /**
   * Return the chain state at `lowestCounter`.
   * Used by snapshotRecvChain() for forward-secrecy tests.
   */
  snapshotChainAtLowest(): Uint8Array {
    return this.chainAtLowest.slice();
  }
}

// ─── RatchetSession ───────────────────────────────────────────────────────────

export class RatchetSession {
  private sendChain: Uint8Array;
  private sendCounter: bigint = 0n;
  private readonly localDir: Direction;
  private readonly remoteDir: Direction;
  private recvCache: RecvKeyCache;
  private replay = new ReplayWindow();

  constructor(opts: RatchetSessionOptions) {
    if (opts.sendChainKey.length !== CHAIN_KEY_BYTES) {
      throw new Error(`sendChainKey must be ${CHAIN_KEY_BYTES} bytes`);
    }
    if (opts.recvChainKey.length !== CHAIN_KEY_BYTES) {
      throw new Error(`recvChainKey must be ${CHAIN_KEY_BYTES} bytes`);
    }
    this.sendChain = opts.sendChainKey.slice();
    this.localDir = opts.direction;
    this.remoteDir = opts.direction === 'initiator' ? 'responder' : 'initiator';
    this.recvCache = new RecvKeyCache(opts.recvChainKey.slice(), 0n);
  }

  /**
   * Build a RatchetSession for the receive side only, starting from a
   * chain key captured at the point of compromise. Used by tests to
   * verify forward secrecy guarantees.
   *
   * Low-counter rejection relies solely on the key cache: RecvKeyCache
   * starts at `nextCounter`, so any frame with counter < nextCounter
   * returns null from `get()` and is rejected with "key no longer
   * available". No explicit replay-window seeding is needed — attempting
   * to forge old frames is blocked by the forward-secrecy key boundary.
   *
   * @internal — test-only state injection. DO NOT call in production.
   * See CRYPTO-INTERNAL banner at the top of this file.
   */
  static fromCompromisedState(opts: CompromisedStateOptions): RatchetSession {
    // Match constructor validation — Object.create bypasses it.
    if (opts.recvChainKey.length !== CHAIN_KEY_BYTES) {
      throw new Error(`recvChainKey must be ${CHAIN_KEY_BYTES} bytes, got ${opts.recvChainKey.length}`);
    }
    const s = Object.create(RatchetSession.prototype) as RatchetSession;
    s.sendChain = new Uint8Array(CHAIN_KEY_BYTES); // dummy — no sends
    s.sendCounter = 0n;
    // localDir/remoteDir are `private readonly` on the class. This test-only
    // factory bypasses the constructor via Object.create, so we cast through
    // `unknown` to a struct exposing just these two fields as writable.
    const sMut = s as unknown as { localDir: Direction; remoteDir: Direction };
    sMut.localDir = opts.direction;
    sMut.remoteDir = opts.direction === 'initiator' ? 'responder' : 'initiator';
    s.recvCache = new RecvKeyCache(opts.recvChainKey.slice(), opts.nextCounter);
    // Fresh replay window — counters below nextCounter are rejected by
    // the key cache (no key available), not by the replay bitmap.
    s.replay = new ReplayWindow();
    return s;
  }

  /**
   * Encrypt a frame. Returns `[u64 counter][ciphertext+tag]`.
   * Ratchets the send chain forward after each call (irreversible).
   */
  async encrypt(plaintext: Uint8Array, ad: Uint8Array = new Uint8Array(0)): Promise<Uint8Array> {
    const counter = this.sendCounter;
    this.sendCounter += 1n;

    const rawKey = deriveFrameKey(this.sendChain);
    // Advance chain immediately — old key material becomes unrecoverable.
    this.sendChain = ratchetChain(this.sendChain);

    const nonce = makeNonce(this.localDir, counter);
    const key = await crypto.subtle.importKey('raw', toBufferSource(rawKey), 'AES-GCM', false, ['encrypt']);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: new Uint8Array(toBufferSource(nonce)), additionalData: new Uint8Array(toBufferSource(ad)) },
        key,
        toBufferSource(plaintext),
      ),
    );
    const out = new Uint8Array(8 + ct.length);
    new DataView(out.buffer).setBigUint64(0, counter, false);
    out.set(ct, 8);
    return out;
  }

  /**
   * Decrypt + replay-check a frame.
   * Throws on AEAD failure, replay, or if the frame counter precedes the
   * current forward-secrecy boundary (key is gone).
   */
  async decrypt(wire: Uint8Array, ad: Uint8Array = new Uint8Array(0)): Promise<Uint8Array> {
    if (wire.length < 8 + TAG_LEN) throw new Error('ratchet: wire frame too short');

    const counter = new DataView(wire.buffer, wire.byteOffset, 8).getBigUint64(0, false);

    // Read-only replay check BEFORE AEAD — prevents DoS gadget where a
    // spoofed frame with bad AEAD tag poisons replay state so the legitimate
    // frame at the same counter is rejected. State mutation (commit) only
    // happens after AEAD succeeds.
    if (!this.replay.canAccept(counter)) {
      throw new Error(`ratchet: replay rejected (counter=${counter})`);
    }

    const rawKey = this.recvCache.get(counter);
    if (rawKey === null) {
      throw new Error(
        `ratchet: key for counter=${counter} is no longer available ` +
        `(forward-secrecy boundary=${this.recvCache.lowestCounter})`,
      );
    }

    const nonce = makeNonce(this.remoteDir, counter);
    const key = await crypto.subtle.importKey('raw', toBufferSource(rawKey), 'AES-GCM', false, ['decrypt']);
    // AEAD decrypt may throw — replay state not yet mutated.
    const pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(toBufferSource(nonce)), additionalData: new Uint8Array(toBufferSource(ad)) },
        key,
        toBufferSource(wire.slice(8)),
      ),
    );

    // AEAD succeeded — now safe to commit replay state and prune key cache.
    this.replay.commit(counter);
    // Prune keys older than the replay window around this counter.
    // Keys within the window are retained for reordered frames.
    this.recvCache.pruneOlderThan(counter);

    return pt;
  }

  /**
   * Return the current recv chain key snapshot for testing forward-secrecy
   * properties. Returns a copy — does not mutate session state.
   *
   * @internal — test-only chain-key extraction. DO NOT call in production.
   * See CRYPTO-INTERNAL banner at the top of this file.
   */
  snapshotRecvChain(): Uint8Array {
    return this.recvCache.snapshotChainAtLowest();
  }

  /**
   * The lowest counter for which this session still holds a decryption key.
   * Counters below this value cannot be decrypted — forward secrecy.
   * Exposed for `fromCompromisedState` tests.
   */
  get recvCounter(): bigint {
    return this.recvCache.lowestCounter;
  }
}

