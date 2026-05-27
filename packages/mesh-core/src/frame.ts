import { FRAME_MAGIC, MAX_FRAME_SIZE } from './constants.js';

export const FRAME_HEADER_LEN = 4;

export const FrameType = {
  HandshakeMsg1: 0,
  HandshakeMsg2: 1,
  HandshakeMsg3: 2,
  SessionData: 3,
} as const;
export type FrameType = (typeof FrameType)[keyof typeof FrameType];

export interface ReassembledFrame {
  frameType: FrameType;
  payload: Uint8Array;
}

/**
 * Split a payload into wire chunks.
 *
 * B.2 byte-1 layout: [frame_type: u4 (top) | seq: u4 (bottom)].
 * Total chunks is capped at 16 (seq nibble is 0..15).
 *
 * Wire-compat with B.1: a B.1 peer sending raw seq > 15 produces total > 16
 * in the B.2 total field, which the B.2 reassembler rejects via the >16 guard.
 * No silent downgrade is possible.
 */
export function chunkFrame(
  payload: Uint8Array,
  mtu: number,
  frameType: FrameType = FrameType.SessionData,
): Uint8Array[] {
  // B1.13: enforce MAX_FRAME_SIZE before any other checks.
  if (payload.length > MAX_FRAME_SIZE) throw new Error('payload exceeds MAX_FRAME_SIZE');
  const dataPerChunk = mtu - FRAME_HEADER_LEN;
  if (dataPerChunk <= 0) throw new Error('mtu too small');
  const total = Math.ceil(payload.length / dataPerChunk);
  if (total > 16) throw new Error('frame requires >16 chunks; use B.3 mesh-bundle layer');
  if (total === 0) throw new Error('empty payload');
  const chunks: Uint8Array[] = [];
  for (let seq = 0; seq < total; seq++) {
    const start = seq * dataPerChunk;
    const end = Math.min(start + dataPerChunk, payload.length);
    const slice = payload.subarray(start, end);
    const chunk = new Uint8Array(FRAME_HEADER_LEN + slice.length);
    chunk[0] = FRAME_MAGIC;
    chunk[1] = (frameType << 4) | (seq & 0x0f);
    chunk[2] = total;
    chunk[3] = slice.length;
    chunk.set(slice, FRAME_HEADER_LEN);
    chunks.push(chunk);
  }
  return chunks;
}

export class FrameReassembler {
  private slots: (Uint8Array | undefined)[] = [];
  private expectedTotal = 0;
  private received = 0;
  private currentFrameType: FrameType | null = null;

  /** Legacy API — discards frame_type, returns payload only. */
  push(chunk: Uint8Array): Uint8Array | null {
    const res = this.pushWithType(chunk);
    return res ? res.payload : null;
  }

  pushWithType(chunk: Uint8Array): ReassembledFrame | null {
    if (chunk.length < FRAME_HEADER_LEN) throw new Error('chunk too short');
    // Non-null assertions safe: bounds-check above guarantees indices 0-3 exist.
    if (chunk[0] !== FRAME_MAGIC) throw new Error('bad magic byte');
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const seqByte = chunk[1]!;
    const ft = ((seqByte >> 4) & 0x0f) as FrameType;
    const seq = seqByte & 0x0f;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const total = chunk[2]!;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const len = chunk[3]!;
    // B1.5: validate len field against actual chunk data length.
    if (len !== chunk.length - FRAME_HEADER_LEN) {
      throw new Error('len-field mismatch with chunk size');
    }
    // B.2 wire-compat guard: B.1 peers can produce total > 16 (raw seq up to 255).
    // Reject immediately — no silent downgrade.
    if (total > 16) throw new Error('total exceeds 16 — wire incompatible with B.2');
    if (this.expectedTotal === 0) {
      this.expectedTotal = total;
      this.slots = new Array(total);
      this.currentFrameType = ft;
    } else {
      if (this.expectedTotal !== total) throw new Error('total mismatch');
      if (this.currentFrameType !== ft) throw new Error('frame_type mismatch within frame');
    }
    if (this.slots[seq] !== undefined) return null; // duplicate
    this.slots[seq] = chunk.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + len);
    this.received++;
    if (this.received < total) return null;

    let outLen = 0;
    for (const s of this.slots) if (s) outLen += s.length;
    const out = new Uint8Array(outLen);
    let off = 0;
    for (const s of this.slots) {
      if (!s) throw new Error('hole in slots');
      out.set(s, off);
      off += s.length;
    }
    const resolvedType = this.currentFrameType!;
    this.expectedTotal = 0;
    this.received = 0;
    this.slots = [];
    this.currentFrameType = null;
    return { frameType: resolvedType, payload: out };
  }
}
