import { describe, it, expect } from 'vitest';
import { chunkFrame, FrameReassembler, FRAME_HEADER_LEN, FrameType } from '../frame';
import { FRAME_MAGIC, MAX_FRAME_SIZE } from '../constants';

describe('frame chunker', () => {
  it('splits 100-byte payload into 5 chunks at mtu=24', () => {
    const payload = new Uint8Array(100).map((_, i) => i);
    const chunks = chunkFrame(payload, 24);
    expect(chunks.length).toBe(5);
    expect(chunks[0][0]).toBe(FRAME_MAGIC);
    // B.2: byte 1 = (frame_type<<4) | seq. Default frame_type=SessionData=3.
    expect(chunks[0]![1] & 0x0f).toBe(0);  // seq 0
    expect(chunks[0]![1] >> 4).toBe(FrameType.SessionData); // frame_type 3
    expect(chunks[0][2]).toBe(5);       // total 5
    expect(chunks[4]![1] & 0x0f).toBe(4); // seq 4
  });

  it('reassembles in any order', () => {
    const payload = new Uint8Array(80).map((_, i) => i & 0xff);
    const chunks = chunkFrame(payload, 24);
    const r = new FrameReassembler();
    expect(r.push(chunks[3])).toBeNull();
    expect(r.push(chunks[0])).toBeNull();
    expect(r.push(chunks[2])).toBeNull();
    const done = r.push(chunks[1]);
    expect(done).not.toBeNull();
    expect(done).toEqual(payload);
  });

  it('rejects chunk with wrong magic', () => {
    const r = new FrameReassembler();
    expect(() => r.push(new Uint8Array([0xff, 0, 1, 1, 42]))).toThrow(/magic/);
  });

  it('caps total to 16 chunks (B.2 seq nibble limit)', () => {
    // B.2: seq is 4 bits → max 16 chunks. Reject anything needing more.
    // 16 chunks * 20 bytes each + 1 byte = 17th chunk needed.
    const tooBig = new Uint8Array(16 * 20 + 1);
    expect(() => chunkFrame(tooBig, 24)).toThrow(/16|chunks/);
  });

  it('throws when len field does not match actual chunk data length', () => {
    // B1.5: FrameReassembler must validate len-field vs chunk size
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const chunks = chunkFrame(payload, 24);
    // Tamper with the len field: say 10 bytes but chunk only carries 5
    const tampered = new Uint8Array(chunks[0]);
    tampered[3] = 10; // len field mismatch
    const r = new FrameReassembler();
    expect(() => r.push(tampered)).toThrow(/len/);
  });

  it('throws when payload exceeds MAX_FRAME_SIZE', () => {
    // B1.13: chunkFrame must enforce MAX_FRAME_SIZE
    const tooBig = new Uint8Array(MAX_FRAME_SIZE + 1);
    expect(() => chunkFrame(tooBig, 247)).toThrow(/MAX_FRAME_SIZE/);
  });
});

describe('frame_type packed in seq byte', () => {
  it('encodes frame_type in top 4 bits and seq in bottom 4 bits', () => {
    const chunks = chunkFrame(new Uint8Array([1, 2, 3]), 247, FrameType.HandshakeMsg1);
    expect(chunks[0]![1] >> 4).toBe(FrameType.HandshakeMsg1);
    expect(chunks[0]![1] & 0x0f).toBe(0);
  });

  it('reassembler exposes the frame_type', () => {
    const r = new FrameReassembler();
    const chunks = chunkFrame(new Uint8Array([42]), 247, FrameType.SessionData);
    const { frameType, payload } = r.pushWithType(chunks[0]!)!;
    expect(frameType).toBe(FrameType.SessionData);
    expect(payload).toEqual(new Uint8Array([42]));
  });

  it('rejects payloads that need > 16 chunks', () => {
    // dataPerChunk = 247 - 4 = 243; 16 * 243 = 3888, so 3889 bytes needs 17 chunks
    expect(() =>
      chunkFrame(new Uint8Array(16 * 243 + 1).fill(0xab), 247, FrameType.SessionData),
    ).toThrow(/16|chunks/);
  });

  it('legacy chunkFrame (no frame_type arg) defaults to SessionData = 3', () => {
    const chunks = chunkFrame(new Uint8Array([1]), 247);
    expect(chunks[0]![1] >> 4).toBe(FrameType.SessionData);
  });

  it('throws on mixed frame_type within a frame (B.2 wire-compat guard)', () => {
    // Handshake-msg1 chunk followed by session-data chunk with same total/seq structure
    // but different frame_type — reassembler must reject it.
    const r = new FrameReassembler();
    // Manually craft two chunks with total=2, seq=0 and seq=1, differing frame_type
    const mtu = 247;
    const dataPerChunk = mtu - FRAME_HEADER_LEN;
    const chunk0 = new Uint8Array(FRAME_HEADER_LEN + 10);
    chunk0[0] = FRAME_MAGIC;
    chunk0[1] = (FrameType.HandshakeMsg1 << 4) | 0; // ft=0, seq=0
    chunk0[2] = 2; // total=2
    chunk0[3] = 10;
    chunk0.fill(0xaa, FRAME_HEADER_LEN);
    expect(r.pushWithType(chunk0)).toBeNull();

    const chunk1 = new Uint8Array(FRAME_HEADER_LEN + 10);
    chunk1[0] = FRAME_MAGIC;
    chunk1[1] = (FrameType.SessionData << 4) | 1; // ft=3, seq=1 — mismatch!
    chunk1[2] = 2; // total=2
    chunk1[3] = 10;
    chunk1.fill(0xbb, FRAME_HEADER_LEN);
    expect(() => r.pushWithType(chunk1)).toThrow(/frame_type mismatch/);
  });

  it('B.1-style chunk with raw seq > 15 is invalid in B.2 (total>16 guard)', () => {
    // B.1 sender could send seq=20 (raw, no frame_type encoding).
    // In B.2 layout this means total field is interpreted normally; but if total>16
    // the B.2 reassembler must reject it.
    const r = new FrameReassembler();
    const badChunk = new Uint8Array(FRAME_HEADER_LEN + 5);
    badChunk[0] = FRAME_MAGIC;
    badChunk[1] = 20; // B.1 raw seq=20, interpreted as frame_type=1, seq=4 in B.2
    badChunk[2] = 20; // total=20 — exceeds 16, triggers wire-compat guard
    badChunk[3] = 5;
    badChunk.fill(0xcc, FRAME_HEADER_LEN);
    expect(() => r.pushWithType(badChunk)).toThrow(/16|total/);
  });

  it('round-trips HandshakeMsg2 through chunkFrame + pushWithType', () => {
    const payload = new Uint8Array(500).map((_, i) => i & 0xff);
    const chunks = chunkFrame(payload, 247, FrameType.HandshakeMsg2);
    const r = new FrameReassembler();
    let result: { frameType: FrameType; payload: Uint8Array } | null = null;
    for (const c of chunks) {
      result = r.pushWithType(c) ?? null;
    }
    expect(result).not.toBeNull();
    expect(result!.frameType).toBe(FrameType.HandshakeMsg2);
    expect(result!.payload).toEqual(payload);
  });
});
