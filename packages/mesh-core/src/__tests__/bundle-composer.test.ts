/**
 * Tests for bundle-composer.ts (B-4 Phase).
 */
import { describe, it, expect } from 'vitest';
import { composeBundle, MESH_BUNDLE_TS_EPOCH_MS } from '../bundle-composer.js';

const CHANNEL_ID = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
const BODY = new Uint8Array([0x01, 0x02, 0x03]);

describe('composeBundle', () => {
  it('returns bundle bytes starting with 0xC9 magic', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
    expect(result.bundle[0]).toBe(0xc9);
  });

  it('returns the channelId used', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
    expect(result.channelId).toEqual(CHANNEL_ID);
  });

  it('generates a unique msgId per call (UUIDv4 bytes, 16 B)', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const r1 = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
    const r2 = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
    expect(r1.msgId.length).toBe(16);
    expect(r2.msgId.length).toBe(16);
    const differ = r1.msgId.some((b, i) => b !== r2.msgId[i]);
    expect(differ).toBe(true);
  });

  it('uses provided msgId when supplied', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const fixedMsgId = new Uint8Array(16).fill(0xfe);
    const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey, msgId: fixedMsgId });
    expect(result.msgId).toEqual(fixedMsgId);
  });

  it('round-trips via decodeMeshBundle (valid header layout)', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
    const { decodeMeshBundle } = await import('@oxpulse/wire-codec');
    const decoded = decodeMeshBundle(result.bundle);
    expect(decoded.body).toEqual(BODY);
    expect(Array.from(decoded.channelIdHash)).toEqual(Array.from(CHANNEL_ID));
    expect(Array.from(decoded.senderPubkey)).toEqual(Array.from(pubkey));
  });
});

describe('bundle-composer — tsSecOffset epoch', () => {
  it('MESH_BUNDLE_TS_EPOCH_MS is 1767225600000 (2026-01-01 UTC)', () => {
    expect(MESH_BUNDLE_TS_EPOCH_MS).toBe(1767225600000);
  });

  it('tsSecOffset for a known date returns predictable seconds value', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);

    // Freeze time to epoch + 1000ms (1 second)
    const fakeNow = MESH_BUNDLE_TS_EPOCH_MS + 1000;
    const origNow = Date.now;
    Date.now = () => fakeNow;
    try {
      const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
      const { decodeMeshBundle } = await import('@oxpulse/wire-codec');
      const decoded = decodeMeshBundle(result.bundle);
      // tsSecOffset should be 1 (1 second after epoch = Math.floor(1000/1000))
      expect(decoded.tsSecOffset).toBe(1);
    } finally {
      Date.now = origNow;
    }
  });

  it('tsSecOffset for epoch + 5000ms returns 5', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);

    // 5 seconds after epoch
    const fakeNow = MESH_BUNDLE_TS_EPOCH_MS + 5000;
    const origNow = Date.now;
    Date.now = () => fakeNow;
    try {
      const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
      const { decodeMeshBundle } = await import('@oxpulse/wire-codec');
      const decoded = decodeMeshBundle(result.bundle);
      expect(decoded.tsSecOffset).toBe(5);
    } finally {
      Date.now = origNow;
    }
  });

  it('tsSecOffset is always unsigned (no negative values for times after epoch)', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);

    // Use a time well after epoch — should give a large positive seconds value
    const fakeNow = MESH_BUNDLE_TS_EPOCH_MS + 0x80000001; // > 2^31 ms after epoch
    const origNow = Date.now;
    Date.now = () => fakeNow;
    try {
      const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
      const { decodeMeshBundle } = await import('@oxpulse/wire-codec');
      const decoded = decodeMeshBundle(result.bundle);
      // Must be >= 0 (unsigned semantics via >>> 0)
      expect(decoded.tsSecOffset).toBeGreaterThanOrEqual(0);
    } finally {
      Date.now = origNow;
    }
  });

  it('tsSecOffset today (2026-05-16) is in the correct seconds range', async () => {
    // 2026-05-16 - 2026-01-01 = 135 days * 86400 s/day = 11,664,000 s
    // Plus ~11 hours into the day ≈ 40,000 s -> total ~11,704,000..11,750,000 s
    // This test validates the order of magnitude is correct (seconds, not ms)
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const result = await composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: pubkey });
    const { decodeMeshBundle } = await import('@oxpulse/wire-codec');
    const decoded = decodeMeshBundle(result.bundle);
    // Should be in the ~11M range (seconds), NOT ~11B range (ms)
    expect(decoded.tsSecOffset).toBeGreaterThan(11_000_000);   // > 127 days
    expect(decoded.tsSecOffset).toBeLessThan(50_000_000);      // < 579 days (< ~1.6 years from epoch)
  });
});

describe('bundle-composer — key length validation (MAJOR 2)', () => {
  it('throws on wrong-length private key (31 bytes)', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const badKey = privkey.slice(0, 31); // 31 bytes instead of 32
    await expect(
      composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: badKey, senderPubkey: pubkey })
    ).rejects.toThrow(/senderKey/i);
  });

  it('throws on wrong-length public key (31 bytes)', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    const badPubkey = pubkey.slice(0, 31);
    await expect(
      composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: privkey, senderPubkey: badPubkey })
    ).rejects.toThrow(/senderPubkey/i);
  });

  it('throws on empty private key', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    const privkey = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(privkey);
    await expect(
      composeBundle({ channelId: CHANNEL_ID, body: BODY, senderKey: new Uint8Array(0), senderPubkey: pubkey })
    ).rejects.toThrow(/senderKey/i);
  });
});
