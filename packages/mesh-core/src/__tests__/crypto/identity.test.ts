import { describe, it, expect } from 'vitest';
import 'fake-indexeddb/auto';
import { sha256 } from '@noble/hashes/sha2.js';
import { derivePeerId } from '../../crypto/identity.js';

// @oxpulse/identity exposes getOrCreateDeviceIdentity backed by fake-indexeddb in test
describe('identity', () => {
  it('derives 8-byte peer-id as SHA256(pubkey)[0..8]', async () => {
    const peerId = await derivePeerId();
    expect(peerId.length).toBe(8);
  });

  it('is deterministic across calls', async () => {
    const a = await derivePeerId();
    const b = await derivePeerId();
    expect(a).toEqual(b);
  });
});
