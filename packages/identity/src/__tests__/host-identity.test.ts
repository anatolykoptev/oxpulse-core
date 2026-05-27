import { describe, it, expect } from 'vitest';
import { generateHostKeypair, signHostAction, buildPinMintPayload } from '../host-identity.js';
import { toBase64url } from '../base64url.js';

describe('host-identity', () => {
    it('generateHostKeypair returns 32-byte base64url pubkey', async () => {
        const { publicKeyB64 } = await generateHostKeypair();
        // base64url decode and check length
        const padded = publicKeyB64.replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(padded + '='.repeat((4 - padded.length % 4) % 4));
        expect(binary.length).toBe(32);
    });

    it('signHostAction returns 64-byte base64url signature', async () => {
        const kp = await generateHostKeypair();
        const sig = await signHostAction(kp, 'lock:ABCD-1234:1714000000');
        const padded = sig.replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(padded + '='.repeat((4 - padded.length % 4) % 4));
        expect(binary.length).toBe(64);
    });

    it('different keypairs produce different signatures', async () => {
        const kp1 = await generateHostKeypair();
        const kp2 = await generateHostKeypair();
        const sig1 = await signHostAction(kp1, 'lock:ABCD-1234:1714000000');
        const sig2 = await signHostAction(kp2, 'lock:ABCD-1234:1714000000');
        expect(sig1).not.toBe(sig2);
    });
});

describe('buildPinMintPayload', () => {
    it('produces colon-separated format matching kick/lock convention', () => {
        expect(buildPinMintPayload('AAAA-0000C', 1234567890)).toBe('pin-mint:AAAA-0000C:1234567890');
    });

    it('uses integer ts directly (no string coercion drift)', () => {
        expect(buildPinMintPayload('ROOM1234', 0)).toBe('pin-mint:ROOM1234:0');
    });

    it('roomId with dashes preserved verbatim', () => {
        expect(buildPinMintPayload('AB12-CD34', 9999)).toBe('pin-mint:AB12-CD34:9999');
    });
});
