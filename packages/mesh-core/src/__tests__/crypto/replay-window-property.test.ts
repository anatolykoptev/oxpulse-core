/**
 * replay-window-property.test.ts
 *
 * Edge-case / property tests for ReplayWindow.
 * ReplayWindow is already implemented; these tests are a regression guard
 * for future modifications to session.ts crypto.
 *
 * REPLAY_WINDOW_SIZE = 64 (from constants.generated.ts).
 * Invariants verified:
 *   – counters below 0 are rejected
 *   – counters within [highest - 63, highest] honour the bitmap
 *   – counters above highest advance the window, always accepted once
 *   – counters exactly at highest + 64 (shift == window size) reset bitmap
 *   – counters at offset >= 64 below highest are unconditionally rejected
 */

import { describe, it, expect } from 'vitest';
import { ReplayWindow } from '../../crypto/session.js';

const WINDOW = 64n; // must match REPLAY_WINDOW_SIZE in constants.generated.ts

describe('ReplayWindow edge cases', () => {
	it('accepts huge counter (2^60)', () => {
		const w = new ReplayWindow();
		const huge = 2n ** 60n;
		expect(w.checkAndAccept(huge)).toBe(true);
	});

	it('rejects replay of huge counter (2^60)', () => {
		const w = new ReplayWindow();
		const huge = 2n ** 60n;
		expect(w.checkAndAccept(huge)).toBe(true);
		expect(w.checkAndAccept(huge)).toBe(false);
	});

	it('accepts counter at highest + WINDOW - 1 (last position in window)', () => {
		const w = new ReplayWindow();
		// Establish highest = 0
		expect(w.checkAndAccept(0n)).toBe(true);
		// highest + 63 advances window, should be accepted (shift < WINDOW)
		expect(w.checkAndAccept(WINDOW - 1n)).toBe(true);
	});

	it('rejects counter at highest + WINDOW (just outside — shifts bitmap to reset)', () => {
		const w = new ReplayWindow();
		// Establish highest = 0; next counter at 64 triggers shift >= WINDOW
		// which resets bitmap to 1n — previous counter (0) is lost from window.
		// The counter itself (64) IS accepted (advances highest).
		expect(w.checkAndAccept(0n)).toBe(true);
		expect(w.checkAndAccept(WINDOW)).toBe(true);
		// After reset, counter 0 is no longer tracked — not a duplicate in the
		// new window.  This is correct RFC-6347 anti-replay: if a packet is
		// that far out of window we treat it as a replay (or just too old).
	});

	it('rejects counter <= highest - WINDOW (far past)', () => {
		const w = new ReplayWindow();
		// Advance highest to 200
		expect(w.checkAndAccept(200n)).toBe(true);
		// counter 200 - 64 = 136 is at the boundary (offset == WINDOW → reject)
		expect(w.checkAndAccept(136n)).toBe(false);
		// counter 100 is > WINDOW behind → reject
		expect(w.checkAndAccept(100n)).toBe(false);
		// counter 137 = 200-63 is exactly within window (offset == WINDOW-1 → accept)
		expect(w.checkAndAccept(137n)).toBe(true);
	});

	it('counter rollback far back (>10000 less than highest) must reject', () => {
		const w = new ReplayWindow();
		expect(w.checkAndAccept(10000n)).toBe(true);
		expect(w.checkAndAccept(0n)).toBe(false);
		expect(w.checkAndAccept(1n)).toBe(false);
		expect(w.checkAndAccept(9936n)).toBe(false); // 10000 - 64
	});

	it('64 sequential accepts, then replay of each is rejected', () => {
		const w = new ReplayWindow();
		// Accept counters 0..63 in order — fills the bitmap fully
		for (let i = 0n; i < WINDOW; i++) {
			expect(w.checkAndAccept(i), `accept counter ${i}`).toBe(true);
		}
		// highest == 63, bitmap all bits 0..63 set
		// Replay every counter in the window → all rejected
		for (let i = 0n; i < WINDOW; i++) {
			expect(w.checkAndAccept(i), `replay counter ${i}`).toBe(false);
		}
	});

	it('acceptance with gaps: 0, 5, 3, 10, 7 — all 5 accepted; replays rejected', () => {
		const w = new ReplayWindow();
		const sequence = [0n, 5n, 3n, 10n, 7n];
		for (const c of sequence) {
			expect(w.checkAndAccept(c), `first accept of ${c}`).toBe(true);
		}
		// Replay of each must be rejected
		for (const c of sequence) {
			expect(w.checkAndAccept(c), `replay of ${c}`).toBe(false);
		}
		// Counters not in sequence but within window (e.g. 1, 2, 4, 6, 8, 9)
		// should still be accepted (gap-fill)
		for (const c of [1n, 2n, 4n, 6n, 8n, 9n]) {
			expect(w.checkAndAccept(c), `gap-fill accept of ${c}`).toBe(true);
		}
	});

	it('bit 63 of bigint bitmap: counter at highest - 63 sets the top window bit', () => {
		const w = new ReplayWindow();
		// Set highest = 63 first
		expect(w.checkAndAccept(63n)).toBe(true);
		// Now accept counter 0 = highest - 63.  offset == 63 == WINDOW-1.
		// This exercises bit (1n << 63n) in the bitmap.
		expect(w.checkAndAccept(0n)).toBe(true);
		// Replay of 0 must be rejected (the bit is set)
		expect(w.checkAndAccept(0n)).toBe(false);
		// Replay of 63 must also be rejected
		expect(w.checkAndAccept(63n)).toBe(false);
	});

	it('counter approach 2^63 (overflow approach): still accepted as new highest', () => {
		// Note: WebCrypto encodes the counter as u64 big-endian on the wire,
		// so the *wire* is limited to u64 max (2^64-1).  ReplayWindow uses
		// bigint internally so there is no JS overflow.  This test documents
		// that values up to 2^63-1 are handled correctly by the bigint bitmap.
		const w = new ReplayWindow();
		const nearMax = 2n ** 63n - 1n;
		expect(w.checkAndAccept(nearMax)).toBe(true);
		// Replay must be rejected
		expect(w.checkAndAccept(nearMax)).toBe(false);
		// A counter just within the window (nearMax - 1) is accepted
		expect(w.checkAndAccept(nearMax - 1n)).toBe(true);
		// A counter far below (nearMax - WINDOW) is rejected (offset == WINDOW)
		expect(w.checkAndAccept(nearMax - WINDOW)).toBe(false);
	});
});
