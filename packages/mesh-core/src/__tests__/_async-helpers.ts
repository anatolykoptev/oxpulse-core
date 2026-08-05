/**
 * _async-helpers.ts — deterministic async-settle primitives for mesh-core tests.
 *
 * Replaces the fixed wall-clock `drain()` (N microtasks + a 50ms `setTimeout`)
 * that asserted on unsettled async state under box load (issue #58). Under load
 * the handshake had not settled when the assertion ran, and whichever step
 * observed the incomplete state first was what failed — hence the shifting
 * failure signatures.
 *
 * `waitFor` polls a condition, draining microtasks and waking early on
 * handshake state-change events, with a bounded wall-clock timeout. A slow box
 * costs latency (we keep waiting up to `timeout`), not a false red. If the
 * condition never holds it throws a message naming WHAT never became true, so
 * the test still goes red for the right reason.
 *
 * `flushMicrotasks` is a pure microtask drain (no wall-clock sleep) for chains
 * that are entirely microtask-based and therefore deterministic.
 *
 * IMPORTANT: `waitFor` WAITS FOR A PRECONDITION and then the caller asserts
 * once. It is NOT a retry loop around an assertion — do not use it to re-run an
 * assertion until it passes; use it to wait until the observable state the
 * assertion reads has actually settled.
 */
import { onHandshakeStateChange } from '../transport.js';

/**
 * Real timer and clock, captured at module load before any test body can call
 * `vi.useFakeTimers()`.
 *
 * `waitFor` checks its deadline only BEFORE awaiting the wake promise, so it
 * has TWO ways to wait forever, and both must be closed:
 *
 *   - a faked `setTimeout` that is never advanced means the wake promise never
 *     settles, so the deadline is never re-reached;
 *   - a faked `realNow()` means the deadline never ARRIVES, however
 *     real the timer is.
 *
 * An earlier version captured only `setTimeout` and claimed that made hanging
 * impossible. Review falsified it: `vi.useFakeTimers()` with no `toFake` list
 * fakes `performance` too, and the wait still never returned. Both are captured
 * now, which is what that claim actually required.
 *
 * Measured, so as not to overstate it in the other direction: without the clock
 * capture the test does not hang forever — vitest's own 5s per-test timeout
 * ends it. What is lost is the DIAGNOSTIC. The failure reads
 *
 *     Error: Test timed out in 5000ms.
 *
 * instead of
 *
 *     waitFor: <what> never became true within 300ms
 *
 * which is the entire reason this helper exists: #58 was hard to diagnose
 * precisely because the failure never said what had not settled.
 *
 * Caveat, currently unreachable: imports are evaluated before test bodies, so
 * this beats `beforeEach`, but vitest `setupFiles` run BEFORE test-file imports.
 * A setup file calling `vi.useFakeTimers()` at top level would be captured here
 * instead. `packages/mesh-core/vitest.config.ts` declares no `setupFiles`;
 * adding one that fakes timers would reopen this.
 */
const realSetTimeout: typeof globalThis.setTimeout = globalThis.setTimeout.bind(globalThis);
const realNow: () => number = performance.now.bind(performance);

/**
 * Wait until `predicate` returns true.
 *
 * Drives the wait by (a) draining microtasks, (b) waking early when the
 * transport emits a handshake state-change event (verdict/SAS transition), and
 * (c) a short real-timer fallback — so it is fast in the common case and
 * correct when the condition is not handshake-state-driven. The wall-clock
 * `timeout` is a safety bound only; the condition is what we wait on.
 *
 * Uses `realNow()` (not `Date.now()`) for the deadline so it is robust
 * in tests that fake `Date`/`setInterval` but leave `performance` and
 * `setTimeout` real.
 */
export async function waitFor(
  predicate: () => boolean,
  description: string,
  { timeout = 2000, interval = 5 }: { timeout?: number; interval?: number } = {},
): Promise<void> {
  const deadline = realNow() + timeout;
  let resolveWake: () => void = () => {};
  const unsub = onHandshakeStateChange(() => resolveWake());
  try {
    for (;;) {
      if (predicate()) return;
      if (realNow() >= deadline) {
        throw new Error(`waitFor: ${description} never became true within ${timeout}ms`);
      }
      // Drain a batch of microtasks — the mocked crypto is microtask-based, so
      // this alone settles most handshake state without any wall-clock wait.
      for (let i = 0; i < 64; i++) await Promise.resolve();
      if (predicate()) return;
      if (realNow() >= deadline) {
        throw new Error(`waitFor: ${description} never became true within ${timeout}ms`);
      }
      // Wait for either a handshake state-change event or a short real timer.
      await new Promise<void>((resolve) => {
        resolveWake = resolve;
        // realSetTimeout, not setTimeout — see the note at the top of this file.
        realSetTimeout(resolve, interval);
      });
    }
  } finally {
    unsub();
  }
}

/**
 * Drain `n` microtask turns with no wall-clock sleep. Use for purely
 * microtask-based async chains (e.g. a single fire-and-forget `readMessage`
 * that throws and is dropped) where there is no positive observable to wait on
 * and the chain is deterministic.
 */
export async function flushMicrotasks(n = 64): Promise<void> {
  for (let i = 0; i < n; i++) await Promise.resolve();
}
