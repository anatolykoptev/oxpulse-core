/**
 * no-wall-clock-sleep.test.ts — no test may sleep on the wall clock.
 *
 * WHY THIS EXISTS
 * ---------------
 * Issue #58 was a handshake flake whose rate tracked box load: the tests drove
 * an async handshake and then asserted, with a `drain()` helper in between that
 * slept a fixed 50 ms. Under load the handshake had not settled when the
 * assertion ran, and whichever step observed the incomplete state first is what
 * failed — one root cause presenting as five different signatures.
 *
 * #81 removed that helper from every file. It came back TWICE within hours, in
 * two brand-new test files (#80's and #82's), both written before #81 merged
 * and both carrying a verbatim copy.
 *
 * That is the shape of the problem worth naming: the sweep was not leaking
 * because a search missed something. It was complete when written, and a copy
 * landed after the search ran. No amount of care during the sweep prevents the
 * next one — only something that fails on the pattern does.
 *
 * WHAT TO DO INSTEAD
 * ------------------
 * Wait on the condition the assertion actually reads:
 *
 *     await waitFor(() => getPendingHandshakes().length > 0, 'handshake to complete');
 *
 * or `flushMicrotasks()` when the chain is purely microtask-based, or fake
 * timers when the test is about elapsed time itself. `waitFor` fails with a
 * message naming WHAT never became true, so a slow box costs latency rather
 * than a false red.
 *
 * `_async-helpers.ts` is not matched here: it is not a `.test.ts`, and its one
 * real timer is a bounded poll fallback, not a sleep.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** `new Promise(r => setTimeout(r, N))` and its parenthesised variants. */
const WALL_CLOCK_SLEEP = /new\s+Promise\s*\(\s*\(?\s*\w*\s*\)?\s*=>\s*setTimeout\s*\(/;

describe('test hygiene', () => {
  it('no test file sleeps on the wall clock (issue #58)', () => {
    const dir = fileURLToPath(new URL('.', import.meta.url));
    const offenders: string[] = [];

    for (const name of readdirSync(dir)) {
      if (!name.endsWith('.test.ts')) continue;
      const lines = readFileSync(new URL(name, new URL('.', import.meta.url)), 'utf8').split('\n');
      lines.forEach((line, i) => {
        // Skip comments — several files legitimately DISCUSS setTimeout.
        const code = line.replace(/^\s*(\/\/|\*|\/\*).*$/, '');
        if (WALL_CLOCK_SLEEP.test(code)) offenders.push(`${name}:${i + 1}`);
      });
    }

    expect(
      offenders,
      `these tests sleep on the wall clock instead of waiting on a condition, which is what made ` +
        `the handshake suite flake under load (#58):\n  ${offenders.join('\n  ')}\n` +
        `Use waitFor(predicate, description) or flushMicrotasks() from ./_async-helpers.js instead.`,
    ).toEqual([]);
  });
});
