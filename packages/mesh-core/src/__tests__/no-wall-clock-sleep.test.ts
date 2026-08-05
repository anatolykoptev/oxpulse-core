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
 * two brand-new test files (#80's and #87's), both written before #81 merged
 * and both carrying a verbatim copy.
 *
 * That is the shape worth naming: the sweep was not leaking because a search
 * missed something. It was complete when written, and copies landed after the
 * search ran. No amount of care during the next sweep prevents the one after
 * it — only something that fails on the pattern does.
 *
 * WHAT IT ACTUALLY CHECKS
 * -----------------------
 * The rule is deliberately blunt: **executable code in a test file may not
 * mention `setTimeout` at all**, and may not import `node:timers/promises`.
 *
 * The first version of this guard matched one syntactic shape,
 * `new Promise(r => setTimeout(r, N))`, and review established that it missed
 * every other spelling of the same sleep — a `function` callback, a block-body
 * arrow, a named `sleep()` helper, a two-line split, `setTimeoutPromise(50)`.
 * A guard believed stronger than it is is worse than a known-partial one, so
 * the rule is now the broad one it should have been: after #81 there are zero
 * legitimate uses of `setTimeout` in a test, so any use is worth a conversation
 * rather than a regex duel over which spellings count.
 *
 * If a test genuinely needs it (scheduling something under fake timers, say),
 * add it to ALLOWED below with a reason. That friction is the point: it puts
 * the decision in a diff where a reviewer sees it.
 *
 * WHAT TO DO INSTEAD
 * ------------------
 *     await waitFor(() => getPendingHandshakes().length > 0, 'handshake to complete');
 *
 * or `flushMicrotasks()` when the chain is purely microtask-based, or fake
 * timers when the test is about elapsed time itself. `waitFor` fails with a
 * message naming WHAT never became true, so a slow box costs latency rather
 * than a false red.
 *
 * `_async-helpers.ts` is not scanned: it is not a `.test.ts`, and its one real
 * timer is a bounded poll fallback rather than a sleep.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Files permitted to mention setTimeout in executable code, each with the
 * reason. Empty today — added entries should be rare and argued for.
 */
const ALLOWED = new Map<string, string>([
  [
    'no-wall-clock-sleep.test.ts',
    'the detector necessarily contains the literal it detects, in its own matching regex',
  ],
]);

/**
 * Strip comments and string literals before scanning.
 *
 * Both matter. Several files legitimately DISCUSS setTimeout in prose — the
 * comments #81 added explaining why timers are faked the way they are would
 * otherwise trip this. And `vi.useFakeTimers({ toFake: ['setTimeout'] })` names
 * it inside a string literal, which is a legitimate use that must not trip it
 * either. Stripping only line-leading comments (the first version) handled
 * neither a trailing comment after code nor a string.
 */
function executableCode(src: string): string {
  const blank = (m: string): string => m.replace(/[^\n]/g, ' ');
  return src
    // Blank comments IN PLACE rather than collapsing them: replacing a
    // multi-line block with a single space shifts every subsequent line, so the
    // file:line in a failure report would point at the wrong line — which is
    // most of what makes a guard like this usable.
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/\/\/[^\n]*/g, blank)
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
}

/** Every `*.test.ts` under this directory, including subdirectories. */
function testFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(join(dir, entry.name), rel);
      else if (entry.name.endsWith('.test.ts')) out.push(rel);
    }
  };
  walk(root, '');
  return out;
}

describe('test hygiene', () => {
  const root = fileURLToPath(new URL('.', import.meta.url));
  const files = testFiles(root);

  it('scans every test file, including subdirectories', () => {
    // The first version used a non-recursive readdirSync and silently skipped
    // crypto/ and mailbox/ — 21 of 58 files, 36% of the suite, outside a fence
    // whose stated purpose was "no test may sleep on the wall clock".
    // A guard that quietly covers part of its stated scope is the failure this
    // whole file exists to prevent, so the coverage is asserted rather than
    // assumed.
    expect(files.some((f) => f.includes('/')), 'no subdirectory test files found — the walk is not recursive').toBe(true);
    expect(files.length, 'suspiciously few test files discovered').toBeGreaterThan(40);
  });

  it('no test file sleeps on the wall clock (issue #58)', () => {
    const offenders: string[] = [];

    for (const rel of files) {
      if (ALLOWED.has(rel)) continue;
      const code = executableCode(readFileSync(join(root, rel), 'utf8'));
      code.split('\n').forEach((line, i) => {
        if (/\bsetTimeout\b/.test(line) || /timers\/promises/.test(line)) {
          offenders.push(`${rel}:${i + 1}`);
        }
      });
    }

    expect(
      offenders,
      `these tests reach for the wall clock instead of waiting on a condition, which is what made ` +
        `the handshake suite flake under load (#58):\n  ${offenders.join('\n  ')}\n` +
        `Use waitFor(predicate, description) or flushMicrotasks() from ./_async-helpers.js, or fake ` +
        `timers if the test is about elapsed time. If a real setTimeout is genuinely needed, add the ` +
        `file to ALLOWED in this file with a reason.`,
    ).toEqual([]);
  });
});
