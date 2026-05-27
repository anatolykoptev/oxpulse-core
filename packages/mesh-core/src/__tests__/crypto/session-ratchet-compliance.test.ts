/**
 * Compliance tests: snapshotRecvChain and fromCompromisedState must not
 * appear in non-test production code (Fix 2.2 — @internal enforcement).
 *
 * These methods expose chain-key material and are intentionally @internal.
 * This grep-based test catches accidental production use during CI.
 *
 * Scope: entire monorepo (all packages + web/src) excluding __tests__,
 * node_modules, dist, .svelte-kit, and the declaration file itself.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Walk `dir` recursively, collecting .ts and .svelte source files.
 * Skips: __tests__, node_modules, dist, .svelte-kit, .git, generated files.
 * Excludes session-ratchet.ts itself (declaration site).
 */
function walkSrc(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    if (
      e === 'node_modules' ||
      e === 'dist' ||
      e === '.svelte-kit' ||
      e === '.git'
    ) continue;
    const p = join(dir, e);
    const stat = statSync(p);
    if (stat.isDirectory()) {
      if (e === '__tests__') continue;
      walkSrc(p, out);
    } else if (
      (p.endsWith('.ts') || p.endsWith('.svelte')) &&
      !p.endsWith('.test.ts') &&
      !p.includes('.generated.') &&
      // Exclude declaration site (use endsWith for tightness — avoids false-exclude of my-session-ratchet.ts)
      !p.endsWith('/crypto/session-ratchet.ts')
    ) {
      out.push(p);
    }
  }
  return out;
}

// Five levels up from packages/mesh-core/src/__tests__/crypto/ = repo root
const repoRoot = join(import.meta.dirname, '../../../../../');

describe('RatchetSession crypto-internal compliance — repo-wide', () => {
  it('snapshotRecvChain not referenced outside __tests__', () => {
    const files = walkSrc(repoRoot);
    const hits = files.filter(f => readFileSync(f, 'utf8').includes('snapshotRecvChain'));
    expect(hits, `Production code calls snapshotRecvChain: ${hits.join('\n')}`).toEqual([]);
  });

  it('fromCompromisedState not referenced outside __tests__', () => {
    const files = walkSrc(repoRoot);
    const hits = files.filter(f => readFileSync(f, 'utf8').includes('fromCompromisedState'));
    expect(hits, `Production code calls fromCompromisedState: ${hits.join('\n')}`).toEqual([]);
  });
});
