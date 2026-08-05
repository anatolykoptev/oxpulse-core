/**
 * workspace-linkage.test.ts — assert mesh-core is built against the identity in
 * THIS repo, not one downloaded from npm.
 *
 * WHY THIS EXISTS
 * ---------------
 * `packages/mesh-core` declares `@oxpulse/identity` as a plain semver range
 * (`^0.1.x`), not the `workspace:` protocol. pnpm 10 defaults
 * `linkWorkspacePackages` to false, so a plain range resolves from the
 * REGISTRY. For the whole of the 2026-08-04 fix arc that is exactly what
 * happened: every gate ran mesh-core against `@oxpulse/identity@0.1.1` from
 * npm while `packages/identity` sat at 0.1.5 — four versions and two
 * identity-keystore changes ahead. Consumers of mesh-core got 0.1.5. We tested
 * a pairing we never shipped and shipped a pairing we never tested (#85).
 *
 * Nothing failed. That is the point: the divergence is silent by construction,
 * because both halves work fine on their own.
 *
 * `pnpm-workspace.yaml` now sets `linkWorkspacePackages: true`, but that config
 * alone cannot be trusted to hold:
 *
 *   - It only links while the workspace version still SATISFIES the declared
 *     range. The day `packages/identity` becomes 0.2.0, `^0.1.0` stops
 *     matching and pnpm silently reverts to fetching from npm. No error, no
 *     diff, nothing to notice.
 *   - The same keys in `.npmrc` are IGNORED by pnpm 10, which moved its
 *     settings into `pnpm-workspace.yaml`. A fix applied there looks applied
 *     and does nothing.
 *
 * So the rule is asserted rather than configured. This compares resolved
 * REAL PATHS, not versions: a version check would pass whenever the registry
 * happened to serve a matching number, which is the failure it must catch.
 */
import { describe, it, expect } from 'vitest';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

describe('workspace linkage', () => {
  it('resolves @oxpulse/identity to packages/identity, not to a registry download', () => {
    const linkedPath = fileURLToPath(new URL('../../node_modules/@oxpulse/identity', import.meta.url));
    const workspacePath = fileURLToPath(new URL('../../../identity', import.meta.url));

    let resolved: string;
    try {
      resolved = realpathSync(linkedPath);
    } catch {
      throw new Error(
        `@oxpulse/identity is not present under packages/mesh-core/node_modules — run pnpm install (looked at ${linkedPath})`,
      );
    }
    const workspace = realpathSync(workspacePath);

    expect(
      resolved,
      `mesh-core resolved @oxpulse/identity to a REGISTRY copy (${resolved}) instead of the workspace package (${workspace}). ` +
        'Every gate is now validating a pairing we do not ship — see issue #85. ' +
        'Check linkWorkspacePackages in pnpm-workspace.yaml, and whether packages/identity still satisfies the range in packages/mesh-core/package.json.',
    ).toBe(workspace);
  });
});
