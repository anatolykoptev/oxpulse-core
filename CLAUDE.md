# oxpulse-core — project rules

Complements `~/CLAUDE.md`. Project-specific only.

## Stack

- pnpm 10.28+ workspace
- 2 packages: `@oxpulse/identity` (Ed25519 device identity), `@oxpulse/mesh-core` (BLE/WiFi-Direct mesh)
- TypeScript ESM, vitest. No build for non-publishable code.
- Phase 1 of oxpulse-chat monorepo split (see `/home/krolik/src/oxpulse-chat/docs/superpowers/specs/2026-05-27-monorepo-split-chat-extract.md`).

## Release workflow

This repo uses [changesets](https://github.com/changesets/changesets) for version + changelog automation.

When opening a PR touching `@oxpulse/identity` or `@oxpulse/mesh-core` source:

```bash
pnpm changeset
```

Pick the affected packages + SemVer bump + summary. Commit the resulting `.changeset/<random>.md` with your PR.

The `changeset-required` CI check enforces this on every PR. Bypass via label `skip-changeset` OR `[no-changeset]` in PR title (for docs / CI / non-publishable code).

On `main` merge: `release.yml` opens a "chore(release): version packages" PR via changesets/action. After operator approves + merges, the next `main` push triggers `changeset publish` (no-op while packages are `private: true`; actual `npm publish` runs after the `private: true` flags are flipped).

## Current state

Both packages are `"private": true` — pre-publish. NPM_TOKEN secret needs to be configured + private flags removed before first real publish.

## Commands

```bash
pnpm install
pnpm -r run build
pnpm -r run test
pnpm changeset            # record a version intent
pnpm changeset:status     # show pending changesets
```

## Commit conventions

Conventional + scope: `feat`, `fix`, `chore`, `docs`, `refactor`. Body explains WHY.

## Skipped tests

Three test files are excluded in `packages/mesh-core/vitest.config.ts` pending `@oxpulse/wire-codec@0.3.1` republish (current 0.3.0 dist has `./dicts` import without `.js` extension breaking Node ESM resolver): `wrap.test.ts`, `__tests__/bundle-composer.test.ts`, `__tests__/transport-crypto.test.ts`.
