# oxpulse-core — project rules

Complements `~/CLAUDE.md`. Project-specific only.

## Stack

- pnpm 10.28+ workspace
- 2 packages: `@oxpulse/identity` (Ed25519 device identity), `@oxpulse/mesh-core` (BLE/WiFi-Direct mesh)
- TypeScript ESM, vitest. No build for non-publishable code.
- Phase 1 of oxpulse-chat monorepo split (see `/home/krolik/src/oxpulse-chat/docs/superpowers/specs/2026-05-27-monorepo-split-chat-extract.md`).

## Release workflow (manual — GHA blocked)

This repo uses [changesets](https://github.com/changesets/changesets) CLI for version + changelog automation. **No GitHub Actions** — `~/CLAUDE.md` global rule "GHA blocked. Cloud CI cancelled" applies repo-wide. Operator runs CLI commands locally.

When opening a PR touching `@oxpulse/identity` or `@oxpulse/mesh-core` source:

```bash
pnpm changeset
```

Pick the affected packages + SemVer bump + summary. Commit the resulting `.changeset/<random>.md` with your PR.

**Reviewer enforces** the changeset presence during code review (no CI gate). Bypass via `[no-changeset]` in PR title (for docs / CI / non-publishable code).

Release flow (manual operator):
1. Merge feature PRs → `main`. Each carries a `.changeset/*.md` if it touched publishable code.
2. When ready to cut release (operator decision), on a clean `main` checkout:
   ```bash
   pnpm changeset:version    # bumps versions, rewrites CHANGELOG.md, consumes changesets
   git add -A && git commit -m "chore(release): version packages"
   git push origin main
   ```
3. Then publish (no-op while packages are `private: true`; runs `npm publish` after flags flipped):
   ```bash
   pnpm install --frozen-lockfile
   pnpm changeset:publish    # npm publishes each bumped package + creates git tags
   git push --follow-tags
   ```

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
