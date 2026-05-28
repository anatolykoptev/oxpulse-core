# Contributing

## Commits

This repo uses [Conventional Commits](https://www.conventionalcommits.org/).

Commit scopes: `feat`, `fix`, `chore`, `docs`, `refactor`. Body explains WHY (the diff shows what).

## Releasing packages

This repo uses [changesets](https://github.com/changesets/changesets) for version + changelog automation of `@oxpulse/identity` and `@oxpulse/mesh-core`.

> **Current state**: both packages are `"private": true` — pre-publish. `changeset publish` is a no-op until the `private: true` flags are removed (separate PR after operator signs off on first npm release). The NPM_TOKEN secret also needs to be configured on the repo before the publish step does anything.

### When opening a feature PR

If your change touches `@oxpulse/identity` or `@oxpulse/mesh-core` source, record the intent:

```bash
pnpm changeset
```

Pick the affected packages, the SemVer bump (patch/minor/major), and write a short summary. This creates `.changeset/<random>.md` which **must** be committed to the PR.

The `changeset-required` CI check enforces this on every PR targeting `main`.

### When the change does NOT need a changeset

For pure docs, CI, tests on internal-only code, or infra-only changes — apply the `skip-changeset` PR label OR include `[no-changeset]` in the PR title.

### Release flow

1. Merge feature PR → `main`.
2. `release.yml` GHA runs on `main` push. If any `.changeset/*.md` accumulated, it opens a "chore(release): version packages" PR that:
   - Runs `changeset version` (bumps package versions, rewrites per-package CHANGELOG.md, consumes the changesets)
   - Updates `pnpm-lock.yaml`
3. Operator reviews the rollup PR and merges to `main`.
4. On the subsequent `main` push, `release.yml` calls `pnpm changeset:publish` which runs `npm publish` for each bumped package (requires `private: true` removed + `NPM_TOKEN` repo secret set).

### What goes inside a changeset

`.md` file with YAML frontmatter listing packages + bump levels. Body is the human-readable summary for the CHANGELOG.

Example:

```markdown
---
'@oxpulse/identity': minor
'@oxpulse/mesh-core': patch
---

Add Ed25519 key rotation API — devices can now rotate their long-term
identity key without re-registering. mesh-core patch for updated identity dep.
```

### Workspace-internal deps

`@oxpulse/mesh-core` depends on `@oxpulse/identity: workspace:*`. A minor bump of `@oxpulse/identity` auto-triggers a patch bump of `@oxpulse/mesh-core` per `updateInternalDependencies: "patch"` in `.changeset/config.json`. You do not need to write a separate changeset for the dependent package.
