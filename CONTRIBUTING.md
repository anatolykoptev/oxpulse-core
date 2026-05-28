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

**Reviewer enforces** the changeset presence during code review. Per `~/CLAUDE.md` "GHA blocked", there is no CI gate — code-quality-reviewer checks for `.changeset/*.md` in every PR touching publishable source. Block merge if missing (unless `[no-changeset]` is in the PR title).

### When the change does NOT need a changeset

For pure docs, CI, tests on internal-only code, or infra-only changes — include `[no-changeset]` in the PR title.

### Release flow (manual operator)

1. Merge feature PRs → `main`.
2. When ready to cut a release, on a clean `main` checkout:
   ```bash
   pnpm changeset:version    # bumps versions, rewrites CHANGELOG.md, consumes changesets, syncs lockfile
   git add -A && git commit -m "chore(release): version packages"
   git push origin main
   ```
3. After private flags removed + NPM creds configured, publish:
   ```bash
   pnpm install --frozen-lockfile
   pnpm changeset:publish    # npm publishes each bumped package + creates git tags
   git push --follow-tags
   ```

NOTE: GHA templates (release.yml + changeset-required.yml) lived in earlier commits of this branch before being removed per `~/CLAUDE.md` "GHA blocked" rule. They can be revived from history when cloud CI budget is restored.

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
