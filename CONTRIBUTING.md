# Contributing

## Commits

This repo uses [Conventional Commits](https://www.conventionalcommits.org/).

Commit scopes: `feat`, `fix`, `chore`, `docs`, `refactor`. Body explains WHY (the diff shows what).

## Releasing packages

This repo uses [release-please](https://github.com/googleapis/release-please) for automated version + changelog management of `@oxpulse/identity` and `@oxpulse/mesh-core`.

> **Current state**: both packages are `"private": true` — pre-publish. release-please only manages version bumps, CHANGELOG generation, and git tags here; there is no npm publish step yet. Publishing (removing the `private: true` flags + configuring an npm token) is a separate follow-up.

### How it works

You don't need to do anything beyond writing a good conventional commit message. On every push to `main`, [release-please](.github/workflows/release-please.yml) opens or updates a "chore(main): release `<package>` X.Y.Z" pull request per package, bumping that package's `package.json` version and prepending a generated CHANGELOG entry from the commits merged since the last release.

Merging a release PR creates the `<package>-vX.Y.Z` tag and a GitHub Release. Never create a release tag by hand — a manual tag desyncs `.release-please-manifest.json`.

### Commit types that show up in the changelog

`feat` → Added, `fix` → Fixed, `perf` → Performance, `refactor` → Changed, `docs` → Documentation, `deps` → Dependencies, `revert` → Reverts. `chore`/`ci`/`test`/`build`/`style` are valid commit types but hidden from the changelog.

### Workspace-internal deps

`@oxpulse/mesh-core` depends on `@oxpulse/identity: workspace:*`. release-please tracks each package independently — bumping `@oxpulse/identity` does not automatically release `@oxpulse/mesh-core`; bump it explicitly in the same PR if the dependency needs to move too.
