# Contributing

## Commits

This repo uses [Conventional Commits](https://www.conventionalcommits.org/).

Commit types: `feat`, `fix`, `perf`, `refactor`, `docs`, `deps`, `revert`, `chore`, `ci`, `test`, `build`, `style`. Body explains WHY (the diff shows what).

A breaking change is marked with `!` **after the scope**, not after the type — `feat(mesh-core)!:`, never `feat!(mesh-core):`. The malformed form is not recognised, so the release is cut as an ordinary patch and the breaking change never reaches the changelog.

Note that squashing a **single-commit** PR uses the commit message, not the PR title. If they differ, pass the intended message explicitly:

```sh
gh pr merge <n> --squash --subject '<type>(<scope>): ...' --body-file <file>
```

## Public API changes

Both packages are published to npm, so their callers live in **other repositories** and no repo-scoped search can see them. Every tool — grep, a call-graph query, a dead-code score — will confidently report "zero callers" for an export whose only consumers are downstream.

That is not hypothetical. `Inbox.evictExcess` and `Spool.evictExcess` were deleted as dead code on exactly that evidence and broke oxpulse-chat's periodic eviction sweep. The tools were right about this repository and wrong about the world.

So:

- **`packages/mesh-core/src/__tests__/public-api-surface.test.ts` is the contract.** Removing or renaming a listed export turns it red. Adding is free — the assertions are subset checks.
- **Re-approving a removal means editing that expected list in the same commit**, which is what makes the removal visible in review.
- **Mark the commit breaking** — `fix(mesh-core)!:` or a `BREAKING CHANGE:` footer. At 0.x, release-please then cuts a **minor**, so a consumer on `^0.x.y` does not silently pick up a removal in a patch. This is the deliberate policy decision from #60: at 0.x semver permits removing public API in a patch, which is exactly why it is easy to keep doing by accident.

Deprecating for one minor before removing is welcome but not required at 0.x.

## CI

Two workflows gate this repo. Both run on `ubuntu-24.04-arm` — free and unlimited for public repos, and arm64 matches the production box.

**[`preflight.yml`](.github/workflows/preflight.yml)** — every PR and every push to `main`: install, build, typecheck, test, in that order. `main` requires it to pass, requires the branch to be up to date first, and allows no force-push or deletion.

Build runs **before** typecheck deliberately. `packages/mesh-core` imports `@oxpulse/identity`, which is linked from the workspace rather than downloaded; the workspace checkout has no compiled `dist/` with `.d.ts` until it is built, so typechecking first fails with `Cannot find module`.

**[`nightly.yml`](.github/workflows/nightly.yml)** — the two things a per-PR gate structurally cannot catch:

- **Nondeterminism.** preflight runs the suite once, so it cannot tell a passing suite from one that passes 80% of the time. The nightly runs it 10x and fails if *any* run fails. This exists because #58 was a handshake flake whose rate tracked box load — roughly 1 in 5 runs idle, 2 in 3 under load — and every PR in the 2026-08-04 fix arc passed the single-run gate regardless.
- **Newly-disclosed advisories.** A CVE published today makes an unchanged tree vulnerable and no `pull_request` event will ever fire for it. Gated on **runtime** dependencies at high/critical only: those are what a consumer installing the package actually receives, and a dev-only advisory must not be able to block a release.

GitHub silently disables scheduled workflows in a repo with no pushes for 60 days, and a dead nightly reads exactly like a passing one. Before trusting a quiet week, check `gh run list --workflow=nightly.yml` has a run newer than 48h.

## Workspace linking

`packages/mesh-core` depends on `@oxpulse/identity`. pnpm 10 defaults `linkWorkspacePackages` to **false**, so a plain semver range resolves from the registry rather than from this repo — which is what happened, silently, for the whole of the 2026-08-04 arc (#85). `pnpm-workspace.yaml` now enables linking, and `workspace-linkage.test.ts` asserts it, because the config alone stops working the moment `packages/identity` no longer satisfies the declared range.

These settings belong in `pnpm-workspace.yaml` and **not** `.npmrc` — pnpm 10 moved its own settings into that file and ignores the same keys in `.npmrc`, so a fix applied there looks applied and does nothing.

## Releasing packages

[release-please](https://github.com/googleapis/release-please) manages versions, changelogs and tags for `@oxpulse/identity` and `@oxpulse/mesh-core`, and [`release-please.yml`](.github/workflows/release-please.yml) publishes to npm.

### How it works

Write a good conventional commit; that is the whole of the author's job. On every push to `main`, release-please opens or updates a `chore(main): release <package> X.Y.Z` PR per package, bumping that package's version and prepending a generated CHANGELOG entry.

Merging a release PR creates the `<package>-vX.Y.Z` tag and a GitHub Release, and the gated `publish` job then pushes that version to npm via **OIDC trusted publishing** — there is no `NPM_TOKEN`.

Never create a release tag by hand: it desyncs `.release-please-manifest.json`.

### The acceptance evidence for a release is the registry, not a green run

This file used to state that both packages were `private: true` and that no publish step was needed. That stopped being true when `private: true` was dropped and oxpulse-chat was pointed at npm ranges — but the sentence stayed, and no publish step was ever added.

The result, measured on 2026-08-05: mesh-core had been released **thirteen** times (0.1.3 … 0.1.15) with a tag and a GitHub Release for each, while npm still served 0.1.2 as `latest`. Every one of those runs was green, because a release that publishes nothing is exactly as green as one that publishes correctly when nothing checks.

The workflow now asserts the registry actually serves the version before the run can pass. Those stranded versions are not published retroactively and never will be; their GitHub Releases are annotated to say so (#76).

### Two things that bind outside this repo

- **npm trusted publishing binds package -> repo -> workflow FILENAME.** Renaming `release-please.yml` breaks publishing until the npm side is updated. That binding is invisible from this repo and is the most common way the setup silently stops working.
- **Release PRs are opened by the krolik-release-bot GitHub App**, not `GITHUB_TOKEN`. GitHub suppresses workflow runs on PRs opened by `GITHUB_TOKEN`, so those release PRs sat unapproved and were merged on a hand-approved run or on nothing at all. An App-opened PR gets CI normally, which is what lets branch protection gate the artifact that ships.

### Commit types in the changelog

`feat` -> Added, `fix` -> Fixed, `perf` -> Performance, `refactor` -> Changed, `docs` -> Documentation, `deps` -> Dependencies, `revert` -> Reverts. `chore`, `ci`, `test`, `build` and `style` are valid types but hidden from the changelog.

### Cross-package dependencies

release-please tracks each package independently — releasing `@oxpulse/identity` does not release `@oxpulse/mesh-core`. `packages/mesh-core` declares `@oxpulse/identity` as a published semver range, so when identity gains something mesh-core needs, widen that range in the same PR.
