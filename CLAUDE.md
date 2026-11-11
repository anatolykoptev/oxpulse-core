# CLAUDE.md

Notes for coding agents working in oxpulse-core: a pnpm workspace of two npm packages,
`@oxpulse/identity` (long-term Ed25519 device identity in IndexedDB) and `@oxpulse/mesh-core`
(Bluetooth LE offline mesh transport with a Noise XX + ML-KEM-768 handshake). Every document is
indexed in [docs/INDEX.md](docs/INDEX.md).

## Layout

- `packages/identity/src`: identity, key wrapping (AES-KW), IndexedDB stores, X25519 and room-host
  seeds. Tests in `src/__tests__`.
- `packages/mesh-core/src`: transport, handshake and crypto (`crypto/`), framing, router, outbox,
  mailbox, channels and the Capacitor glue (`native/`). Tests in `src/__tests__`.
- Each package has its own README and its own `CHANGELOG.md` (written by release-please). The root
  [CHANGELOG.md](CHANGELOG.md) only points to them.
- `packages/mesh-core/src/constants.generated.ts` is marked `@generated` and its generator is not in
  this repository (the GATT UUIDs and frame constants are shared with the native side); do not edit
  it by hand.

## Gate

CI (`.github/workflows/preflight.yml`, job `preflight`) runs in this order on Node 22 and pnpm 10:

```sh
pnpm install --frozen-lockfile
pnpm run build
pnpm run typecheck
pnpm -r run test -- --run --no-file-parallelism
```

Build comes before typecheck on purpose: `mesh-core` imports `@oxpulse/identity` through the
workspace link, which has no `.d.ts` until it is compiled. A docs-only PR (Markdown, `docs/`,
licence, issue and PR templates) skips that job through the `docs-scope` job in the same workflow;
that block is canonical across the fleet and compared byte for byte, so do not edit it here.
`nightly.yml` repeats the suite ten times to catch flakes and audits runtime dependencies.

## Invariants that are easy to break

- **Both packages are published to npm; their callers live in other repositories.** A repo-wide
  search that finds no caller proves nothing. `packages/mesh-core/src/__tests__/public-api-surface.test.ts`
  is the contract: removing or renaming a listed export must be a deliberate, breaking commit
  (`fix(mesh-core)!:`, with the `!` after the scope).
- **Workspace linking lives in `pnpm-workspace.yaml`, not `.npmrc`.** pnpm 10 ignores those keys in
  `.npmrc`. `workspace-linkage.test.ts` asserts the link; keep the declared range of
  `@oxpulse/identity` in `packages/mesh-core/package.json` satisfiable by the workspace version.
- **Tests run with `--no-file-parallelism`** and in a Node environment, because WebCrypto and
  fake-indexeddb state is shared between files.
- **The transport crypto is fixed: a distinct AEAD key per frame, derived from a chain key.** Do not change the AEAD
  construction, the nonce layout (direction byte plus 64-bit counter), the 64-frame replay window
  or the TOFU plus SAS peer acceptance (`sendFrame` must keep refusing unaccepted peers) without an
  issue and a crypto review.
- **Raw secrets stay behind `OpaquePrivateKey`.** Identity secrets are exported only through the
  audited paths; never log or format a seed or key into an error message.
- **Versions come from release-please** (Conventional Commits, one release PR per package). Never
  tag, or edit a version, `.release-please-manifest.json` or a package `CHANGELOG.md` by hand. npm
  publishing uses OIDC trusted publishing bound to the workflow file name `release-please.yml`;
  do not rename it.
- **The licence is AGPL-3.0-or-later.** Do not change `LICENSE` or the `license` fields.
- **This repository is public.** No hostnames, operator paths, account names, tokens or personal
  data in any tracked file, tests and fixtures included.
