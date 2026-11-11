# oxpulse-core

Offline-first platform primitives for peer-to-peer and degraded-network apps: a
post-quantum mesh transport and long-term device identity, used across the OxPulse family.

## Packages

| Package | Purpose | Status |
|---|---|---|
| [`@oxpulse/identity`](packages/identity) | Long-term Ed25519 device identity (host + device + room-host seed; IndexedDB-backed) | Pre-1.0 — API stability not yet guaranteed |
| [`@oxpulse/mesh-core`](packages/mesh-core) | Bluetooth LE offline mesh transport (frame, outbox, dedupe, router, peer-registry, GATT channel; Noise-XX + ML-KEM post-quantum handshake) | Pre-1.0 |

## Why a separate package

These primitives are consumed by several independent surfaces (messaging, signaling,
offline transport), so they live in their own package with an independent release cadence.
Downstream apps pin a stable version instead of tracking a larger codebase.

## Layout

```
packages/
  identity/   — Ed25519 device identity, X25519 seed derivation, IndexedDB store
  mesh-core/  — BLE mesh transport, frame codec, outbox, router, mailbox
```

## Build

Node 22 and pnpm 10 (the `packageManager` field pins the exact version):

```bash
pnpm install --frozen-lockfile
pnpm run build        # build before typecheck: mesh-core consumes identity's compiled types
pnpm run typecheck
pnpm -r run test -- --run --no-file-parallelism
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit rules and the release flow.

## Status

Both packages are pre-1.0 and published to npm. Release history is in each package's
`CHANGELOG.md`, indexed from [CHANGELOG.md](CHANGELOG.md).

## License

[AGPL-3.0-or-later](LICENSE). If you embed `@oxpulse/identity` or `@oxpulse/mesh-core` in a
network service, the network service source must be made available under AGPL.
