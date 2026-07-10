# oxpulse-core

Offline-first platform primitives for peer-to-peer and degraded-network apps: a
post-quantum mesh transport and long-term device identity, used across the OxPulse family.

## Packages

| Package | Purpose | Status |
|---|---|---|
| [`@oxpulse/identity`](packages/identity) | Long-term Ed25519 device identity (host + device + room-host seed; IndexedDB-backed) | Pre-1.0 — API stability not yet guaranteed |
| [`@oxpulse/mesh-core`](packages/mesh-core) | BLE / WiFi-Direct offline mesh transport (frame, outbox, dedupe, router, peer-registry, GATT channel; Noise-XX + ML-KEM post-quantum handshake) | Pre-1.0 |

## Why a separate package

These primitives are consumed by several independent surfaces (messaging, signaling,
offline transport), so they live in their own package with an independent release cadence.
Downstream apps pin a stable version instead of tracking a larger codebase.

## Layout

```
packages/
  identity/   — Ed25519 device identity, X25519 seed derivation, IndexedDB store
  mesh-core/  — BLE + WiFi-Direct mesh transport, frame codec, outbox, router
```

## Build

```bash
pnpm install
pnpm -r run build
pnpm -r run test
```

## License

[AGPL-3.0-or-later](LICENSE). If you embed `@oxpulse/identity` or `@oxpulse/mesh-core` in a
network service, the network service source must be made available under AGPL.
