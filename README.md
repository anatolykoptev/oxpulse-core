# oxpulse-core

Platform primitives shared between **oxpulse-chat** (group messenger) and call surfaces of the OxPulse family.

## Packages

| Package | Purpose | Status |
|---|---|---|
| [`@oxpulse/identity`](packages/identity) | Long-term Ed25519 device identity (host + device + room-host seed; IndexedDB-backed) | Pre-1.0 — internal API stability not guaranteed |
| [`@oxpulse/mesh-core`](packages/mesh-core) | BLE / WiFi-Direct offline mesh transport (frame, outbox, dedupe, router, peer-registry, GATT channel) | Pre-1.0 |

## Why a separate repo

Both `@oxpulse/identity` and `@oxpulse/mesh-core` are imported from multiple downstream surfaces (chat handlers, call signaling, group-call admission, federated mailbox transport). Extracting them out of the oxpulse-chat monorepo lets each downstream surface pin a stable version and lets us iterate on the shared layer with its own release cadence.

This repo is **Phase 1 of the oxpulse-chat monorepo split**. Later phases (chat extraction, web-app split) are gated on first paying B2B `chat-sdk` customer.

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

[AGPL-3.0-or-later](LICENSE). If you embed `@oxpulse/identity` or `@oxpulse/mesh-core` in a network service, the network service source must be made available under AGPL.
