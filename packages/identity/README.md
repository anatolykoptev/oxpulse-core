# @oxpulse/identity

Long-term Ed25519 device identity for oxpulse-chat.

## What goes here

- `device-identity.ts` — persistent Ed25519 device keypair (IDB + AES-KW wrapping)
- `host-identity.ts` — in-memory Ed25519 room-host keypair
- `base64url.ts` — canonical base64url encode/decode (single copy across workspace)
- `tracker-shim.ts` — analytics injection point (avoids circular dep with `web/tracker.ts`)

**What does NOT go here:** session crypto (`webrtc-keys*`, `chat-cryptor`), profile
derivation logic (`short-id-mint.ts`, `handle-sync.ts`), identity backup UI.

## Storage contract

IDB store name and key names are load-bearing for installed users.
See `device-identity.ts` for `// LOAD-BEARING` comments and the
`storage-keys.test.ts` pin test.

See `docs/architecture/identity-extraction-adr.md` for design rationale.
