# @oxpulse/identity

Long-term Ed25519 device identity for the browser — generated once, persisted in IndexedDB with the
private key wrapped under AES-KW, and reused across sessions.

Built for [oxpulse-chat](https://github.com/anatolykoptev/oxpulse-chat), usable on its own.

> **Pre-1.0.** The public API is not yet stable and may change between minor versions. Pin an exact
> version rather than a range if that matters to you.

## Install

```bash
pnpm add @oxpulse/identity
```

Runs in any browser with IndexedDB, and under Node ≥ 18 for tests (with a `fake-indexeddb` shim).
The only runtime dependency is [`@noble/curves`](https://github.com/paulmillr/noble-curves).

## Quick start

```ts
import {
  getOrCreateDeviceIdentity,
  signWithDeviceIdentity,
  verifyDeviceSignature,
  fromBase64url,
} from '@oxpulse/identity';

// Call once at app startup. Creates the keypair on first run, loads it after.
const identity = await getOrCreateDeviceIdentity();
console.log('device pubkey:', identity.publicKeyB64); // base64url, 32-byte Ed25519

const sig = await signWithDeviceIdentity(identity, 'hello');   // base64url signature
const ok = await verifyDeviceSignature(
  fromBase64url(identity.publicKeyB64),
  'hello',
  fromBase64url(sig),
);
```

### WebCrypto is not guaranteed

`identity.publicKey` and `identity.privateKey` are WebCrypto `CryptoKey` handles that are **`null`
on runtimes without Ed25519 support** — notably the frozen WebViews on HyperOS and HarmonyOS. Code
that reaches for `crypto.subtle` must check for null and fall back to the raw material:

```ts
if (identity.privateKey) {
  // WebCrypto path
} else {
  // Fall back to identity.privateKeyBytes with @noble/curves.
}
```

`signWithDeviceIdentity` and `verifyDeviceSignature` sidestep the problem entirely — both go through
`@noble/curves` on every runtime and never touch `crypto.subtle`. Signing does require
`privateKeyBytes`, and throws if it is null (an identity created before raw-seed persistence must be
re-registered). The `CryptoKey` handles matter only if you drive WebCrypto yourself.

## What's in the box

| Area | Exports |
|---|---|
| Device identity | `getOrCreateDeviceIdentity` `generateDeviceIdentity` `replaceDeviceIdentity` `clearDeviceIdentity` `hasDeviceIdentity` |
| Signing | `signWithDeviceIdentity` `verifyDeviceSignature` `exportRawDeviceSecret` |
| Noise DH | `getOrCreateX25519Keypair` `dhX25519` — X25519 static keypair for Noise XX `es`/`se` |
| X25519 identity | `getOrCreateX25519Identity` `generateX25519Identity` `verifyX25519SelfSig` |
| Profile seed | `getOrCreateProfileSeed` `setProfileSeed` `clearProfileSeed` |
| Room-host | `getOrCreateRoomHostKey` `signHostAction` `buildKickPayload` `buildLockPayload` `buildUnlockPayload` `buildPinMintPayload` `buildShortlinkMintPayload` |
| Room-host seed | `getOrCreateRoomHostSeed` `exportRoomHostSeed` |
| Helpers | `toBase64url` `fromBase64url` `probeBrowserSupport` `IDBUnavailableError` `setIdentityTracker` |

Room-host keys are **in-memory only** and HKDF-derived from a dedicated seed — they are never
persisted alongside the device key.

## Storage contract

The IndexedDB database name, store name and key names are **load-bearing for already-installed
users**: changing any of them orphans every existing identity, and the affected users silently
appear as brand-new devices. They are pinned by `storage-keys.test.ts` and marked `// LOAD-BEARING`
in `device-identity.ts`. Treat a change there as a migration, not a rename.

`IDBUnavailableError` is exported as a single class so `instanceof` works across module boundaries —
import it from here rather than matching on error messages.

## Links

- [Repository](https://github.com/anatolykoptev/oxpulse-core)
- [Changelog](https://github.com/anatolykoptev/oxpulse-core/blob/main/packages/identity/CHANGELOG.md)
- [Issues](https://github.com/anatolykoptev/oxpulse-core/issues)

## License

AGPL-3.0-or-later
