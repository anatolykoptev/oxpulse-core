# @oxpulse/mesh-core

Offline mesh transport over Bluetooth LE — peers exchange end-to-end encrypted frames with no
server, no internet, and no shared infrastructure.

Built for [oxpulse-chat](https://github.com/anatolykoptev/oxpulse-chat), usable on its own.

> **Pre-1.0.** The public API is not yet stable and may change between minor versions. Pin an exact
> version rather than a range if that matters to you.

## Install

```bash
pnpm add @oxpulse/mesh-core
```

BLE transport runs inside [Capacitor](https://capacitorjs.com/). Those peer dependencies are
**optional** — install them only if you use the radio:

```bash
pnpm add @capacitor/core @capacitor-community/bluetooth-le
```

Without them the pure-logic parts still work anywhere (Node ≥ 18 or a browser): frame codec,
router, outbox, dedupe, mailbox, channel derivation, `mesh-wrap`.

## Security model

Sessions are established with a **Noise XX** handshake hybridised with **ML-KEM-768**: the initiator
carries an ML-KEM public key in msg-1, the responder returns a ciphertext in msg-2, and the session
keys derive from HKDF over `noise_ck || mlkem_shared_secret`. A recorded session is therefore not
retroactively decryptable by a future quantum adversary — the same construction as Signal's PQXDH
and Apple's PQ3.

Transport AEAD is **AES-128-GCM** via WebCrypto (hardware-accelerated on modern ARM), with the nonce
built from a direction byte plus a 64-bit counter. Each frame is encrypted under a **distinct AEAD
key** derived from the previous frame's chain key via one HKDF-SHA-256 step; after the key is used
the chain advances irreversibly, so compromise of the sender's state at frame *T* cannot retroactively
decrypt frames it already sent. A sliding **64-frame replay window** rejects duplicated or replayed
frames, and a matching 64-entry key cache on the receiver retains keys for the trailing 64 counters so
that BLE GATT notifications reordered under congestion still decrypt. This is **window forward
secrecy**, not per-frame forward secrecy: compromise of the receiver's state at frame *T* reveals
frames in *[T−63, T]*; frames older than *T−64* are unrecoverable because their keys and chain state
have been evicted. Per-frame forward secrecy (strict in-order, no key retention) was rejected because
BLE reorders under congestion and strict in-order delivery dropped legitimate frames.

Peer authentication is **TOFU** (trust on first use) plus an out-of-band **SAS** check: the first
time you meet a peer its static public key is pinned, a short authentication string is derived, and
the two humans compare it. `sendFrame` refuses to send until you have explicitly accepted the peer
— an unverified peer cannot receive traffic by default, and a key change on a known peer-id is
surfaced rather than silently accepted.

Advertised MAC addresses rotate on a timer to limit passive tracking.

## Quick start

```ts
import {
  startMesh, stopMesh, onFrame, sendFrame,
  getPendingHandshakes, acceptPeer, onHandshakeStateChange,
  setMeshMetricSink,
} from '@oxpulse/mesh-core';

// Optional: observe error trends. Register before startMesh().
setMeshMetricSink((metric, labels) => console.log('[mesh]', metric, labels));

const offFrame = onFrame((peerIdHex, frame) => {
  console.log('frame from', peerIdHex, frame.byteLength, 'bytes');
});

// Surface each new peer for SAS verification as it completes its handshake.
const offHandshake = onHandshakeStateChange(() => {
  for (const p of getPendingHandshakes()) {
    // Show p.sas to the user; both devices must display the same string.
    // p.keyChanged === true means this peer-id now presents a DIFFERENT key
    // than the one pinned on first contact — treat that as suspicious.
    console.log('verify peer', p.peerIdHex, 'SAS:', p.sas, 'key changed:', p.keyChanged);
  }
});

await startMesh();

// Only after the user confirms the SAS matches:
acceptPeer(peerIdHex);            // rejectPeer(peerIdHex) otherwise

// Throws 'unknown-peer-key' unless the handshake completed AND the peer was accepted.
await sendFrame(peerIdHex, new Uint8Array([1, 2, 3]));

offFrame();
offHandshake();
await stopMesh();
```

`meshState` is a reactive object carrying `peers`, `advertising`, `scanning` and `error` for
binding straight into a UI.

## What's in the box

| Area | Exports |
|---|---|
| Transport | `startMesh` `stopMesh` `sendFrame` `onFrame` `meshState` |
| Handshake | `getPendingHandshakes` `acceptPeer` `rejectPeer` `onHandshakeStateChange` |
| Framing | `chunkFrame` `FrameReassembler` `FRAME_HEADER_LEN` |
| Peers | `generatePeerId` `PeerRegistry` `MacRotationTimer` |
| Routing | `routeOutgoing` `onIncoming` `bridgeSend` `startOutboxDrainer` |
| Storage | `Outbox` `DedupeCache` — plus the mailbox (inbox / spool / Bloom dedup) |
| Bundles | `composeBundle` `composeMeshWrap` `peelMeshWrap` |
| Channels | `channelIdHash` `currentChannelId` `neighboringChannelIds` `getRegionFallback` |
| Platform | `isInCapacitor` `isAndroid` `isIOS` `isNative`, also via `@oxpulse/mesh-core/native` |

IndexedDB-backed stores (outbox, inbox, spool) are **bounded** — each insert enforces its entry cap
atomically, evicting oldest-first, so a long offline stretch cannot grow storage without limit.

## Operational notes

- **Connection cap.** At most 6 concurrent BLE links, below Android's hard limit of 7, to avoid the
  GATT error-133 hangs that appear at the platform ceiling.
- **Backoff.** A failed connect backs off 5s → 15s → 60s per device.
- **Metrics.** `setMeshMetricSink` is the single observability hook; every drop, eviction, quota
  error and handshake failure emits through it. Without a sink those events are invisible.

## Links

- [Repository](https://github.com/anatolykoptev/oxpulse-core)
- [Changelog](https://github.com/anatolykoptev/oxpulse-core/blob/main/packages/mesh-core/CHANGELOG.md)
- [Issues](https://github.com/anatolykoptev/oxpulse-core/issues)

## License

AGPL-3.0-or-later
