# Changelog

## [0.2.3](https://github.com/anatolykoptev/oxpulse-core/compare/identity-v0.2.2...identity-v0.2.3) (2026-08-08)


### Fixed

* **identity:** adopt the pre-[#98](https://github.com/anatolykoptev/oxpulse-core/issues/98) wrapping key — 0.2.x locked field users out of their identities ([#113](https://github.com/anatolykoptev/oxpulse-core/issues/113)) ([f17c0e3](https://github.com/anatolykoptev/oxpulse-core/commit/f17c0e3c939742227c51c3cb29525b824a5e8d5b))

## [0.2.2](https://github.com/anatolykoptev/oxpulse-core/compare/identity-v0.2.1...identity-v0.2.2) (2026-08-06)


### Added

* **identity:** audit every raw-secret export ([0aed0b6](https://github.com/anatolykoptev/oxpulse-core/commit/0aed0b60d6e03d7babdf55b954d08306a058001b))
* **identity:** audit every raw-secret export ([#111](https://github.com/anatolykoptev/oxpulse-core/issues/111)) ([0aed0b6](https://github.com/anatolykoptev/oxpulse-core/commit/0aed0b60d6e03d7babdf55b954d08306a058001b))

## [0.2.1](https://github.com/anatolykoptev/oxpulse-core/compare/identity-v0.2.0...identity-v0.2.1) (2026-08-05)


### Fixed

* **identity:** read the KEK back without touching the CryptoKey global ([#109](https://github.com/anatolykoptev/oxpulse-core/issues/109)) ([07a6810](https://github.com/anatolykoptev/oxpulse-core/commit/07a681048d3ffef5784b14160c1fe54ff1ffa184))

## [0.2.0](https://github.com/anatolykoptev/oxpulse-core/compare/identity-v0.1.5...identity-v0.2.0) (2026-08-05)


### ⚠ BREAKING CHANGES

* **identity:** `DeviceIdentity.privateKeyBytes` is renamed to `privateKeySeed` and its type changes from `Uint8Array | null` to `OpaquePrivateKey | null`. Callers read the seed with `.bytes()`. The old name was kept in an earlier revision of this branch and dropped: the field stopped being bytes, `privateKeyBytes.bytes()` reads like a mistake, and renaming later would cost consumers a second breaking release for the same field. The plan specified renaming to `privateKey`, which is not possible — that name is already the WebCrypto `CryptoKey` handle on the same interface.

### Added

* **identity:** non-extractable KEK, separate KEK store, shared AES-KW, OpaquePrivateKey ([#104](https://github.com/anatolykoptev/oxpulse-core/issues/104)) ([da81475](https://github.com/anatolykoptev/oxpulse-core/commit/da81475f4771edcc9b7fd9723020790ea6b6fbc1))

## [0.1.5](https://github.com/anatolykoptev/oxpulse-core/compare/identity-v0.1.4...identity-v0.1.5) (2026-08-05)


### Documentation

* rewrite both package READMEs for their npm pages ([#63](https://github.com/anatolykoptev/oxpulse-core/issues/63)) ([72a479e](https://github.com/anatolykoptev/oxpulse-core/commit/72a479ea2d6ccf12f968c34adde52f418ab097c2))

## [0.1.4](https://github.com/anatolykoptev/oxpulse-core/compare/identity-v0.1.3...identity-v0.1.4) (2026-08-04)


### Fixed

* **identity:** ephemeral fallback on IDB QuotaExceededError ([#39](https://github.com/anatolykoptev/oxpulse-core/issues/39)) ([6d8f564](https://github.com/anatolykoptev/oxpulse-core/commit/6d8f564c54782acf66e9f4884d353484185fc85e))

## [0.1.3](https://github.com/anatolykoptev/oxpulse-core/compare/identity-v0.1.2...identity-v0.1.3) (2026-08-04)


### Fixed

* **identity:** persist X25519 raw key for noble fallback on WebCrypto downgrade ([#38](https://github.com/anatolykoptev/oxpulse-core/issues/38)) ([29048aa](https://github.com/anatolykoptev/oxpulse-core/commit/29048aa4afdd3efb98a7c9ecceaca016aa038030))
* **identity:** sync 4 post-extraction commits from oxpulse-chat ([a8415b7](https://github.com/anatolykoptev/oxpulse-core/commit/a8415b7f3cf78f818677dbed452d120be124680f))
* **mesh-core:** bump wire-codec to ^0.4.1 + drop 0.3.0 patch ([50c53b8](https://github.com/anatolykoptev/oxpulse-core/commit/50c53b83130996d35342f2fdd85e5bfa8572d698))
