# Changelog

## [0.1.17](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.16...mesh-core-v0.1.17) (2026-08-05)


### Fixed

* **mesh-core:** restore Inbox/Spool evictExcess and lock the public API ([#69](https://github.com/anatolykoptev/oxpulse-core/issues/69)) ([34e1ff0](https://github.com/anatolykoptev/oxpulse-core/commit/34e1ff0a847ebe279a22df930915b7bbb623d84f))

## [0.1.16](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.15...mesh-core-v0.1.16) (2026-08-05)


### Fixed

* **mesh-core:** drop unused sframe-ratchet dependency, revert manual publish path ([#66](https://github.com/anatolykoptev/oxpulse-core/issues/66)) ([3b4017f](https://github.com/anatolykoptev/oxpulse-core/commit/3b4017f64d8c4b2b06b1d33e7ad36b78eaf24e47))

## [0.1.15](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.14...mesh-core-v0.1.15) (2026-08-05)


### Fixed

* **mesh-core:** restore exponential backoff + unblock the inbound responder handshake ([#56](https://github.com/anatolykoptev/oxpulse-core/issues/56)) ([d971248](https://github.com/anatolykoptev/oxpulse-core/commit/d9712489e64f4862c1258bdf8fc84bd9d5bc79d6))


### Changed

* **mesh-core:** delete the two remaining uncalled evictExcess copies ([#57](https://github.com/anatolykoptev/oxpulse-core/issues/57)) ([15f8c95](https://github.com/anatolykoptev/oxpulse-core/commit/15f8c952c24722c42690801fab5de0e367d0b712))


### Documentation

* rewrite both package READMEs for their npm pages ([#63](https://github.com/anatolykoptev/oxpulse-core/issues/63)) ([72a479e](https://github.com/anatolykoptev/oxpulse-core/commit/72a479ea2d6ccf12f968c34adde52f418ab097c2))

## [0.1.14](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.13...mesh-core-v0.1.14) (2026-08-04)


### Fixed

* **mesh-core:** clear backoff/backoffCounts Maps on device disconnect ([#52](https://github.com/anatolykoptev/oxpulse-core/issues/52)) ([00b19c5](https://github.com/anatolykoptev/oxpulse-core/commit/00b19c5cdb6812d386ab2f42c9199713e903308a))
* **mesh-core:** emit bloom_params_changed metric on Bloom filter state discard ([#53](https://github.com/anatolykoptev/oxpulse-core/issues/53)) ([145f16b](https://github.com/anatolykoptev/oxpulse-core/commit/145f16b418716494f52077ff33906f49fd973366))
* **mesh-core:** reset handshakeFailures on successful handshake completion ([#54](https://github.com/anatolykoptev/oxpulse-core/issues/54)) ([1cfd3c7](https://github.com/anatolykoptev/oxpulse-core/commit/1cfd3c7f880acac50de5e3df3d75e125d243c686))

## [0.1.13](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.12...mesh-core-v0.1.13) (2026-08-04)


### Fixed

* **mesh-core:** review council fixes — outbox eviction math + test coverage + dead code ([#41](https://github.com/anatolykoptev/oxpulse-core/issues/41)) ([080d72e](https://github.com/anatolykoptev/oxpulse-core/commit/080d72e0a3ed15af24ad3ea3aae6e28a69d17c6e))

## [0.1.12](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.11...mesh-core-v0.1.12) (2026-08-04)


### Fixed

* **mesh-core:** enforce BLE connection limit to avoid platform caps ([#36](https://github.com/anatolykoptev/oxpulse-core/issues/36)) ([f8b4be0](https://github.com/anatolykoptev/oxpulse-core/commit/f8b4be06d2d8ec5969c42ed47525feb3e70407b3))

## [0.1.11](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.10...mesh-core-v0.1.11) (2026-08-04)


### Fixed

* **mesh-core:** bounded outbox storage with entry count limit ([#34](https://github.com/anatolykoptev/oxpulse-core/issues/34)) ([de6d998](https://github.com/anatolykoptev/oxpulse-core/commit/de6d998c93eb0b51b4010886ae7c20e9ed5eea5b))

## [0.1.10](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.9...mesh-core-v0.1.10) (2026-08-04)


### Fixed

* **mesh-core:** emit metric when handshake frame dropped during mesh stop ([#32](https://github.com/anatolykoptev/oxpulse-core/issues/32)) ([b92ab00](https://github.com/anatolykoptev/oxpulse-core/commit/b92ab00df714785e3aae54a2d983bcd8d6bf091d))

## [0.1.9](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.8...mesh-core-v0.1.9) (2026-08-04)


### Fixed

* **mesh-core:** skip handshake timeout for disconnected devices ([#30](https://github.com/anatolykoptev/oxpulse-core/issues/30)) ([f90dee2](https://github.com/anatolykoptev/oxpulse-core/commit/f90dee22754e6caabf936c69f968011e53e3fedb))

## [0.1.8](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.7...mesh-core-v0.1.8) (2026-08-04)


### Fixed

* **mesh-core:** verdict state machine + connected-device guard for async bootstrap ([#28](https://github.com/anatolykoptev/oxpulse-core/issues/28)) ([41342b1](https://github.com/anatolykoptev/oxpulse-core/commit/41342b193f9d4c8f865d8f240c99ce6e9daaac40))

## [0.1.7](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.6...mesh-core-v0.1.7) (2026-08-04)


### Fixed

* **mesh-core:** atomic read-modify-write via cursor.update for outbox + spool ([#26](https://github.com/anatolykoptev/oxpulse-core/issues/26)) ([f8dd50d](https://github.com/anatolykoptev/oxpulse-core/commit/f8dd50d503327a56fcfc40f86da664a207c88be4))

## [0.1.6](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.5...mesh-core-v0.1.6) (2026-08-04)


### Fixed

* **mesh-core:** downgrade strategy to 'online' when BLE fails in dual mode ([#24](https://github.com/anatolykoptev/oxpulse-core/issues/24)) ([525caea](https://github.com/anatolykoptev/oxpulse-core/commit/525caea6c38a35c32ea25512c9eeb49f38e1020c))

## [0.1.5](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.4...mesh-core-v0.1.5) (2026-08-04)


### Fixed

* **mesh-core:** propagate handshake errors to meshState + CryptoState ([#22](https://github.com/anatolykoptev/oxpulse-core/issues/22)) ([64aa28d](https://github.com/anatolykoptev/oxpulse-core/commit/64aa28d32e56665aeac01d36babdad195d167aef))

## [0.1.4](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.3...mesh-core-v0.1.4) (2026-08-04)


### Fixed

* **mesh-core:** bounded mailbox storage — atomic evict-on-put + cursor reads ([#19](https://github.com/anatolykoptev/oxpulse-core/issues/19)) ([95e1cd6](https://github.com/anatolykoptev/oxpulse-core/commit/95e1cd63ca6ea2aacecc22371cb6d3bce7986022))

## [0.1.3](https://github.com/anatolykoptev/oxpulse-core/compare/mesh-core-v0.1.2...mesh-core-v0.1.3) (2026-08-04)


### Fixed

* **identity:** sync 4 post-extraction commits from oxpulse-chat ([a8415b7](https://github.com/anatolykoptev/oxpulse-core/commit/a8415b7f3cf78f818677dbed452d120be124680f))
* **mesh-core:** bump wire-codec to ^0.4.1 + drop 0.3.0 patch ([50c53b8](https://github.com/anatolykoptev/oxpulse-core/commit/50c53b83130996d35342f2fdd85e5bfa8572d698))
* **mesh-core:** bump wire-codec to ^0.6.1, drop orphaned patch, node16 resolution ([#5](https://github.com/anatolykoptev/oxpulse-core/issues/5)) ([4945c79](https://github.com/anatolykoptev/oxpulse-core/commit/4945c79a9d4978d45db5aaa98648bd9f3d30f04e))
* **mesh-core:** unbreak 3 excluded test suites — wire-codec ESM patch + vitest pin ([f3c87a3](https://github.com/anatolykoptev/oxpulse-core/commit/f3c87a3545c448b598bf98d7267ba2b2d0df620b))
