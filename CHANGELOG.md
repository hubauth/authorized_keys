# CHANGELOG

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/) and [Keep a Changelog](http://keepachangelog.com/).

## [Unreleased]

* Fix clippy warnings against nightly

---

## [1.0.0] - (2019-08-28)

* Upgrade to stable version 5 of nom

---

### Changes

* Replaced hand-written parser with `nom 5.0.0-beta2` parser, improving
  readability and parsing speed. [#7]

## [0.10.0] - (2019-04-16)

---

### Changes

* Replaced pest-based parser with a hand-written parser, reducing dependencies
  and improving parsing speed [#3].

### Breaks

* Public key types are now strongly-typed enums [#2].
* Model structs have been renamed [#4].
* Public key data is now nested within key authorizations [#4].

## [0.9.0] - (2019-04-14)

---

Initial release.

[Unreleased]: https://github.com/hubauth/authorized_keys/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/hubauth/authorized_keys/compare/v0.10.0...v1.0.0
[0.10.0]: https://github.com/hubauth/authorized_keys/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/hubauth/authorized_keys/releases/tag/v0.9.0

[#2]: https://github.com/hubauth/authorized_keys/pull/2
[#3]: https://github.com/hubauth/authorized_keys/pull/3
[#4]: https://github.com/hubauth/authorized_keys/pull/4
[#7]: https://github.com/hubauth/authorized_keys/pull/7
