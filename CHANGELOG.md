# CHANGELOG

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/) and [Keep a Changelog](http://keepachangelog.com/).

## [Unreleased]
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

[Unreleased]: https://github.com/hubauth/authorized_keys/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/hubauth/authorized_keys/releases/tag/v0.9.0
[#2]: https://github.com/hubauth/authorized_keys/pull/2
[#3]: https://github.com/hubauth/authorized_keys/pull/3
[#4]: https://github.com/hubauth/authorized_keys/pull/4
