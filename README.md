# authorized_keys-rs

Parse and manipulate OpenSSH `authorized_keys` files.

[![AppVeyor](https://img.shields.io/appveyor/ci/liamdawson/authorized_keys.svg?label=Windows%20builds&style=flat-square)](https://ci.appveyor.com/project/liamdawson/authorized-keys)
[![Travis](https://img.shields.io/travis/com/hubauth/authorized_keys.svg?style=flat-square)](https://travis-ci.com/hubauth/authorized_keys)
[![Crates.io](https://img.shields.io/crates/v/authorized_keys.svg?style=flat-square)](https://crates.io/crates/authorized_keys)

  [Contributing](./CONTRIBUTING.md)
| [Code of Conduct](./CODE_OF_CONDUCT.md)
| [Examples](./examples/)

## Installation

`Cargo.toml`:

```toml
[features]
authorized_keys = "0.9"
```

## Features

* Parse `authorized_keys` files
* Parse individual lines from `authorized_keys` files
* Change the parts of a line (options, key type, encoded key, comments)
  with convenience methods
* Write `authorized_keys` files in the correct format
* Depends on [`pest`], (and `pest_derive`) by default:
  * [`data-encoding`] if you want to edit keys as bytes
  * No dependencies if you disable the default `parsing` feature

## Roadmap

### 1.0

* [ ] more significant testing
* [ ] benchmarks

## Authors

* [Liam Dawson](https://github.com/liamdawson)

## License

`authorized_keys` is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[`pest`]: https://pest.rs
[`data-encoding`]: https://github.com/ia0/data-encoding
