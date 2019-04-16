# authorized_keys-rs

Parse and manipulate OpenSSH `authorized_keys` files.

[![Windows Build Status](https://ci.appveyor.com/api/projects/status/gm7dto6llk0mgrsr?svg=true)](https://ci.appveyor.com/project/liamdawson/authorized-keys)
[![Build Status](https://travis-ci.com/hubauth/authorized_keys.svg?branch=master)](https://travis-ci.com/hubauth/authorized_keys)
[![Crates.io](https://img.shields.io/crates/v/authorized_keys.svg)](https://crates.io/crates/authorized_keys)

  [Contributing](./CONTRIBUTING.md)
| [Code of Conduct](./CODE_OF_CONDUCT.md)
| [Changelog](./CHANGELOG.md)
| [Examples](./examples/)

## Installation

`Cargo.toml`:

```toml
[dependencies]
authorized_keys = "0.9"
```

## Features

* Parse `authorized_keys` files
* Parse individual lines from `authorized_keys` files
* Change the parts of a line (options, key type, encoded key, comments)
  with convenience methods
* Write `authorized_keys` files in the correct format
* No dependencies by default
  * Depends on [`data-encoding`] if you want to edit key data as bytes

## Roadmap

### 1.0

* [ ] more significant testing
* [x] benchmarks
* [ ] validated benchmarks

## Authors

* [Liam Dawson](https://github.com/liamdawson)

## License

`authorized_keys` is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[`data-encoding`]: https://github.com/ia0/data-encoding
