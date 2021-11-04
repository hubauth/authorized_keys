# authorized_keys

Parse and manipulate OpenSSH `authorized_keys` files.

[![Linting Status](https://github.com/hubauth/authorized_keys/workflows/Lint/badge.svg)](https://github.com/hubauth/authorized_keys/actions?query=workflow%3ALint)
[![Test Suite Status](https://github.com/hubauth/authorized_keys/workflows/Test/badge.svg)](https://github.com/hubauth/authorized_keys/actions?query=workflow%3ATest)
[![Crates.io](https://img.shields.io/crates/v/authorized_keys.svg)](https://crates.io/crates/authorized_keys)

  [Contributing](./CONTRIBUTING.md)
| [Code of Conduct](./CODE_OF_CONDUCT.md)
| [Changelog](./CHANGELOG.md)
| [Examples](./examples/)

## Installation

`Cargo.toml`:

```toml
[dependencies]
authorized_keys = "1.0"
```

## Features

* Parse `authorized_keys` files
* Parse individual lines from `authorized_keys` files
* Change the parts of a line (options, key type, encoded key, comments)
  with convenience methods
* Write `authorized_keys` files in the correct format
* One dependency by default (`nom`)
  * Depends on [`data-encoding`] if you want to edit key data as bytes using
    convenience methods
* Minimum rust version 1.34.2 (supports Debian Buster)

## Authors

* [Liam Dawson](https://github.com/liamdawson)

## License

`authorized_keys` is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[`data-encoding`]: https://github.com/ia0/data-encoding
