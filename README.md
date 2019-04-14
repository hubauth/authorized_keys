# authorized_keys-rs

Parse and manipulate OpenSSH `authorized_keys` files.

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
* Depends on `pest`, `pest_derive` by default:
  * `data-encoding` if you want to edit keys as bytes
  * No dependencies if you disable the default `parsing` feature

## Authors

* [Liam Dawson](https://github.com/liamdawson)

## License

Rustfmt is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
