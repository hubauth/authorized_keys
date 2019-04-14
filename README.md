# authorized_keys-rs

Parse and manipulate OpenSSH `authorized_keys` files.

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

## Contributing

### Requirements

* `rustc`/`cargo` 1.34+ ([`rustup`] recommended)
* `cargo clippy --version` 0.0.212+
* `cargo fmt --version` 1.0.3-stable+

### Process

1. Open an issue for the contribution you'd like to make
    * Check for duplicates first :slightly_smiling_face:
1. Fork the repository, make your changes on a branch
1. Add tests for new features
1. Ensure `just check` passes locally
1. Open a PR for the changes
    * Add yourself as an author to `Cargo.toml` and `README.md`, if you'd like!

## Authors

* [Liam Dawson](https://github.com/liamdawson)

## License

Rustfmt is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
