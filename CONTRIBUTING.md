# Contributing

Particularly welcomed:

* Test cases (especially failing ones)
* Enhanced testing
* Improvements to the way [pest] is used

## Requirements

* `rustc`/`cargo` 1.34+ ([`rustup`] recommended)
* `cargo clippy --version` 0.0.212+
* `cargo fmt --version` 1.0.3-stable+

## Process

1. Open an issue for the contribution you'd like to make
    * Check for duplicates first :slightly_smiling_face:
1. Fork the repository, make your changes on a branch
1. Add tests for new features
1. Ensure `just check` passes locally
1. Open a PR for the changes
    * Add yourself as an author to `Cargo.toml` and `README.md`, if you'd like!

[pest]: https://pest.rs
