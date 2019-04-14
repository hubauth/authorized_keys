check: check-fmt check-tests check-clippy check-docs

check-fmt:
    cargo fmt -- --check

check-tests:
    cargo test
    cargo test --features "key_encoding"

check-clippy:
    cargo clippy --all-targets --all-features -- -D warnings

check-docs:
    cargo doc

fix: fix-fmt

fix-fmt:
    cargo fmt
