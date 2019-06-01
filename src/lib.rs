//! Parse and manipulate OpenSSH `authorized_keys` files.
//!
//! This [crate] provides parsers and manipulations for OpenSSH
//! `authorized_key` files. [Example usages] include validating,
//! sanitizing, and hardening `authorized_keys` files.
//!
//! [crate]: https://crates.io/crates/authorized_keys
//! [Example usages]: https://github.com/hubauth/authorized_keys/blob/master/examples/

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

extern crate nom;

pub mod openssh;
mod string_enum;
#[cfg(test)]
pub(crate) mod testing;
