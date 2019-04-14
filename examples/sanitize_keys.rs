// Remove all comments and other human-readable data from a list of keys

extern crate authorized_keys;

use authorized_keys::openssh::v2::*;
use std::iter::FromIterator;
use std::str::FromStr;

const SAMPLE_FILE: &str = include_str!("./sanitize_keys_data.txt");

fn main() {
    let key_file =
        AuthorizedKeysFile::from_str(SAMPLE_FILE).expect("that was a valid authorized_keys file!");

    println!("Before:\n{}", SAMPLE_FILE);

    println!(
        "After:\n{}",
        AuthorizedKeysFile::from_iter(key_file.into_iter().flat_map(|line| match line {
            AuthorizedKeysFileLine::Comment(_) => None,
            AuthorizedKeysFileLine::AuthorizedKey(key) => {
                Some(AuthorizedKeysFileLine::AuthorizedKey(key.remove_comments()))
            }
        }))
    );
}
