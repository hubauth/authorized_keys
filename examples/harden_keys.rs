// Take a list of GitHub user keys, and restrict them so they can only run the command uptime (and cannot port-forward/etc)

extern crate authorized_keys;

use authorized_keys::openssh::v2::*;
use std::iter::FromIterator;
use std::str::FromStr;

const SAMPLE_FILE: &str = include_str!("./harden_keys_data.txt");

fn main() {
    let key_file =
        AuthorizedKeysFile::from_str(SAMPLE_FILE).expect("that was a valid authorized_keys file!");

    println!("Before:\n{}", SAMPLE_FILE);

    println!(
        "After:\n{}",
        AuthorizedKeysFile::from_iter(key_file.into_iter().flat_map(|line| {
            match line {
                AuthorizedKeysFileLine::Comment(_) => None,
                AuthorizedKeysFileLine::AuthorizedKey(key) => {
                    Some(AuthorizedKeysFileLine::AuthorizedKey(
                        key.clear_options()
                            .option_name("restrict".to_owned())
                            .option(("command".to_owned(), Some("uptime".to_owned()))),
                    ))
                }
            }
        }))
    );
}
