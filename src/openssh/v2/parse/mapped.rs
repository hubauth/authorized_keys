use super::super::models::{KeyOptions, KeyType, PublicKey};
use super::atoms::*;
use super::parts::*;
use nom::{combinator::map_resc, sequence::tuple, IResult};
use std::borrow::ToOwned;

pub(crate) fn key_type(input: &str) -> IResult<&str, KeyType> {
    map_resc(input, identifier, str::parse)
}

pub(crate) fn public_key(input: &str) -> IResult<&str, PublicKey> {
    let (input, (parsed_key_type, _, encoded_key)) = tuple((key_type, whitespace, base64))(input)?;

    Ok((
        input,
        PublicKey {
            key_type: parsed_key_type,
            encoded_key: encoded_key.to_owned(),
        },
    ))
}

pub(crate) fn key_options(input: &str) -> IResult<&str, KeyOptions> {
    let (input, parsed_options) = options(input)?;

    let mapped_options = parsed_options
        .iter()
        .map(|(name, val)| (name.to_string(), val.map(ToOwned::to_owned)))
        .collect();

    Ok((input, mapped_options))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    fn reverse_tuple((a, b): (KeyType, String)) -> (String, KeyType) {
        (b, a)
    }

    #[test]
    fn parses_all_key_types() {
        assert_that_cases(
            |i| key_type(&i).unwrap().1,
            as_expected,
            KeyType::name_value_pairs()
                .into_iter()
                .map(reverse_tuple)
                .collect(),
        );
    }

    #[test]
    fn parses_public_keys() {
        assert_that_cases(
            |i| public_key(i).unwrap().1,
            as_expected,
            vec![
                (
                    "ssh-ed25519 foobar==",
                    PublicKey {
                        key_type: KeyType::SshEd25519,
                        encoded_key: "foobar==".to_owned(),
                    },
                ),
                (
                    "ecdsa-sha2-nistp521 istestbase64",
                    PublicKey {
                        key_type: KeyType::EcdsaSha2Nistp521,
                        encoded_key: "istestbase64".to_owned(),
                    },
                ),
            ],
        );
    }

    #[test]
    fn parses_option_lists() {
        assert_that_cases(
            |i| key_options(i).unwrap().1,
            as_expected,
            vec![
                ("restrict", vec![("restrict".to_owned(), None)]),
                (
                    "restrict,command=\"uptime\"",
                    vec![
                        ("restrict".to_owned(), None),
                        ("command".to_owned(), Some("uptime".to_owned())),
                    ],
                ),
            ],
        );
    }
}
