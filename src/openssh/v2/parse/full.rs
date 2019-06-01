use super::super::models::{KeyAuthorization, KeyOptions};
use super::atoms::{comments, whitespace};
use super::mapped::*;
use nom::{branch::alt, sequence::tuple, IResult};

pub(crate) fn key_authorization_without_options(input: &str) -> IResult<&str, KeyAuthorization> {
    let (input, (parsed_public_key, parsed_comments)) = tuple((public_key, comments))(input)?;

    Ok((
        input,
        KeyAuthorization {
            options: KeyOptions::new(),
            key: parsed_public_key,
            comments: parsed_comments.trim_start().to_owned(),
        },
    ))
}

pub(crate) fn key_authorization_with_options(input: &str) -> IResult<&str, KeyAuthorization> {
    let (input, (options, _, parsed_public_key, parsed_comments)) =
        tuple((key_options, whitespace, public_key, comments))(input)?;

    Ok((
        input,
        KeyAuthorization {
            options,
            key: parsed_public_key,
            comments: parsed_comments.trim_start().to_owned(),
        },
    ))
}

pub(crate) fn key_authorization(input: &str) -> IResult<&str, KeyAuthorization> {
    alt((
        key_authorization_without_options,
        key_authorization_with_options,
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::super::super::models::{KeyType, PublicKey};
    use super::*;
    use crate::testing::*;

    #[test]
    fn it_parses_full_authorizations() {
        assert_that_cases(
            |i| key_authorization(i).unwrap().1,
            as_expected,
            vec![
                (
                    "ssh-ed25519 foobar==",
                    KeyAuthorization {
                        options: KeyOptions::new(),
                        key: PublicKey {
                            key_type: KeyType::SshEd25519,
                            encoded_key: "foobar==".to_owned(),
                        },
                        comments: "".to_owned(),
                    },
                ),
                (
                    "restrict ecdsa-sha2-nistp521 istestbase64",
                    KeyAuthorization {
                        options: vec![("restrict".to_owned(), None)],
                        key: PublicKey {
                            key_type: KeyType::EcdsaSha2Nistp521,
                            encoded_key: "istestbase64".to_owned(),
                        },
                        comments: "".to_owned(),
                    },
                ),
                (
                    "ssh-ed25519 foobar== now with comments",
                    KeyAuthorization {
                        options: KeyOptions::new(),
                        key: PublicKey {
                            key_type: KeyType::SshEd25519,
                            encoded_key: "foobar==".to_owned(),
                        },
                        comments: "now with comments".to_owned(),
                    },
                ),
                (
                    "restrict ecdsa-sha2-nistp521 istestbase64 also with comments",
                    KeyAuthorization {
                        options: vec![("restrict".to_owned(), None)],
                        key: PublicKey {
                            key_type: KeyType::EcdsaSha2Nistp521,
                            encoded_key: "istestbase64".to_owned(),
                        },
                        comments: "also with comments".to_owned(),
                    },
                ),
            ],
        );
    }
}
