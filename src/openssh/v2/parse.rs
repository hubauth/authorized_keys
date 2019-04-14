use super::models::*;
use pest::error::Error;
use pest::iterators::Pair;
use pest::Parser;
use std::str::FromStr;

#[derive(Parser)]
#[grammar = "openssh/v2/grammar.pest"]
struct AuthorizedKeyParser;

impl FromStr for AuthorizedKey {
    type Err = Error<Rule>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut pairs = AuthorizedKeyParser::parse(Rule::key_line, s)?;

        Ok(Self::from_pair(pairs.next().unwrap()))
    }
}

impl FromStr for AuthorizedKeysFile {
    type Err = Error<Rule>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if s.ends_with('\n') || s.ends_with('\r') {
            s.to_owned()
        } else {
            s.to_owned() + "\n"
        };

        let mut pairs = AuthorizedKeyParser::parse(Rule::key_file, &s)?;

        Ok(Self::from_pair(pairs.next().unwrap()))
    }
}

impl AuthorizedKeysFile {
    fn from_pair(root_pair: Pair<Rule>) -> Self {
        assert!(root_pair.as_rule() == Rule::key_file);

        Self {
            lines: root_pair
                .into_inner()
                .flat_map(|inner_pair| match inner_pair.as_rule() {
                    Rule::comment_line => Some(AuthorizedKeysFileLine::Comment(
                        inner_pair.as_str().to_owned(),
                    )),
                    Rule::key_line => Some(AuthorizedKeysFileLine::AuthorizedKey(
                        AuthorizedKey::from_pair(inner_pair),
                    )),
                    Rule::EOI => None,
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>(),
        }
    }
}

impl AuthorizedKey {
    fn from_pair(root_pair: Pair<Rule>) -> Self {
        assert!(root_pair.as_rule() == Rule::key_line);

        let mut key = Self::default();

        for pair in root_pair.into_inner() {
            match pair.as_rule() {
                Rule::options => {
                    for option_pair in pair.into_inner() {
                        let innards = option_pair.into_inner().collect::<Vec<_>>();

                        key.options.push(match innards.len() {
                            2 => {
                                let quoted_val = innards[1].as_str();
                                let inner_val = quoted_val
                                    .chars()
                                    .skip(1)
                                    .take(quoted_val.len() - 2)
                                    .collect::<String>();

                                (innards[0].as_str().to_owned(), Some(inner_val))
                            }
                            1 => (innards[0].as_str().to_owned(), None),
                            _ => unreachable!(),
                        });
                    }
                }
                Rule::key => {
                    for inner_pair in pair.into_inner() {
                        match inner_pair.as_rule() {
                            Rule::key_type => {
                                key.key_type = inner_pair.as_str().to_owned();
                            }
                            Rule::encoded_key => {
                                key.encoded_key = inner_pair.as_str().to_owned();
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                Rule::key_comment => {
                    key.comments = pair.as_str().to_owned();
                }
                _ => unreachable!(),
            }
        }

        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_a_minimal_key() {
        let key_str: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM";

        let key = AuthorizedKey::from_str(key_str).expect("should parse key successfully");

        assert_eq!("ssh-ed25519", key.key_type);
        assert_eq!(
            "AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM",
            key.encoded_key
        );
    }

    #[test]
    fn it_parses_a_key_with_a_comment() {
        let key_str: &str = "ssh-ed25519 AAAAtHUM hello, world!";

        let key = AuthorizedKey::from_str(key_str).expect("should parse key successfully");

        assert_eq!("hello, world!", key.comments);
    }

    #[test]
    fn it_parses_a_name_option() {
        let key_str: &str = "no-agent-forwarding ssh-ed25519 AAAAtHUM";

        let key = AuthorizedKey::from_str(key_str).expect("should parse key successfully");

        assert_eq!(vec![("no-agent-forwarding".to_owned(), None)], key.options);
    }

    #[test]
    fn it_parses_a_value_option() {
        let key_str: &str = r#"command="echo hello" ssh-ed25519 AAAAtHUM"#;

        let key = AuthorizedKey::from_str(key_str).expect("should parse key successfully");

        assert_eq!(
            vec![("command".to_owned(), Some("echo hello".to_owned()))],
            key.options
        );
    }

    #[test]
    fn it_parses_a_complex_line() {
        let key_str: &str =
            r#"no-agent-forwarding,command="echo \"hello\"",restrict ssh-ed25519 AAAAtHUM comment value here"#;

        let key = AuthorizedKey::from_str(key_str).expect("should parse key successfully");

        assert_eq!(
            vec![
                ("no-agent-forwarding".to_owned(), None),
                ("command".to_owned(), Some(r#"echo \"hello\""#.to_owned())),
                ("restrict".to_owned(), None),
            ],
            key.options
        );

        assert_eq!("ssh-ed25519", key.key_type);
        assert_eq!("AAAAtHUM", key.encoded_key);
        assert_eq!("comment value here", key.comments);
    }

    #[test]
    fn it_parses_an_empty_keys_file() {
        let file: &str = "";
        let expected: Vec<AuthorizedKeysFileLine> =
            vec![AuthorizedKeysFileLine::Comment("".to_owned())];

        assert_eq!(expected, AuthorizedKeysFile::from_str(file).unwrap().lines);
    }

    #[test]
    fn it_parses_an_basic_keys_file() {
        let file: &str = "ssh-ed25519 AAAAtHUM";
        let expected: Vec<AuthorizedKeysFileLine> =
            vec![AuthorizedKeysFileLine::AuthorizedKey(AuthorizedKey {
                options: KeyOptions::default(),
                key_type: "ssh-ed25519".to_owned(),
                encoded_key: "AAAAtHUM".to_owned(),
                comments: "".to_owned(),
            })];

        assert_eq!(expected, AuthorizedKeysFile::from_str(file).unwrap().lines);
    }

    #[test]
    fn it_parses_an_basic_keys_file_with_two_comment_lines() {
        let file: &str = "# hello, world!\n\nssh-ed25519 AAAAtHUM";
        let expected: Vec<AuthorizedKeysFileLine> = vec![
            AuthorizedKeysFileLine::Comment("# hello, world!".to_owned()),
            AuthorizedKeysFileLine::Comment("".to_owned()),
            AuthorizedKeysFileLine::AuthorizedKey(AuthorizedKey {
                options: KeyOptions::default(),
                key_type: "ssh-ed25519".to_owned(),
                encoded_key: "AAAAtHUM".to_owned(),
                comments: "".to_owned(),
            }),
        ];

        assert_eq!(expected, AuthorizedKeysFile::from_str(file).unwrap().lines);
    }
}
