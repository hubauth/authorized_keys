use super::constants::*;
use super::models::*;
use std::str::FromStr;

impl FromStr for AuthorizedKeyType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            ECDSA_SHA2_NISTP256 => Ok(AuthorizedKeyType::EcdsaSha2Nistp256),
            ECDSA_SHA2_NISTP384 => Ok(AuthorizedKeyType::EcdsaSha2Nistp384),
            ECDSA_SHA2_NISTP521 => Ok(AuthorizedKeyType::EcdsaSha2Nistp521),
            SSH_ED25519 => Ok(AuthorizedKeyType::SshEd25519),
            SSH_DSS => Ok(AuthorizedKeyType::SshDss),
            SSH_RSA => Ok(AuthorizedKeyType::SshRsa),
            _ => Err(()),
        }
    }
}

struct AuthorizedKeyLinePartParser {
    in_quotes: bool,
    was_slash: bool,
    separator: char,
}

impl AuthorizedKeyLinePartParser {
    pub fn new(separator: char) -> Self {
        Self {
            in_quotes: false,
            was_slash: false,
            separator,
        }
    }

    pub fn still_part(&mut self, c: char) -> bool {
        if c == '\\' {
            // also handle double backslash
            self.was_slash = !self.was_slash;

            return true;
        } else if c == '"' && !self.was_slash {
            self.in_quotes = !self.in_quotes;
        } else if c == self.separator && !self.in_quotes {
            return false;
        }

        self.was_slash = false;
        true
    }

    pub fn reset(&mut self) {
        self.was_slash = false;
        self.in_quotes = false;
    }
}

struct AuthorizedKeyLineParser {}
impl AuthorizedKeyLineParser {
    fn parse_option_value(input: Option<String>) -> Option<String> {
        if let Some(mut val) = input {
            if let Some(to) = val.len().checked_sub(1) {
                Some(val.drain(1..to).collect::<String>())
            } else {
                None
            }
        } else {
            None
        }
    }

    fn parse_option(input: &str) -> KeyOption {
        let mut part_parser = AuthorizedKeyLinePartParser::new('=');
        let mut current_part: Vec<char> = Vec::with_capacity(32);
        let mut option_name: Option<String> = None;
        let mut option_raw_value: Option<String> = None;

        let mut chars = input.chars().peekable();

        while chars.peek().is_some() {
            if let Some(c) = chars.next() {
                if part_parser.still_part(c) {
                    current_part.push(c);
                } else {
                    part_parser.reset();

                    option_name = Some(current_part.drain(0..).collect());
                    option_raw_value = Some(chars.collect());
                    break;
                }
            }
        }

        if option_name.is_none() && !current_part.is_empty() {
            option_name = Some(current_part.drain(0..).collect());
        }

        (
            option_name.unwrap(),
            Self::parse_option_value(option_raw_value),
        )
    }

    fn parse_options(input: Option<String>) -> KeyOptions {
        if let Some(options_str) = input {
            let mut chars = options_str.chars().peekable();
            let mut part_parser = AuthorizedKeyLinePartParser::new(',');
            let mut current_part: Vec<char> = Vec::with_capacity(128);
            let mut options = KeyOptions::default();

            while chars.peek().is_some() {
                if let Some(c) = chars.next() {
                    if part_parser.still_part(c) {
                        current_part.push(c);
                    } else {
                        part_parser.reset();

                        options.push(Self::parse_option(
                            &current_part.drain(0..).collect::<String>(),
                        ));
                    }
                }
            }

            if !current_part.is_empty() {
                options.push(Self::parse_option(
                    &current_part.drain(0..).collect::<String>(),
                ))
            }

            options
        } else {
            KeyOptions::default()
        }
    }

    fn parse(s: &str) -> Result<AuthorizedKey, String> {
        let mut chars = s.chars().peekable();
        let mut part_parser = AuthorizedKeyLinePartParser::new(' ');
        let mut current_part: Vec<char> = Vec::with_capacity(1024);
        let mut options: Option<String> = None;
        let mut key_type: Option<AuthorizedKeyType> = None;
        let mut encoded_key: Option<String> = None;
        let mut comments = String::new();

        while chars.peek().is_some() {
            if encoded_key.is_some() {
                comments = chars.collect::<String>().trim().to_owned();
                break;

            // always true
            } else if let Some(c) = chars.next() {
                // handle consecutive spaces
                if c == ' ' && current_part.is_empty() {
                    continue;
                }

                if key_type.is_some() {
                    if part_parser.still_part(c) {
                        current_part.push(c);
                    } else {
                        part_parser.reset();

                        encoded_key = Some(current_part.drain(0..).collect());
                    }
                } else if part_parser.still_part(c) {
                    current_part.push(c);
                } else {
                    part_parser.reset();

                    let part = current_part.drain(0..).collect::<String>();

                    match AuthorizedKeyType::from_str(&part) {
                        Ok(t) => {
                            key_type = Some(t);
                        }
                        Err(_) => {
                            if options.is_some() {
                                return Err(format!("{} is not a recognised key type", part));
                            } else {
                                options = Some(part);
                            }
                        }
                    }
                }
            }
        }

        // if EOI and no encoded key, use current part as encoded key
        if encoded_key.is_none() && !current_part.is_empty() {
            encoded_key = Some(current_part.drain(0..).collect());
        }

        match key_type {
            Some(key_type) => match encoded_key {
                Some(encoded_key) => Ok(AuthorizedKey {
                    options: Self::parse_options(options),
                    key_type,
                    encoded_key,
                    comments,
                }),
                _ => Err("could not parse encoded key".to_owned()),
            },
            _ => Err("could not parse key type".to_owned()),
        }
    }
}

impl FromStr for AuthorizedKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AuthorizedKeyLineParser::parse(s)
    }
}

impl FromStr for AuthorizedKeysFile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines: Vec<AuthorizedKeysFileLine> = Vec::default();

        for (i, line) in s.lines().enumerate() {
            if line.starts_with('#') || line.chars().all(|c| c.is_ascii_whitespace()) {
                lines.push(AuthorizedKeysFileLine::Comment(line.to_owned()));
            } else {
                match AuthorizedKeyLineParser::parse(line) {
                    Ok(key) => lines.push(AuthorizedKeysFileLine::AuthorizedKey(key)),
                    Err(e) => return Err(format!("parsing failed on line {}: {}", i, e)),
                }
            }
        }

        Ok(Self { lines })
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

        assert_eq!(AuthorizedKeyType::SshEd25519, key.key_type);
        assert_eq!(
            "AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM",
            key.encoded_key
        );
    }

    #[test]
    fn it_parses_a_key_with_a_comment_through_consecutive_spaces() {
        let key_str: &str = "ssh-ed25519   AAAAtHUM   hello, world!";

        let key = AuthorizedKey::from_str(key_str).expect("should parse key successfully");

        assert_eq!("hello, world!", key.comments);
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

        assert_eq!(AuthorizedKeyType::SshEd25519, key.key_type);
        assert_eq!("AAAAtHUM", key.encoded_key);
        assert_eq!("comment value here", key.comments);
    }

    #[test]
    fn it_parses_an_empty_keys_file() {
        let file: &str = "";
        let expected: Vec<AuthorizedKeysFileLine> = vec![];

        assert_eq!(expected, AuthorizedKeysFile::from_str(file).unwrap().lines);
    }

    #[test]
    fn it_parses_an_basic_keys_file() {
        let file: &str = "ssh-ed25519 AAAAtHUM";
        let expected: Vec<AuthorizedKeysFileLine> =
            vec![AuthorizedKeysFileLine::AuthorizedKey(AuthorizedKey {
                options: KeyOptions::default(),
                key_type: AuthorizedKeyType::SshEd25519,
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
                key_type: AuthorizedKeyType::SshEd25519.to_owned(),
                encoded_key: "AAAAtHUM".to_owned(),
                comments: "".to_owned(),
            }),
        ];

        assert_eq!(expected, AuthorizedKeysFile::from_str(file).unwrap().lines);
    }
}
