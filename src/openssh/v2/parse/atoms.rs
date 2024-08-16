use nom::branch::alt;
use nom::bytes::complete::{escaped, is_a, is_not, tag, take, take_while1};
use nom::character::complete::{anychar, char, space0};
use nom::combinator::{recognizec, value};
use nom::error::{ErrorKind, ParseError};
use nom::multi::count;
use nom::sequence::{delimitedc, pairc};
use nom::IResult;

/// Parse valid whitespace.
pub(crate) fn whitespace(input: &str) -> IResult<&str, &str> {
    is_a(" \t")(input)
}

/// Parse an identifier from the start of the input.
///
/// An identifier begins with an alphabetic character, ends with an alphanumeric
/// character, and can have alphanumeric characters (or certain punctuation marks) in the middle.
pub(crate) fn identifier(input: &str) -> IResult<&str, &str> {
    let res =
        take_while1(|c: char| c.is_alphanumeric() || c == '-' || c == '@' || c == '.')(input)?;

    let first_char = res.1.chars().nth(0).unwrap();
    let last_char = res.1.chars().last().unwrap();

    if !first_char.is_ascii_alphabetic() || !last_char.is_ascii_alphanumeric() {
        return Err(nom::Err::Error(ParseError::from_error_kind(
            input,
            ErrorKind::Char,
        )));
    }

    Ok(res)
}

/// Parse an escapable string.
pub(crate) fn string(input: &str) -> IResult<&str, &str> {
    alt((value("", tag(r#""""#)), |inner| {
        delimitedc(
            inner,
            char('"'),
            escaped(is_not(r#"\""#), '\\', anychar),
            char('"'),
        )
    }))(input)
}

/// Indicates whether the character is a valid base64 body character.
///
/// Base64 body characters are alphanumeric, a '+' or a '/'.
fn is_base64_body_char(input: char) -> bool {
    input.is_ascii_alphanumeric() || input == '+' || input == '/'
}

/// Parse a valid base64 padded string from the start of input.
pub(crate) fn base64(input: &str) -> IResult<&str, &str> {
    let base_res = take_while1(is_base64_body_char)(input)?;

    let remainder = base_res.1.len() % 4;

    let res = if remainder == 1 {
        return Err(nom::Err::Error(ParseError::from_error_kind(
            input,
            ErrorKind::TakeWhile1,
        )));
    } else if remainder == 2 || remainder == 3 {
        let data_char_len = base_res.1.len();

        recognizec(input, |i| {
            pairc(i, take(data_char_len), count(char('='), 4 - remainder))
        })?
    } else {
        base_res
    };

    if res.0.chars().next().map(|c| c.is_ascii_whitespace()) == Some(false) {
        is_a(" ")(res.0)?;
    }

    Ok(res)
}

/// Parse the rest of the line (or input) as comments.
pub(crate) fn comments(input: &str) -> IResult<&str, &str> {
    alt((is_not("\r\n"), space0))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    #[test]
    fn parses_identifiers() {
        assert_that_cases(
            |i| identifier(i).unwrap().1,
            as_expected,
            vec![
                ("a ", "a"),
                ("a", "a"),
                ("A", "A"),
                ("hello-world", "hello-world"),
                ("x1", "x1"),
                ("ssh-ed25519", "ssh-ed25519"),
            ],
        )
    }

    #[test]
    fn rejects_invalid_identifiers() {
        assert_cases_err(identifier, vec!["1a", "-A", "A-", "@ca-certificate"]);
    }

    #[test]
    fn parses_strings() {
        assert_that_cases(
            |i| string(i).unwrap().1,
            as_expected,
            vec![
                (r#""""#, ""),
                (r#""uptime""#, "uptime"),
                (r#""echo \"Hello,\nworld!\"""#, r#"echo \"Hello,\nworld!\""#),
            ],
        )
    }

    #[test]
    fn rejects_invalid_strings() {
        assert_cases_err(
            string,
            vec![
                // does not start with quote
                (r#"a"""#),
                // unterminated string
                (r#""no end in sight"#),
                // unterminated due to escaping
                (r#""\""#),
            ],
        );
    }

    #[test]
    fn parses_base64() {
        assert_that_cases(
            |i| base64(i).unwrap().1,
            as_expected,
            vec![
                ("foobar==", "foobar=="),
                (
                    "FullerRangeOfCharacters+/1==",
                    "FullerRangeOfCharacters+/1==",
                ),
                ("lesspadding=", "lesspadding="),
                ("handlestrailingspace ", "handlestrailingspace"),
            ],
        )
    }

    #[test]
    fn rejects_invalid_base64() {
        assert_cases_err(
            base64,
            vec![
                // 13 characters and unpadded
                ("unpaddedvalue"),
                // 3 === is invalid
                ("twoequalsatmo==="),
                // character trailing the end must be whitespace
                ("validwithtrailingchars==a"),
                // equals must pad to a multiple of 4, and not have trailing chars
                ("invalidvalueis=a"),
            ],
        );
    }

    #[test]
    fn parses_comments() {
        assert_that_cases(
            |i| comments(i).unwrap().1,
            as_expected,
            vec![
                ("", ""),
                ("these are some\ncomments", "these are some"),
                ("just these four thanks", "just these four thanks"),
            ],
        )
    }
}
