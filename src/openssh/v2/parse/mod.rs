mod atoms;
mod full;
mod mapped;
mod parts;

use super::models::{KeyAuthorization, KeysFile, KeysFileLine};
use std::str::FromStr;

impl FromStr for KeyAuthorization {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        full::key_authorization(s)
            .map(|(_, res)| res)
            .map_err(|e| match e {
                nom::Err::Incomplete(_) => unreachable!(),
                nom::Err::Error(err) | nom::Err::Failure(err) => err.0.to_string(),
            })
    }
}

impl FromStr for KeysFile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let in_lines = s.lines().enumerate().collect::<Vec<_>>();

        let mut lines: Vec<KeysFileLine> = Vec::with_capacity(in_lines.len());

        for (line_no, line) in in_lines {
            let comment_indicator = line.chars().skip_while(char::is_ascii_whitespace).next();

            // line was all whitespace, or first non-whitespace was comment char
            lines.push(
                if comment_indicator == None || comment_indicator == Some('#') {
                    KeysFileLine::Comment(line.to_owned())
                } else {
                    match line.parse() {
                        Ok(authorization) => KeysFileLine::Key(authorization),
                        Err(e) => {
                            return Err(format!(
                                "failed to parse line {}: {}",
                                line_no,
                                e.to_string()
                            ))
                        }
                    }
                },
            );
        }

        Ok(Self { lines })
    }
}
