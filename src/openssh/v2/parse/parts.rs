use super::atoms::*;
use nom::branch::alt;
use nom::character::complete::char;
use nom::multi::separated_listc;
use nom::sequence::separated_pairc;
use nom::IResult;

type RawKeyOption<'a> = (&'a str, Option<&'a str>);

pub(crate) fn option_without_value(input: &str) -> IResult<&str, RawKeyOption> {
    let id = identifier(input)?;

    Ok((id.0, (id.1, None)))
}

pub(crate) fn option_with_value(input: &str) -> IResult<&str, RawKeyOption> {
    let pair = separated_pairc(input, identifier, char('='), string)?;
    let val = pair.1;

    Ok((pair.0, (val.0, Some(val.1))))
}

pub(crate) fn option(input: &str) -> IResult<&str, RawKeyOption> {
    alt((option_with_value, option_without_value))(input)
}

pub(crate) fn options(input: &str) -> IResult<&str, Vec<RawKeyOption>> {
    separated_listc(input, char(','), option)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    #[test]
    fn it_parses_an_option_without_value() {
        assert_that_cases(
            |i| option_without_value(i).unwrap().1,
            as_expected,
            vec![
                ("restrict", ("restrict", None)),
                ("no-agent-forwarding", ("no-agent-forwarding", None)),
            ],
        );
    }

    #[test]
    fn it_parses_an_option_with_value() {
        assert_that_cases(
            |i| option_with_value(i).unwrap().1,
            as_expected,
            vec![
                ("command=\"\"", ("command", Some(""))),
                ("from=\"127.0.0.1\"", ("from", Some("127.0.0.1"))),
            ],
        );
    }

    #[test]
    fn it_parses_options() {
        assert_that_cases(
            |i| options(i).unwrap().1,
            as_expected,
            vec![
                ("restrict", vec![("restrict", None)]),
                ("command=\"uptime\"", vec![("command", Some("uptime"))]),
                (
                    "restrict,command=\"uptime \",no-agent-forwarding",
                    vec![
                        ("restrict", None),
                        ("command", Some("uptime ")),
                        ("no-agent-forwarding", None),
                    ],
                ),
            ],
        );
    }
}
