#![allow(clippy::assertions_on_constants)]

use spectral::result::ResultAssertions;
use spectral::{assert_that, Spec};
use std::fmt::Debug;

pub(crate) fn assert_that_cases<G, A, I, O>(test_fn: G, verification_fn: A, cases: Vec<(I, O)>)
where
    G: Fn(I) -> O,
    A: Fn((O, Spec<O>)),
    I: Sized + Clone + Debug,
    O: Sized + Clone + Debug,
{
    for (input, expected) in cases {
        let disp = format!("{:?}", &input);

        let actual = test_fn(input);
        verification_fn((expected, assert_that(&actual).named(&disp)));
    }
}

pub(crate) fn assert_cases_err<G, I, A, E>(test_fn: G, cases: Vec<I>)
where
    G: Fn(I) -> Result<A, E>,
    I: Sized + Debug,
    A: Debug,
    E: Debug,
{
    for input in cases {
        let disp = format!("{:?}", &input);

        let actual = test_fn(input);

        assert_that(&actual).named(&disp).is_err();
    }
}

pub(crate) fn as_expected<O>((expected, mut spec): (O, Spec<O>))
where
    O: PartialEq + Sized + Debug,
{
    spec.is_equal_to(expected)
}
