use std::{fmt, str::FromStr};

/// The name of a secret, such as `kanidm/oauth2/freshrss`.
///
/// A name is one or more segments that a `/` separates.
/// A segment starts with `a-z` or `0-9` and goes on with `a-z`, `0-9`, `.`, `_` and `-`.
/// So no segment is empty, `.` or `..`, and a name is always a safe relative path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

#[derive(Debug, thiserror::Error)]
#[error(
    "a secret name is segments of `a-z`, `0-9`, `.`, `_` and `-` that start with `a-z` or `0-9` and that a `/` separates"
)]
pub struct NameError;

impl Name {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, NameError> {
        let lower = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        let valid = text.split('/').all(|segment| {
            segment.as_bytes().first().is_some_and(lower)
                && segment
                    .bytes()
                    .all(|byte| lower(&byte) || b"._-".contains(&byte))
        });
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(NameError)
        }
    }
}
