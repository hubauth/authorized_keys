#[doc(inline)]
pub use super::constants::KeyType;
use std::iter::FromIterator;

/// A key or key/value token which set parameters on the way the
/// given public key is used by OpenSSH.
///
/// Inner slashes or double-quotes must be escaped.
///
/// ```
/// use authorized_keys::openssh::v2::KeyOption;
///
/// let simple_option: KeyOption = ("no-agent-forwarding".to_owned(), None);
/// let value_option: KeyOption = ("command".to_owned(), Some("echo \\\"Hello, world!\\\"".to_owned()));
/// ```
pub type KeyOption = (String, Option<String>);
/// A list of `KeyOption` structs, suitable for placement in front of an
/// `AuthorizedKey`.
pub type KeyOptions = Vec<KeyOption>;

/// Represents a public key for authorization
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Type of key (e.g. `ssh-rsa` -> `AuthorizedKeyType::SshRsa`)
    pub key_type: KeyType,
    /// Public key data, base64 encoded
    pub encoded_key: String,
}

impl PublicKey {
    #[must_use]
    /// Create a representation of a public key
    pub fn new(key_type: KeyType, encoded_key: String) -> Self {
        Self {
            key_type,
            encoded_key,
        }
    }
}

/// Represents the format of a key in an OpenSSH v2 `authorized_keys`
/// file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyAuthorization {
    /// Options applied to the key
    pub options: KeyOptions,
    /// Public key type and data
    pub key: PublicKey,
    /// Comments written at the end of the `authorized_keys` line
    pub comments: String,
}

/// Represents a valid line in an `authorized_keys` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysFileLine {
    /// A comment line: begins with a "#", or is only whitespace.
    Comment(String),
    /// An authorized key line.
    Key(KeyAuthorization),
}

/// Represents an `authorized_keys` file.
#[derive(Debug, Default, Clone)]
pub struct KeysFile {
    /// Lines of the `authorized_keys` file
    pub lines: Vec<KeysFileLine>,
}

impl FromIterator<KeysFileLine> for KeysFile {
    fn from_iter<I: IntoIterator<Item = KeysFileLine>>(i: I) -> Self {
        Self {
            lines: i.into_iter().collect::<Vec<_>>(),
        }
    }
}

impl IntoIterator for KeysFile {
    type Item = KeysFileLine;
    type IntoIter = ::std::vec::IntoIter<KeysFileLine>;

    fn into_iter(self) -> Self::IntoIter {
        self.lines.into_iter()
    }
}
