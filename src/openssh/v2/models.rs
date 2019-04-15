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

/// Represents the key type of an authorized public key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedKeyType {
    /// `ecdsa-sha2-nistp256`
    EcdsaSha2Nistp256,
    /// `ecdsa-sha2-nistp384`
    EcdsaSha2Nistp384,
    /// `ecdsa-sha2-nistp521`
    EcdsaSha2Nistp521,
    /// `ssh-ed25519`
    SshEd25519,
    /// `ssh-dss` (for DSA)
    SshDss,
    /// `ssd-rsa`
    SshRsa,
}

impl Default for AuthorizedKeyType {
    fn default() -> Self {
        AuthorizedKeyType::SshRsa
    }
}

/// Represents the format of a key in an OpenSSH v2 `authorized_keys`
/// file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuthorizedKey {
    /// Options applied to the key
    pub options: KeyOptions,
    /// Type of key (e.g. `ssh-rsa` -> `AuthorizedKeyType::SshRsa`)
    pub key_type: AuthorizedKeyType,
    /// Public key, base64 encoded
    pub encoded_key: String,
    /// Comments written at the end of the `authorized_keys` line
    pub comments: String,
}

/// Represents a valid line in an `authorized_keys` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedKeysFileLine {
    /// A comment line: begins with a "#", or is only whitespace.
    Comment(String),
    /// An authorized key line.
    AuthorizedKey(AuthorizedKey),
}

/// Represents an `authorized_keys` file.
#[derive(Debug, Default, Clone)]
pub struct AuthorizedKeysFile {
    /// Lines of the `authorized_keys` file
    pub lines: Vec<AuthorizedKeysFileLine>,
}

impl FromIterator<AuthorizedKeysFileLine> for AuthorizedKeysFile {
    fn from_iter<I: IntoIterator<Item = AuthorizedKeysFileLine>>(i: I) -> Self {
        Self {
            lines: i.into_iter().collect::<Vec<_>>(),
        }
    }
}

impl IntoIterator for AuthorizedKeysFile {
    type Item = AuthorizedKeysFileLine;
    type IntoIter = ::std::vec::IntoIter<AuthorizedKeysFileLine>;

    fn into_iter(self) -> Self::IntoIter {
        self.lines.into_iter()
    }
}
