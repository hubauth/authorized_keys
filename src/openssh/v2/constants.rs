pub const ECDSA_SHA2_NISTP256: &str = "ecdsa-sha2-nistp256";
pub const ECDSA_SHA2_NISTP384: &str = "ecdsa-sha2-nistp384";
pub const ECDSA_SHA2_NISTP521: &str = "ecdsa-sha2-nistp521";
pub const SSH_ED25519: &str = "ssh-ed25519";
pub const SSH_DSS: &str = "ssh-dss";
pub const SSH_RSA: &str = "ssh-rsa";

/// Represents the key type of an authorized public key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
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

impl Default for KeyType {
    fn default() -> Self {
        KeyType::SshRsa
    }
}
