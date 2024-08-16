#![allow(missing_docs)]

use crate::string_enum;

string_enum!(KeyType, {
    SkEcdsaSha2Nistp256 = "sk-ecdsa-sha2-nistp256@openssh.com",
    EcdsaSha2Nistp256 = "ecdsa-sha2-nistp256",
    EcdsaSha2Nistp384 = "ecdsa-sha2-nistp384",
    EcdsaSha2Nistp521 = "ecdsa-sha2-nistp521",
    SkSshEd25519 = "sk-ssh-ed25519@openssh.com",
    SshEd25519 = "ssh-ed25519",
    SshDss = "ssh-dss",
    SshRsa = "ssh-rsa"
});

impl Default for KeyType {
    fn default() -> Self {
        KeyType::SshRsa
    }
}
