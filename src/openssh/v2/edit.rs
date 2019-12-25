use super::models::{KeyAuthorization, KeyOption, KeyType, PublicKey};
#[cfg(feature = "key_encoding")]
use data_encoding::BASE64;

fn basic_escape(val: &str) -> String {
    val.replace("\\", "\\\\").replace("\"", "\\\"")
}

impl KeyAuthorization {
    /// Adds a `KeyOption` to the key's options, without escaping the
    /// value.
    #[must_use]
    pub fn raw_option(mut self, option: KeyOption) -> Self {
        self.options.push(option);

        self
    }

    /// Adds a `KeyOption` to the key's options, escaping any
    /// double-quotes and slashes. Does not avoid double-escapes.
    #[must_use]
    pub fn option(self, option: KeyOption) -> Self {
        self.raw_option((option.0, option.1.map(|v| basic_escape(&v))))
    }

    /// Adds a `KeyOption` to the key's option, where the option is
    /// (`name`, None).
    #[must_use]
    pub fn option_name(self, name: String) -> Self {
        self.raw_option((name, None))
    }

    /// Removes all options from the key.
    #[must_use]
    pub fn clear_options(mut self) -> Self {
        self.options.truncate(0);

        self
    }

    /// Removes all options with the given option name.
    #[must_use]
    pub fn remove_named_options(mut self, name: &str) -> Self {
        self.options = self
            .options
            .into_iter()
            .filter(|(n, _)| n != name)
            .collect::<Vec<_>>();

        self
    }

    /// Remove all options with the given name and value.
    #[must_use]
    pub fn remove_options(mut self, option: &KeyOption) -> Self {
        self.options = self
            .options
            .into_iter()
            .filter(|v| v.0 != option.0 || v.1 != option.1)
            .collect::<Vec<_>>();

        self
    }

    /// Removes the comments field for the key.
    #[must_use]
    pub fn remove_comments(mut self) -> Self {
        self.comments = "".to_owned();

        self
    }

    /// Sets the comments field to the provided value.
    #[must_use]
    pub fn comments(mut self, val: String) -> Self {
        self.comments = val;

        self
    }

    /// Sets the public key to the provided value.
    #[must_use]
    pub fn key(mut self, key: PublicKey) -> Self {
        self.key = key;

        self
    }

    /// Sets the key type to the provided value.
    #[must_use]
    pub fn key_type(mut self, val: KeyType) -> Self {
        self.key.key_type = val;

        self
    }

    /// Sets the encoded key to the provided value.
    #[must_use]
    pub fn encoded_key(mut self, val: String) -> Self {
        self.key.encoded_key = val;

        self
    }

    /// Sets the public key data to the encoded form of the given bytes.
    #[cfg(feature = "key_encoding")]
    #[must_use]
    pub fn key_data_from_bytes(mut self, bytes: &[u8]) -> Self {
        self.key.encoded_key = BASE64.encode(bytes);

        self
    }
}

impl PublicKey {
    /// Sets the encoded key to the provided value.
    #[must_use]
    pub fn encoded_key(mut self, val: String) -> Self {
        self.encoded_key = val;

        self
    }

    /// Sets the key type to the provided value.
    #[must_use]
    pub fn key_type(mut self, val: KeyType) -> Self {
        self.key_type = val;

        self
    }

    /// Sets the encoded key to the base64 representation of the given
    /// bytes.
    #[must_use]
    #[cfg(feature = "key_encoding")]
    pub fn data_from_bytes(mut self, bytes: &[u8]) -> Self {
        self.encoded_key = BASE64.encode(bytes);

        self
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyAuthorization, KeyType, PublicKey};

    #[test]
    fn it_adds_options() {
        let subject = KeyAuthorization::default()
            .option((
                "command".to_owned(),
                Some(r#"echo "hello, world!""#.to_owned()),
            ))
            .option_name("baz".to_owned())
            .raw_option((
                "command".to_owned(),
                Some(r#"echo \"goodbye, world!\""#.to_owned()),
            ));

        assert_eq!(
            &subject.to_string(),
            r#"command="echo \"hello, world!\"",baz,command="echo \"goodbye, world!\"" ssh-rsa "#
        )
    }

    #[test]
    fn it_removes_options() {
        let mut subject = KeyAuthorization::default();
        subject.options = vec![
            ("foo".to_owned(), Some("bar".to_owned())),
            ("foo".to_owned(), Some("baz".to_owned())),
            ("foo".to_owned(), None),
            ("quz".to_owned(), None),
        ];

        assert_eq!(1, subject.clone().remove_named_options("foo").options.len());
        assert_eq!(
            3,
            subject
                .clone()
                .remove_options(&("foo".to_owned(), Some("bar".to_owned())))
                .options
                .len()
        );
        assert_eq!(
            3,
            subject
                .clone()
                .remove_options(&("foo".to_owned(), None))
                .options
                .len()
        );
        assert_eq!(
            4,
            subject
                .remove_options(&("foo".to_owned(), Some("miss".to_owned())))
                .options
                .len()
        );
    }

    #[test]
    fn it_edits_comments() {
        let subject = KeyAuthorization::default().comments("test".to_owned());

        assert_eq!("test", subject.comments);
        assert_eq!("", subject.remove_comments().comments);
    }

    #[test]
    fn it_sets_nested_key_parameters() {
        let subject = KeyAuthorization::default()
            .key_type(KeyType::SshRsa)
            .encoded_key("thisisvalidbase64/==".to_owned());

        assert_eq!(KeyType::SshRsa, subject.key.key_type);
        assert_eq!("thisisvalidbase64/==", subject.key.encoded_key);

        let subject = subject.key(PublicKey::new(
            KeyType::SshDss,
            "morevalidbase64=".to_owned(),
        ));

        assert_eq!(KeyType::SshDss, subject.key.key_type);
        assert_eq!("morevalidbase64=", subject.key.encoded_key);
    }

    #[test]
    fn it_sets_key_parameters() {
        let subject = PublicKey::default()
            .key_type(KeyType::SshRsa)
            .encoded_key("thisisvalidbase64/==".to_owned());

        assert_eq!(KeyType::SshRsa, subject.key_type);
        assert_eq!("thisisvalidbase64/==", subject.encoded_key);
    }

    #[cfg(feature = "key_encoding")]
    #[test]
    fn it_sets_nested_key_bytes() {
        let data_str: &str = "MTIzNDU2Nzg=";
        let data: &[u8] = &[49, 50, 51, 52, 53, 54, 55, 56];

        assert_eq!(
            data_str,
            KeyAuthorization::default()
                .key_data_from_bytes(data)
                .key
                .encoded_key
        );
    }

    #[cfg(feature = "key_encoding")]
    #[test]
    fn it_sets_key_bytes() {
        let data_str: &str = "MTIzNDU2Nzg=";
        let data: &[u8] = &[49, 50, 51, 52, 53, 54, 55, 56];

        assert_eq!(
            data_str,
            PublicKey::default().data_from_bytes(data).encoded_key
        );
    }
}
