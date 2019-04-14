use super::models::*;
#[cfg(feature = "key_encoding")]
use data_encoding::BASE64;

fn basic_escape(val: &str) -> String {
    val.replace("\\", "\\\\").replace("\"", "\\\"").to_owned()
}

impl AuthorizedKey {
    /// Adds a `KeyOption` to the key's options, without escaping the
    /// value.
    pub fn raw_option(mut self, option: KeyOption) -> Self {
        self.options.push(option);

        self
    }

    /// Adds a `KeyOption` to the key's options, escaping any
    /// double-quotes and slashes. Does not avoid double-escapes.
    pub fn option(self, option: KeyOption) -> Self {
        self.raw_option((option.0, option.1.map(|v| basic_escape(&v))))
    }

    /// Adds a `KeyOption` to the key's option, where the option is
    /// (`name`, None).
    pub fn option_name(self, name: String) -> Self {
        self.raw_option((name, None))
    }

    /// Removes all options from the key.
    pub fn clear_options(mut self) -> Self {
        self.options.truncate(0);

        self
    }

    /// Removes all options with the given option name.
    pub fn remove_named_options(mut self, name: &str) -> Self {
        self.options = self
            .options
            .into_iter()
            .filter(|(n, _)| n != name)
            .collect::<Vec<_>>();

        self
    }

    /// Remove all options with the given name and value.
    pub fn remove_options(mut self, option: &KeyOption) -> Self {
        self.options = self
            .options
            .into_iter()
            .filter(|v| v.0 != option.0 || v.1 != option.1)
            .collect::<Vec<_>>();

        self
    }

    /// Removes the comments field for the key.
    pub fn remove_comments(mut self) -> Self {
        self.comments = "".to_owned();

        self
    }

    /// Sets the comments field to the provided value.
    pub fn comments(mut self, val: String) -> Self {
        self.comments = val;

        self
    }

    /// Sets the key type to the provided value.
    pub fn key_type(mut self, val: String) -> Self {
        self.key_type = val;

        self
    }

    /// Sets the encoded key to the provided value.
    pub fn encoded_key(mut self, val: String) -> Self {
        self.encoded_key = val;

        self
    }

    /// Sets the encoded key to the base64 representation of the given
    /// bytes.
    #[cfg(feature = "key_encoding")]
    pub fn key_from_bytes(self, bytes: &[u8]) -> Self {
        self.encoded_key(BASE64.encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizedKey;

    #[test]
    fn it_adds_options() {
        let subject = AuthorizedKey::default()
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
            r#"command="echo \"hello, world!\"",baz,command="echo \"goodbye, world!\""  "#
        )
    }

    #[test]
    fn it_removes_options() {
        let subject = AuthorizedKey {
            options: vec![
                ("foo".to_owned(), Some("bar".to_owned())),
                ("foo".to_owned(), Some("baz".to_owned())),
                ("foo".to_owned(), None),
                ("quz".to_owned(), None),
            ],
            key_type: "".to_owned(),
            encoded_key: "".to_owned(),
            comments: "".to_owned(),
        };

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
                .clone()
                .remove_options(&("foo".to_owned(), Some("miss".to_owned())))
                .options
                .len()
        );
    }

    #[test]
    fn it_edits_comments() {
        let subject = AuthorizedKey::default().comments("test".to_owned());

        assert_eq!("test", subject.comments);
        assert_eq!("", subject.remove_comments().comments);
    }

    #[test]
    fn it_sets_key_parameters() {
        let subject = AuthorizedKey::default()
            .key_type("ssh-rsa".to_owned())
            .encoded_key("thisisvalidbase64/==".to_owned());

        assert_eq!("ssh-rsa", subject.key_type);
        assert_eq!("thisisvalidbase64/==", subject.encoded_key);
    }

    #[cfg(feature = "key_encoding")]
    #[test]
    fn it_sets_key_bytes() {
        let data_str: &str = "MTIzNDU2Nzg=";
        let data: &[u8] = &[49, 50, 51, 52, 53, 54, 55, 56];

        assert_eq!(
            data_str,
            AuthorizedKey::default().key_from_bytes(data).encoded_key
        );
    }
}
