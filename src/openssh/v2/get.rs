use super::models::{KeyAuthorization, PublicKey};
#[cfg(feature = "key_encoding")]
use data_encoding::BASE64;

impl KeyAuthorization {
    /// Key options, formatted in the `authorized_keys` compatible manner.
    pub fn options_string(&self) -> String {
        self.options
            .iter()
            .map(|(name, val)| match val {
                Some(v) => format!("{}=\"{}\"", name, v),
                None => name.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl PublicKey {
    #[cfg(feature = "key_encoding")]
    /// Public key, decoded into bytes.
    pub fn data_bytes(&self) -> Result<Vec<u8>, data_encoding::DecodeError> {
        BASE64.decode(self.encoded_key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::KeyAuthorization;

    #[test]
    fn it_generates_an_option_string() {
        let mut subject = KeyAuthorization::default();

        subject.options = vec![
            ("option1".to_owned(), None),
            ("option2".to_owned(), Some("has a value".to_owned())),
            ("option3".to_owned(), None),
        ];

        assert_eq!(
            r#"option1,option2="has a value",option3"#,
            subject.options_string()
        );
    }

    #[cfg(feature = "key_encoding")]
    #[test]
    fn it_gets_key_bytes() {
        let data_str: &str = "MTIzNDU2Nzg=";
        let data: &[u8] = &[49, 50, 51, 52, 53, 54, 55, 56];

        let mut subject = KeyAuthorization::default();
        subject.key.encoded_key = data_str.to_owned();

        assert_eq!(
            data.to_vec(),
            subject.key.data_bytes().expect("decoding should succeed")
        );
    }
}
