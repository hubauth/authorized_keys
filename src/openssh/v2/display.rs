use super::models::{KeyAuthorization, KeysFile, KeysFileLine, PublicKey};
use std::fmt::{Display, Error, Formatter};

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{} {}", self.key_type, self.encoded_key)
    }
}

impl Display for KeyAuthorization {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let options = self.options_string();

        if !options.is_empty() {
            write!(f, "{} ", options)?;
        }
        write!(f, "{}", self.key)?;
        if !self.comments.trim().is_empty() {
            write!(f, " {}", self.comments.trim())?;
        }

        Ok(())
    }
}

impl Display for KeysFile {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        for line in &self.lines {
            match line {
                KeysFileLine::Comment(val) => writeln!(f, "{}", val)?,
                KeysFileLine::Key(val) => writeln!(f, "{}", val)?,
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::constants::KeyType;
    use super::{KeyAuthorization, PublicKey};

    #[test]
    fn it_writes_a_key() {
        let mut subject = KeyAuthorization::default();
        subject.key = PublicKey::new(
            KeyType::SshEd25519,
            "AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM".to_owned(),
        );

        assert_eq!(
            &subject.to_string(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM"
        );
    }

    #[test]
    fn it_writes_a_key_with_comments() {
        let mut subject = KeyAuthorization::default();
        subject.key = PublicKey::new(
            KeyType::SshEd25519,
            "AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM".to_owned(),
        );
        subject.comments = " the quick brown fox jumped over the lazy dog   ".to_owned();

        assert_eq!(&subject.to_string(), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM the quick brown fox jumped over the lazy dog");
    }

    #[test]
    fn it_writes_a_key_with_an_option() {
        let mut subject = KeyAuthorization::default();
        subject
            .options
            .push(("no-agent-forwarding".to_owned(), None));
        subject.key = PublicKey::new(
            KeyType::SshEd25519,
            "AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM".to_owned(),
        );

        assert_eq!(&subject.to_string(), "no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM");
    }

    #[test]
    fn it_writes_a_complex_key() {
        let mut subject = KeyAuthorization::default();
        subject
            .options
            .push(("no-agent-forwarding".to_owned(), None));
        subject.options.push((
            "command".to_owned(),
            Some("echo \\\"Hello, world!\\\"".to_owned()),
        ));
        subject
            .options
            .push(("environment".to_owned(), Some("PATH=/bin:/sbin".to_owned())));
        subject.options.push((
            "environment".to_owned(),
            Some("LOGNAME=ssh-user".to_owned()),
        ));
        subject.key = PublicKey::new(
            KeyType::SshEd25519,
            "AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM".to_owned(),
        );
        subject.comments = "this is a more complex example".to_owned();

        assert_eq!(&subject.to_string(), "no-agent-forwarding,command=\"echo \\\"Hello, world!\\\"\",environment=\"PATH=/bin:/sbin\",environment=\"LOGNAME=ssh-user\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgqo1o+dOHqeIc7A5MG53s5iYwpMQm7f3hnn+uxtHUM this is a more complex example");
    }
}
