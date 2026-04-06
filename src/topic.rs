use std::fmt;
use std::str::FromStr;

const MAX_LEN: usize = 64;

/// A validated chat topic name used for socket and key file naming.
///
/// Rules:
/// - 1 to 64 characters
/// - Alphanumeric, hyphens, and underscores only (no spaces, slashes, dots, etc.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic(String);

fn is_valid_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn sanitize(s: &str) -> String {
    s.chars().filter(|c| is_valid_char(*c)).take(MAX_LEN).collect()
}

impl Topic {
    /// Create a Topic from the current system username.
    pub fn from_username() -> Self {
        let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
        let sanitised = sanitize(&username);
        Topic(if sanitised.is_empty() { "unknown".into() } else { sanitised })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Topic {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sanitised = sanitize(s);
        if sanitised.is_empty() {
            return Err("topic must contain at least one alphanumeric character, hyphen, or underscore".into());
        }
        if sanitised != s {
            return Err(format!("topic contains invalid characters; did you mean '{sanitised}'?"));
        }
        Ok(Topic(sanitised))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_topics() {
        assert!("general".parse::<Topic>().is_ok());
        assert!("dev-chat".parse::<Topic>().is_ok());
        assert!("room_42".parse::<Topic>().is_ok());
        assert!("Alice".parse::<Topic>().is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!("".parse::<Topic>().is_err());
    }

    #[test]
    fn rejects_spaces() {
        assert!("my room".parse::<Topic>().is_err());
    }

    #[test]
    fn rejects_slashes() {
        assert!("../etc".parse::<Topic>().is_err());
    }

    #[test]
    fn rejects_dots() {
        assert!("foo.bar".parse::<Topic>().is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(65);
        assert!(long.parse::<Topic>().is_err());
    }

    #[test]
    fn max_length_ok() {
        let exact = "a".repeat(64);
        assert!(exact.parse::<Topic>().is_ok());
    }

    #[test]
    fn suggests_sanitised_name() {
        let err = "my room!".parse::<Topic>().unwrap_err();
        assert!(err.contains("myroom"), "should suggest sanitised name, got: {err}");
    }
}
