use std::fmt;

#[derive(Debug)]
pub enum ChatError {
    Io { source: std::io::Error, context: String },
    PermissionDenied { path: String, operation: String },
    Crypto(String),
    KeyNotFound(String),
    ConnectionRefused(String),
    InvalidPassword,
    SshKeyMissing(String),
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatError::Io { source, context } => write!(f, "{context}: {source}"),
            ChatError::PermissionDenied { path, operation } => {
                write!(f, "Permission denied {operation} '{path}'.\n")?;
                write!(f, "  Check that you have the correct file permissions and group membership.\n")?;
                write!(f, "  Run 'unix-chat init' to diagnose your environment.")
            }
            ChatError::Crypto(msg) => write!(f, "Encryption error: {msg}"),
            ChatError::KeyNotFound(path) => write!(f, "Key file not found: {path}"),
            ChatError::ConnectionRefused(msg) => write!(f, "Connection refused: {msg}"),
            ChatError::InvalidPassword => {
                write!(f, "Invalid password. Check that you're using the same password the server was started with.")
            }
            ChatError::SshKeyMissing(path) => {
                write!(f, "SSH key not found at {path}. Run 'unix-chat init' to generate one.")
            }
        }
    }
}

impl std::error::Error for ChatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChatError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ChatError {
    fn from(e: std::io::Error) -> Self {
        ChatError::Io { source: e, context: "I/O error".into() }
    }
}

/// Extension trait for adding context to `std::io::Result` values.
pub trait IoResultExt<T> {
    /// Add a context string to an IO error. Automatically promotes `PermissionDenied`
    /// errors to `ChatError::PermissionDenied` when a path is provided.
    fn io_context(self, context: impl Into<String>) -> Result<T>;

    /// Add context with a file path. Permission errors are promoted to
    /// `ChatError::PermissionDenied` with the path included.
    fn io_path_context(self, path: &std::path::Path, operation: &str) -> Result<T>;
}

impl<T> IoResultExt<T> for std::io::Result<T> {
    fn io_context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| ChatError::Io { source: e, context: context.into() })
    }

    fn io_path_context(self, path: &std::path::Path, operation: &str) -> Result<T> {
        self.map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ChatError::PermissionDenied {
                    path: path.display().to_string(),
                    operation: operation.into(),
                }
            } else {
                ChatError::Io {
                    context: format!("{operation} '{}'", path.display()),
                    source: e,
                }
            }
        })
    }
}

pub type Result<T> = std::result::Result<T, ChatError>;
