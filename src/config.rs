use std::path::PathBuf;

use crate::error::{ChatError, Result};

pub const APP_NAME: &str = "unix_chat";
pub const SOCKET_DIR: &str = "/tmp/unix_chat_sockets";
pub const SOCKET_GROUP: &str = "unixchat";

pub fn ssh_key_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| {
        ChatError::Crypto("HOME environment variable is not set. Cannot locate SSH key.".into())
    })?;
    Ok(PathBuf::from(format!("{home}/.ssh/id_ed25519_{APP_NAME}")))
}
