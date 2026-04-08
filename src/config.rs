use std::path::PathBuf;

use crate::error::{ChatError, Result};

pub const APP_NAME: &str = "unix_chat";
pub const SOCKET_DIR: &str = "/tmp/unix_chat_sockets";
pub const SOCKET_GROUP: &str = "unixchat";

pub fn ssh_key_path() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(PathBuf::from(format!("{home}/.ssh/id_ed25519_{APP_NAME}")))
}

pub fn ssh_pub_key_path() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(PathBuf::from(format!(
        "{home}/.ssh/id_ed25519_{APP_NAME}.pub"
    )))
}

pub fn pubkey_dir() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(PathBuf::from(format!("{home}/unix-chat/pubkeys")))
}

pub fn peer_pubkey_path(peer: &str) -> Result<PathBuf> {
    let dir = pubkey_dir()?;
    Ok(dir.join(format!("id_ed25519_{APP_NAME}_{peer}.pub")))
}

fn home_dir() -> Result<String> {
    std::env::var("HOME").map_err(|_| {
        ChatError::Crypto("HOME environment variable is not set. Cannot locate SSH key.".into())
    })
}
