use std::path::PathBuf;

pub const APP_NAME: &str = "unix_chat";
pub const SOCKET_DIR: &str = "/tmp/unix_chat_sockets";
pub const SOCKET_GROUP: &str = "unixchat";

pub fn ssh_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(format!("{home}/.ssh/id_ed25519_{APP_NAME}"))
}
