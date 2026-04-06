use crate::config::{SOCKET_DIR, ssh_key_path};
use crate::crypto;
use crate::error::{ChatError, IoResultExt, Result};
use crate::permissions;
use crate::signal;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

const SESSION_KEY_BYTES: usize = 48; // 16 salt + 32 key

/// Remove a path only if it is a socket. Refuse if it is a symlink or other file type.
fn safe_remove_socket(path: &PathBuf) -> Result<()> {
    if path.exists() {
        let meta =
            std::fs::symlink_metadata(path).io_path_context(path, "checking existing socket")?;
        if meta.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        } else {
            return Err(ChatError::Io {
                context: format!(
                    "'{}' exists but is not a socket -- refusing to remove",
                    path.display()
                ),
                source: std::io::Error::new(std::io::ErrorKind::AlreadyExists, "not a socket"),
            });
        }
    }
    Ok(())
}

pub fn share_key(target_username: &str, world: bool, shutdown: &AtomicBool) -> Result<()> {
    let session_key = crypto::generate_session_key(&ssh_key_path()?)?;

    permissions::ensure_socket_dir()?;

    let pid = std::process::id();
    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/key_exchange_{pid}.sock"));
    safe_remove_socket(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)
        .io_path_context(&socket_path, "binding key exchange socket")?;
    listener
        .set_nonblocking(true)
        .io_context("setting key exchange socket to non-blocking")?;
    permissions::set_socket_permissions(&socket_path, world)?;

    println!("Waiting for {target_username} to receive the key...");
    println!("On {target_username}'s terminal, run: unix-chat receive-key {pid}");

    loop {
        if signal::shutdown_requested(shutdown) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let key_bytes = session_key.to_bytes();
                stream
                    .write_all(&key_bytes)
                    .io_context("sending session key to recipient")?;
                stream.flush()?;
                let sas = crypto::short_auth_string(&session_key.key);
                println!("Key shared with {target_username}");
                println!("Verification code: {sas}");
                println!("Ask {target_username} to confirm this code matches.");
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Key exchange failed: {e}");
                break;
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

pub fn receive_key(pid: u32) -> Result<()> {
    let own_username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/key_exchange_{pid}.sock"));

    println!("Receiving encryption key...");

    let mut stream = UnixStream::connect(&socket_path).map_err(|e| {
        ChatError::ConnectionRefused(format!("Failed to connect to key exchange socket: {e}"))
    })?;

    let mut buf = [0u8; SESSION_KEY_BYTES];
    stream
        .read_exact(&mut buf)
        .io_context("reading session key from key exchange socket")?;

    let session_key = crypto::SessionKey::from_bytes(&buf)?;

    // Save the raw key bytes with restricted permissions.
    // Use create_new (O_EXCL) to avoid following symlinks planted by an attacker.
    let save_path = PathBuf::from(format!("/tmp/.unix_chat_received_key_{own_username}"));
    if let Ok(meta) = std::fs::symlink_metadata(&save_path) {
        if meta.file_type().is_symlink() {
            return Err(ChatError::Io {
                context: format!(
                    "'{}' is a symlink -- refusing to write (possible attack)",
                    save_path.display()
                ),
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "symlink at key path",
                ),
            });
        }
        std::fs::remove_file(&save_path).io_path_context(&save_path, "removing old key file")?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&save_path)
        .io_path_context(&save_path, "saving received key to")?;
    file.write_all(&buf)
        .io_path_context(&save_path, "writing received key to")?;

    let sas = crypto::short_auth_string(&session_key.key);
    println!("Encryption key received and saved");
    println!("Verification code: {sas}");
    println!("Confirm this code matches the sender's display.");
    Ok(())
}
