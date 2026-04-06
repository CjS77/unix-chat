use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use crate::config::{SOCKET_DIR, ssh_key_path};
use crate::crypto;
use crate::error::{IoResultExt, Result};
use crate::permissions;
use crate::signal;

const SESSION_KEY_BYTES: usize = 48; // 16 salt + 32 key

pub fn share_key(target_username: &str, world: bool, shutdown: &AtomicBool) -> Result<()> {
    let session_key = crypto::generate_session_key(&ssh_key_path())?;

    permissions::ensure_socket_dir()?;

    let pid = std::process::id();
    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/key_exchange_{pid}.sock"));
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .io_path_context(&socket_path, "binding key exchange socket")?;
    listener.set_nonblocking(true).io_context("setting key exchange socket to non-blocking")?;
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
                stream.write_all(&key_bytes).io_context("sending session key to recipient")?;
                stream.flush()?;
                println!("Key shared with {target_username}");
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

    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| crate::error::ChatError::ConnectionRefused(format!("Failed to connect to key exchange socket: {e}")))?;

    let mut buf = [0u8; SESSION_KEY_BYTES];
    stream.read_exact(&mut buf).io_context("reading session key from key exchange socket")?;

    // Save the raw key bytes for later use by `connect`
    let save_path = PathBuf::from(format!("/tmp/.unix_chat_received_key_{own_username}"));
    std::fs::write(&save_path, &buf).io_path_context(&save_path, "saving received key to")?;

    // Restrict permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&save_path, std::fs::Permissions::from_mode(0o600))
            .io_path_context(&save_path, "restricting permissions on key file")?;
    }

    println!("Encryption key received and saved");
    Ok(())
}
