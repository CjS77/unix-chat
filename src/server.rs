use crate::chat_loop;
use crate::config::{SOCKET_DIR, ssh_key_path};
use crate::crypto;
use crate::error::{ChatError, IoResultExt, Result};
use crate::permissions;
use crate::signal;
use crate::topic::Topic;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

/// Guard that removes socket and key files on drop.
struct ServerGuard {
    socket_path: PathBuf,
    key_enc_path: Option<PathBuf>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(ref p) = self.key_enc_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

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

pub fn run(
    password: Option<&str>,
    topic: &Topic,
    world: bool,
    shutdown: &AtomicBool,
) -> Result<()> {
    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let session_key = crypto::generate_session_key(&ssh_key_path()?)?;

    permissions::ensure_socket_dir()?;

    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.sock"));
    safe_remove_socket(&socket_path)?;

    // Publish password-protected session key if requested
    let key_enc_path = if let Some(pwd) = password {
        let path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.key.enc"));
        let wrapped = crypto::wrap_key_with_password(&session_key, pwd)?;
        let mode = if world { 0o666 } else { 0o660 };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&path)
            .io_path_context(&path, "writing encrypted session key to")?;
        file.write_all(wrapped.as_bytes())
            .io_path_context(&path, "writing encrypted session key to")?;
        // Set group ownership (permissions already correct from open)
        permissions::set_socket_permissions(&path, world)?;
        println!(
            "Session key published (password-protected) at {}",
            path.display()
        );
        Some(path)
    } else {
        None
    };

    let _guard = ServerGuard {
        socket_path: socket_path.clone(),
        key_enc_path,
    };

    let listener =
        UnixListener::bind(&socket_path).io_path_context(&socket_path, "binding server socket")?;
    listener
        .set_nonblocking(true)
        .io_context("setting server socket to non-blocking")?;
    permissions::set_socket_permissions(&socket_path, world)?;
    println!("Chat server started on {}", socket_path.display());
    println!("Waiting for connections...\n");

    // Accept loop -- survives client disconnects.
    // The listener is non-blocking so we poll with a short sleep to
    // check the shutdown flag, since signal-hook uses SA_RESTART.
    let mut last_connect = std::time::Instant::now();
    let mut rapid_count: u32 = 0;
    loop {
        if signal::shutdown_requested(shutdown) {
            println!("Shutting down...");
            break;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                let now = std::time::Instant::now();
                if now.duration_since(last_connect) < std::time::Duration::from_secs(1) {
                    rapid_count += 1;
                    if rapid_count >= 5 {
                        eprintln!(
                            "Warning: rapid reconnection detected ({rapid_count} in <1s). Possible abuse."
                        );
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                } else {
                    rapid_count = 0;
                }
                last_connect = now;

                stream.set_nonblocking(false)?;
                println!("Client connected!");
                chat_loop::run(stream, &session_key.key, &username);
                if signal::shutdown_requested(shutdown) {
                    break;
                }
                println!("\n(client disconnected, waiting for new connection...)");
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Accept error: {e}");
            }
        }
    }

    // _guard drops here, cleaning up socket and key files
    drop(_guard);
    Ok(())
}
