use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use crate::config::{SOCKET_DIR, ssh_key_path};
use crate::crypto;
use crate::error::{IoResultExt, Result};
use crate::permissions;
use crate::signal;
use crate::chat_loop;
use crate::topic::Topic;

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

pub fn run(password: Option<&str>, topic: &Topic, world: bool, shutdown: &AtomicBool) -> Result<()> {
    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let session_key = crypto::generate_session_key(&ssh_key_path())?;

    permissions::ensure_socket_dir()?;

    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.sock"));
    // Remove stale socket
    let _ = std::fs::remove_file(&socket_path);

    // Publish password-protected session key if requested
    let key_enc_path = if let Some(pwd) = password {
        let path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.key.enc"));
        let wrapped = crypto::wrap_key_with_password(&session_key, pwd)?;
        std::fs::write(&path, &wrapped).io_path_context(&path, "writing encrypted session key to")?;
        permissions::set_socket_permissions(&path, world)?;
        println!("Session key published (password-protected) at {}", path.display());
        Some(path)
    } else {
        None
    };

    let _guard = ServerGuard { socket_path: socket_path.clone(), key_enc_path };

    let listener = UnixListener::bind(&socket_path)
        .io_path_context(&socket_path, "binding server socket")?;
    listener.set_nonblocking(true).io_context("setting server socket to non-blocking")?;
    permissions::set_socket_permissions(&socket_path, world)?;
    println!("Chat server started on {}", socket_path.display());
    println!("Waiting for connections...\n");

    // Accept loop -- survives client disconnects.
    // The listener is non-blocking so we poll with a short sleep to
    // check the shutdown flag, since signal-hook uses SA_RESTART.
    loop {
        if signal::shutdown_requested(shutdown) {
            println!("Shutting down...");
            break;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
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
