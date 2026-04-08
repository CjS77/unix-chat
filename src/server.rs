use crate::chat_loop;
use crate::config::{self, SOCKET_DIR, ssh_key_path};
use crate::crypto;
use crate::error::{ChatError, IoResultExt, Result};
use crate::permissions;
use crate::relay::Relay;
use crate::signal;
use crate::topic::Topic;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
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
    peer: Option<&str>,
    max_connections: usize,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let safe_username = config::sanitize_peer_name(&username)?;

    permissions::ensure_socket_dir()?;

    let (key, socket_path, key_enc_path) = if let Some(peer_name) = peer {
        // ECDH mode: derive shared key from own private key + peer's public key
        let peer_pub_path = config::peer_pubkey_path(peer_name)?;
        if !peer_pub_path.exists() {
            return Err(ChatError::KeyNotFound(format!(
                "Public key for '{peer_name}' not found at {}.\n  \
                 Ask {peer_name} to broadcast their key with /pubkey-broadcast, \
                 or manually copy their public key there.",
                peer_pub_path.display()
            )));
        }
        let ecdh_key = crypto::derive_ecdh_key(&ssh_key_path()?, &peer_pub_path)?;
        let socket_path = PathBuf::from(format!(
            "{SOCKET_DIR}/e2ee-{safe_username}-{peer_name}.sock"
        ));
        (ecdh_key, socket_path, None)
    } else {
        // Password mode
        let session_key = crypto::generate_session_key(&ssh_key_path()?)?;
        let socket_path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.sock"));
        let key_enc_path = if let Some(pwd) = password {
            let path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.key.enc"));
            let wrapped = crypto::wrap_key_with_password(&session_key, pwd)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o660)
                .open(&path)
                .io_path_context(&path, "writing encrypted session key to")?;
            file.write_all(wrapped.as_bytes())
                .io_path_context(&path, "writing encrypted session key to")?;
            permissions::set_socket_permissions(&path)?;
            println!(
                "Session key published (password-protected) at {}",
                path.display()
            );
            Some(path)
        } else {
            None
        };
        (session_key.key, socket_path, key_enc_path)
    };

    safe_remove_socket(&socket_path)?;

    let _guard = ServerGuard {
        socket_path: socket_path.clone(),
        key_enc_path,
    };

    let listener =
        UnixListener::bind(&socket_path).io_path_context(&socket_path, "binding server socket")?;
    listener
        .set_nonblocking(true)
        .io_context("setting server socket to non-blocking")?;
    permissions::set_socket_permissions(&socket_path)?;
    println!("Chat server started on {}", socket_path.display());
    println!("Waiting for connections...\n");

    // Relay broadcasts every incoming message to all other connected streams.
    let relay = Relay::new(Arc::clone(&shutdown));

    // Internal stream pair: one end goes to the relay, the other is used by
    // the server operator's chat_loop -- identical to a client.
    let (operator_stream, relay_end) =
        UnixStream::pair().io_context("creating internal stream pair")?;
    relay.add_client(relay_end);

    // Accept loop in a background thread.
    let relay_accept = Arc::clone(&relay);
    let shutdown_accept = Arc::clone(&shutdown);
    std::thread::spawn(move || {
        let mut last_connect = std::time::Instant::now();
        let mut rapid_count: u32 = 0;
        loop {
            if signal::shutdown_requested(&shutdown_accept) {
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

                    if relay_accept.client_count() >= max_connections {
                        eprintln!(
                            "Connection rejected: max connections ({max_connections}) reached"
                        );
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }

                    let _ = stream.set_nonblocking(false);
                    relay_accept.add_client(stream);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("Accept error: {e}");
                }
            }
        }
    });

    // Server operator enters the same chat loop as any client.
    chat_loop::run(
        operator_stream,
        &key,
        &username,
        topic.as_str(),
        Arc::clone(&shutdown),
    );

    // Operator quit -- tear everything down.
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    relay.shutdown_all();

    // _guard drops here, cleaning up socket and key files
    drop(_guard);
    Ok(())
}
