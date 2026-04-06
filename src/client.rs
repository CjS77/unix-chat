use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use zeroize::Zeroizing;

use crate::chat_loop;
use crate::config::SOCKET_DIR;
use crate::crypto::{self, SessionKey};
use crate::error::{ChatError, IoResultExt, Result};
use crate::topic::Topic;

pub fn run(topic: &Topic, shutdown: Arc<AtomicBool>) -> Result<()> {
    let own_username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.sock"));
    let key_enc_path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.key.enc"));
    let received_key_path = PathBuf::from(format!("/tmp/.unix_chat_received_key_{own_username}"));

    // Resolve session key
    let session_key = if key_enc_path.exists() {
        // Password mode: server published an encrypted key
        let password = read_password("Session password: ")?;
        eprint!("Decrypting session key.. ");
        let encoded = std::fs::read_to_string(&key_enc_path)
            .io_path_context(&key_enc_path, "reading encrypted session key from")?;
        let key = crypto::unwrap_key_with_password(&encoded, &password)?;
        eprintln!("OK!");
        key
    } else if received_key_path.exists() {
        // Key was received via key exchange
        let data = Zeroizing::new(
            std::fs::read(&received_key_path)
                .io_path_context(&received_key_path, "reading received key from")?,
        );
        let key = SessionKey::from_bytes(&data)?;
        // Clean up the key file now that it has been loaded
        let _ = std::fs::remove_file(&received_key_path);
        key
    } else {
        return Err(ChatError::KeyNotFound(format!(
            "No session key found for {topic}. Use '{topic}'s --password option, or run 'uc receive-key <pid>' first."
        )));
    };

    if !socket_path.exists() {
        return Err(ChatError::ConnectionRefused(format!(
            "{topic} is not running a chat server"
        )));
    }

    let stream = UnixStream::connect(&socket_path)
        .map_err(|e| ChatError::ConnectionRefused(format!("Failed to connect to {topic}: {e}")))?;

    println!("Connected to {topic}!\n");

    chat_loop::run(
        stream,
        &session_key.key,
        &own_username,
        topic.as_str(),
        shutdown,
    );
    println!("\nDisconnected.");
    Ok(())
}

/// Read a password from the terminal without echoing.
fn read_password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    let password = rpassword::read_password().io_context("reading password from stdin")?;
    Ok(Zeroizing::new(password))
}
