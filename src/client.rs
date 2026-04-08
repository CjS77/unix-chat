use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use zeroize::Zeroizing;

use crate::chat_loop;
use crate::config::{self, SOCKET_DIR, ssh_key_path};
use crate::crypto;
use crate::error::{ChatError, IoResultExt, Result};
use crate::topic::Topic;

pub fn run(topic: Option<&Topic>, peer: Option<&str>, shutdown: Arc<AtomicBool>) -> Result<()> {
    let own_username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    match (peer, topic) {
        (Some(peer_name), None) => run_p2p(own_username, peer_name, shutdown),
        (None, Some(topic)) => run_password_protected(own_username, topic, shutdown),
        (Some(_), Some(_)) => Err(ChatError::Config(
            "Cannot specify both topic and peer".to_string(),
        )),
        (None, None) => Err(ChatError::Config(
            "One of topic or peer must be specified".to_string(),
        )),
    }
}

fn run_password_protected(
    own_username: String,
    topic: &Topic,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    // Password mode
    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.sock"));
    let key_enc_path = PathBuf::from(format!("{SOCKET_DIR}/{topic}.key.enc"));

    if !key_enc_path.exists() {
        return Err(ChatError::KeyNotFound(format!(
            "No session key found for {topic}. The server must use --password to publish a key."
        )));
    }

    let password = read_password("Session password: ")?;
    eprint!("Decrypting session key.. ");
    let encoded = std::fs::read_to_string(&key_enc_path)
        .io_path_context(&key_enc_path, "reading encrypted session key from")?;
    let session_key = crypto::unwrap_key_with_password(&encoded, &password)?;
    eprintln!("OK!");

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
    Ok(())
}

fn run_p2p(own_username: String, peer_name: &str, shutdown: Arc<AtomicBool>) -> Result<()> {
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
    let key = crypto::derive_ecdh_key(&ssh_key_path()?, &peer_pub_path)?;
    // Server is the peer, client is us
    let socket_path = PathBuf::from(format!("{SOCKET_DIR}/e2ee-{peer_name}-{own_username}.sock"));

    if !socket_path.exists() {
        return Err(ChatError::ConnectionRefused(format!(
            "{peer_name} is not running a chat server (expected socket at {})",
            socket_path.display()
        )));
    }

    let stream = UnixStream::connect(&socket_path).map_err(|e| {
        ChatError::ConnectionRefused(format!("Failed to connect to {peer_name}: {e}"))
    })?;

    println!("Connected to {peer_name} (ECDH encrypted)!\n");
    chat_loop::run(stream, &key, &own_username, peer_name, shutdown);
    Ok(())
}

/// Read a password from the terminal without echoing.
fn read_password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    let password = rpassword::read_password().io_context("reading password from stdin")?;
    Ok(Zeroizing::new(password))
}
