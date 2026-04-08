use std::path::Path;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use curve25519_dalek::MontgomeryPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar;
use hkdf::Hkdf;
use hmac::Hmac;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use ssh_key::{PrivateKey, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{ChatError, Result};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const PBKDF2_ITERATIONS: u32 = 600_000;
const PBKDF2_DOMAIN_SEP: &[u8] = b"unix-chat-password-wrap";

/// A session key with the salt used to derive it.
/// The salt is needed for key exchange so the recipient can verify derivation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey {
    pub key: [u8; KEY_LEN],
    pub salt: [u8; SALT_LEN],
}

impl SessionKey {
    /// Serialize to 48 bytes: salt || key
    pub fn to_bytes(&self) -> [u8; SALT_LEN + KEY_LEN] {
        let mut buf = [0u8; SALT_LEN + KEY_LEN];
        buf[..SALT_LEN].copy_from_slice(&self.salt);
        buf[SALT_LEN..].copy_from_slice(&self.key);
        buf
    }

    /// Deserialize from 48 bytes: salt || key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SALT_LEN + KEY_LEN {
            return Err(ChatError::Crypto(format!(
                "Invalid session key length: expected {}, got {}",
                SALT_LEN + KEY_LEN,
                bytes.len()
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        let mut key = [0u8; KEY_LEN];
        salt.copy_from_slice(&bytes[..SALT_LEN]);
        key.copy_from_slice(&bytes[SALT_LEN..]);
        Ok(SessionKey { key, salt })
    }
}

/// Generate a session key by deriving from the SSH private key file.
pub fn generate_session_key(ssh_key_path: &std::path::Path) -> Result<SessionKey> {
    let ssh_key_bytes =
        Zeroizing::new(std::fs::read(ssh_key_path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                ChatError::SshKeyMissing(ssh_key_path.display().to_string())
            }
            std::io::ErrorKind::PermissionDenied => ChatError::PermissionDenied {
                path: ssh_key_path.display().to_string(),
                operation: "reading SSH key".into(),
            },
            _ => ChatError::Io {
                context: format!("reading SSH key '{}'", ssh_key_path.display()),
                source: e,
            },
        })?);

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ssh_key_bytes);
    let mut key = [0u8; KEY_LEN];
    hk.expand(b"unix-chat-session-key", &mut key)
        .map_err(|e| ChatError::Crypto(format!("HKDF expansion failed: {e}")))?;

    Ok(SessionKey { key, salt })
}

const ECDH_DOMAIN_TAG: &[u8] = b"unix_chat_ecdh_v1";

pub(crate) fn openssh_key_to_bytes(private_key: &PrivateKey) -> Result<Zeroizing<[u8; 32]>> {
    let ed25519_keypair = private_key
        .key_data()
        .ed25519()
        .ok_or_else(|| ChatError::Crypto("SSH key is not Ed25519".into()))?;

    // Ed25519 private keys are seeds. To convert to an X25519 scalar we must
    // follow the Ed25519 spec: SHA-512 hash the seed, then clamp the lower 32 bytes.
    let seed = ed25519_keypair.private.to_bytes();
    let hash = Sha512::digest(seed);
    let mut scalar_bytes = Zeroizing::new([0u8; 32]);
    scalar_bytes.copy_from_slice(&hash[..32]);
    Ok(Zeroizing::new(scalar::clamp_integer(*scalar_bytes)))
}

pub(crate) fn openssh_pubkey_to_point(pubkey: &PublicKey) -> Result<MontgomeryPoint> {
    let ed25519_pub = pubkey
        .key_data()
        .ed25519()
        .ok_or_else(|| ChatError::Crypto("Peer key is not Ed25519".into()))?;

    // Convert Edwards point to Montgomery form for X25519-style ECDH
    let compressed = CompressedEdwardsY::from_slice(ed25519_pub.as_ref())
        .map_err(|e| ChatError::Crypto(format!("Invalid peer public key point: {e}")))?;
    let edwards_point = compressed
        .decompress()
        .ok_or_else(|| ChatError::Crypto("Peer public key is not a valid curve point".into()))?;
    let montgomery = edwards_point.to_montgomery();
    Ok(montgomery)
}

/// Derive a shared encryption key via ECDH from our Ed25519 private key and a peer's public key.
///
/// Algorithm:
/// 1. Parse our SSH private key, extract Ed25519 seed, derive X25519 scalar
/// 2. Parse peer's SSH public key, convert Ed25519 point to Montgomery form
/// 3. Compute shared point: scalar * montgomery_point
/// 4. Derive key: SHA-256(DOMAIN_TAG || shared_point || Pa || Pb)
pub fn derive_ecdh_key(own_key_path: &Path, peer_pubkey_path: &Path) -> Result<[u8; KEY_LEN]> {
    // Parse our private key and extract the Ed25519 seed
    let private_key = ssh_key::PrivateKey::read_openssh_file(own_key_path).map_err(|e| {
        ChatError::Crypto(format!(
            "Failed to parse SSH private key '{}': {e}",
            own_key_path.display()
        ))
    })?;

    let scalar = openssh_key_to_bytes(&private_key)?;

    // Parse peer's public key
    let pub_key = ssh_key::PublicKey::read_openssh_file(peer_pubkey_path).map_err(|e| {
        ChatError::Crypto(format!(
            "Failed to parse peer public key '{}': {e}",
            peer_pubkey_path.display()
        ))
    })?;

    let montgomery = openssh_pubkey_to_point(&pub_key)?;

    // ECDH: shared_point = montgomery_point * scalar
    let shared_point = montgomery.mul_clamped(*scalar);

    // Reject the identity point (all zeros) — indicates a low-order peer public key
    if shared_point.0 == [0u8; 32] {
        return Err(ChatError::Crypto(
            "ECDH produced identity point — peer public key is invalid (low-order)".into(),
        ));
    }

    // Derive our own public key bytes for inclusion in the KDF
    let own_pub_key = private_key.public_key();
    let own_pub_ed = own_pub_key
        .key_data()
        .ed25519()
        .ok_or_else(|| ChatError::Crypto("Own SSH key is not Ed25519".into()))?;
    let peer_pub_ed = pub_key
        .key_data()
        .ed25519()
        .ok_or_else(|| ChatError::Crypto("Peer key is not Ed25519".into()))?;

    // Sort public keys so both sides produce the same hash regardless of who is "own" vs "peer".
    let (first, second) = if own_pub_ed.as_ref() < peer_pub_ed.as_ref() {
        (own_pub_ed.as_ref(), peer_pub_ed.as_ref())
    } else {
        (peer_pub_ed.as_ref(), own_pub_ed.as_ref())
    };

    // Derive shared secret: SHA-256(DOMAIN_TAG || pubkey_low || pubkey_high || shared_point)
    // Including both public keys binds the derived key to the specific participants.
    let mut hasher = Sha256::new();
    hasher.update(ECDH_DOMAIN_TAG);
    hasher.update(first);
    hasher.update(second);
    hasher.update(shared_point.0);
    let result = hasher.finalize();

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&result);
    Ok(key)
}

/// Encrypt a message. Plaintext format: username_len (1 byte) || username || message.
/// Returns: nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
pub fn encrypt(key: &[u8; KEY_LEN], username: &str, message: &[u8]) -> Result<Vec<u8>> {
    let username_bytes = username.as_bytes();
    if username_bytes.len() > 255 {
        return Err(ChatError::Crypto(
            "Username too long (max 255 bytes)".into(),
        ));
    }

    // Build plaintext: username_len || username || message
    let mut plaintext = Vec::with_capacity(1 + username_bytes.len() + message.len());
    plaintext.push(username_bytes.len() as u8);
    plaintext.extend_from_slice(username_bytes);
    plaintext.extend_from_slice(message);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ChatError::Crypto(format!("Failed to create cipher: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| ChatError::Crypto(format!("Encryption failed: {e}")))?;

    // Output: nonce || ciphertext (which includes GCM tag)
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a message. Input: nonce (12 bytes) || ciphertext || GCM tag.
/// Returns (username, message_bytes).
pub fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Result<(String, Vec<u8>)> {
    if data.len() < NONCE_LEN + 1 {
        return Err(ChatError::Crypto("Ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ChatError::Crypto(format!("Failed to create cipher: {e}")))?;

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        ChatError::Crypto("Decryption failed (wrong key or tampered message)".into())
    })?;

    if plaintext.is_empty() {
        return Err(ChatError::Crypto("Empty plaintext".into()));
    }

    let username_len = plaintext[0] as usize;
    if plaintext.len() < 1 + username_len {
        return Err(ChatError::Crypto(
            "Malformed plaintext: username truncated".into(),
        ));
    }

    let username = String::from_utf8(plaintext[1..1 + username_len].to_vec())
        .map_err(|e| ChatError::Crypto(format!("Invalid username encoding: {e}")))?;
    let message = plaintext[1 + username_len..].to_vec();

    Ok((username, message))
}

/// Encrypt a session key with a password for publishing.
/// Returns base64-encoded blob.
pub fn wrap_key_with_password(session_key: &SessionKey, password: &str) -> Result<String> {
    let mut derived = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        PBKDF2_DOMAIN_SEP,
        PBKDF2_ITERATIONS,
        derived.as_mut(),
    )
    .map_err(|e| ChatError::Crypto(format!("PBKDF2 failed: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(derived.as_ref())
        .map_err(|e| ChatError::Crypto(format!("Failed to create cipher: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = Zeroizing::new(session_key.to_bytes());
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| ChatError::Crypto(format!("Key wrapping failed: {e}")))?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &output,
    ))
}

/// Decrypt a session key from a password-protected base64 blob.
pub fn unwrap_key_with_password(encoded: &str, password: &str) -> Result<SessionKey> {
    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.trim())
        .map_err(|e| ChatError::Crypto(format!("Base64 decode failed: {e}")))?;

    if data.len() < NONCE_LEN + 1 {
        return Err(ChatError::Crypto("Wrapped key data too short".into()));
    }

    let mut derived = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        PBKDF2_DOMAIN_SEP,
        PBKDF2_ITERATIONS,
        derived.as_mut(),
    )
    .map_err(|e| ChatError::Crypto(format!("PBKDF2 failed: {e}")))?;

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(derived.as_ref())
        .map_err(|e| ChatError::Crypto(format!("Failed to create cipher: {e}")))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ChatError::InvalidPassword)?;

    SessionKey::from_bytes(&plaintext)
}

/// Derive a short authentication string from key material for out-of-band verification.
/// Returns a 6-character uppercase hex string (24 bits of entropy).
pub fn short_auth_string(key: &[u8; KEY_LEN]) -> String {
    use hmac::Mac;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(b"unix-chat-sas-verification");
    let result = mac.finalize().into_bytes();
    format!("{:02X}{:02X}{:02X}", result[0], result[1], result[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let username = "alice";
        let message = b"hello, world!";

        let encrypted = encrypt(&key, username, message).unwrap();
        let (dec_user, dec_msg) = decrypt(&key, &encrypted).unwrap();

        assert_eq!(dec_user, username);
        assert_eq!(dec_msg, message);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = test_key();
        let key2 = test_key();

        let encrypted = encrypt(&key1, "alice", b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn encrypt_decrypt_empty_message() {
        let key = test_key();
        let encrypted = encrypt(&key, "bob", b"").unwrap();
        let (user, msg) = decrypt(&key, &encrypted).unwrap();
        assert_eq!(user, "bob");
        assert!(msg.is_empty());
    }

    #[test]
    fn password_wrap_unwrap_round_trip() {
        let session_key = SessionKey {
            key: test_key(),
            salt: {
                let mut s = [0u8; SALT_LEN];
                rand::rng().fill_bytes(&mut s);
                s
            },
        };
        let password = "test-password-123";

        let wrapped = wrap_key_with_password(&session_key, password).unwrap();
        let unwrapped = unwrap_key_with_password(&wrapped, password).unwrap();

        assert_eq!(session_key.key, unwrapped.key);
        assert_eq!(session_key.salt, unwrapped.salt);
    }

    #[test]
    fn password_unwrap_wrong_password_fails() {
        let session_key = SessionKey {
            key: test_key(),
            salt: [0u8; SALT_LEN],
        };

        let wrapped = wrap_key_with_password(&session_key, "correct").unwrap();
        assert!(unwrap_key_with_password(&wrapped, "wrong").is_err());
    }

    #[test]
    fn short_auth_string_deterministic_and_well_formed() {
        let key = test_key();
        let sas1 = short_auth_string(&key);
        let sas2 = short_auth_string(&key);
        assert_eq!(sas1, sas2, "SAS must be deterministic for the same key");
        assert_eq!(sas1.len(), 6, "SAS must be 6 hex characters");
        assert!(
            sas1.chars().all(|c| c.is_ascii_hexdigit()),
            "SAS must be valid hex"
        );
    }

    #[test]
    fn short_auth_string_different_keys_differ() {
        let sas1 = short_auth_string(&test_key());
        let sas2 = short_auth_string(&test_key());
        // Random keys should produce different SAS (collision probability ~1/16M)
        assert_ne!(sas1, sas2);
    }
}
