use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::crypto;
use crate::protocol;
use crate::signal;
use crate::slash_commands;
use crate::slash_commands::Action;

// ANSI color codes
const COLOR_PEER: &str = "\x1b[36m"; // Cyan for peer messages
const COLOR_SELF: &str = "\x1b[32m"; // Green for own messages
const COLOR_RESET: &str = "\x1b[0m";
const COLOR_SYSTEM: &str = "\x1b[33m"; // Yellow for system messages

/// Run the bidirectional chat loop over an established Unix stream.
/// Blocks until the connection is closed or an error occurs.
pub fn run(stream: UnixStream, key: &[u8; 32], username: &str) {
    let shutdown = Arc::new(AtomicBool::new(false));

    let write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Failed to clone stream: {e}{COLOR_RESET}");
            return;
        }
    };

    // Stdin reader thread: reads lines, encrypts, sends
    let shutdown_tx = Arc::clone(&shutdown);
    let key_copy = *key;
    let username_owned = username.to_string();
    let stdin_handle = thread::spawn(move || {
        stdin_writer(write_stream, &key_copy, &username_owned, &shutdown_tx);
    });

    // Main thread: reads from socket, decrypts, prints
    socket_reader(&stream, key, username, &shutdown);

    // Signal stdin thread to stop and wait for it
    shutdown.store(true, Ordering::Relaxed);
    // Shutdown the read side won't help stdin, but shutting down the write side
    // will cause the stdin thread's next write to fail.
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = stdin_handle.join();
}

fn stdin_writer(mut stream: UnixStream, key: &[u8; 32], username: &str, shutdown: &AtomicBool) {
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());

    for line in reader.lines() {
        if signal::shutdown_requested(shutdown) {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        // Check for slash commands before sending
        match slash_commands::try_execute(&line, username) {
            Action::Continue => print_message(&mut stream, key, username, &line),
            Action::Handled => continue,
            Action::Quit => break,
        }
    }
}

fn print_message(stream: &mut UnixStream, key: &[u8; 32], username: &str, line: &str) {
    // Print own message locally
    println!("{COLOR_SELF}{username}> {line}{COLOR_RESET}");

    let encrypted = match crypto::encrypt(key, username, line.as_bytes()) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Encryption error: {e}{COLOR_RESET}");
            return;
        }
    };

    if let Err(e) = protocol::write_message(stream, &encrypted) {
        eprintln!("{e}");
    }
}

/// Strip control characters that could manipulate the terminal.
/// Preserves printable ASCII, newlines, and valid multi-byte UTF-8.
fn sanitize_for_terminal(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || (c >= ' ' && c != '\x7f'))
        .collect()
}

fn socket_reader(stream: &UnixStream, key: &[u8; 32], own_username: &str, shutdown: &AtomicBool) {
    let mut reader = BufReader::new(stream);

    loop {
        if signal::shutdown_requested(shutdown) {
            break;
        }

        match protocol::read_message(&mut reader) {
            Ok(Some(data)) => match crypto::decrypt(key, &data) {
                Ok((sender, message)) => {
                    let msg_str = String::from_utf8_lossy(&message);
                    let safe_msg = sanitize_for_terminal(&msg_str);
                    let safe_sender = sanitize_for_terminal(&sender);
                    let color = if sender == own_username {
                        COLOR_SELF
                    } else {
                        COLOR_PEER
                    };
                    println!("{color}{safe_sender}> {safe_msg}{COLOR_RESET}");
                }
                Err(e) => {
                    eprintln!("{COLOR_SYSTEM}Decryption error: {e}{COLOR_RESET}");
                }
            },
            Ok(None) => break, // Clean disconnect
            Err(e) => {
                if !signal::shutdown_requested(shutdown) {
                    if e.to_string().contains("Interrupted") {
                        continue;
                    }
                    eprintln!("{COLOR_SYSTEM}Read error: {e}{COLOR_RESET}");
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escape_sequences() {
        assert_eq!(
            sanitize_for_terminal("hello\x1b[31mred\x1b[0m"),
            "hello[31mred[0m"
        );
    }

    #[test]
    fn strips_bell_and_other_control_chars() {
        assert_eq!(
            sanitize_for_terminal("normal\x07bell\x01start"),
            "normalbellstart"
        );
    }

    #[test]
    fn preserves_newlines() {
        assert_eq!(sanitize_for_terminal("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn preserves_unicode() {
        assert_eq!(sanitize_for_terminal("hello 🌍 world"), "hello 🌍 world");
    }

    #[test]
    fn strips_del() {
        assert_eq!(sanitize_for_terminal("abc\x7fdef"), "abcdef");
    }
}
