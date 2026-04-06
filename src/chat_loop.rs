use std::fs::File;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use rustyline::Editor;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;

use crate::completer::ChatCompleter;
use crate::crypto;
use crate::protocol;
use crate::protocol::MessageType;
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
pub fn run(
    stream: UnixStream,
    key: &[u8; 32],
    username: &str,
    topic: &str,
    shutdown: Arc<AtomicBool>,
) {
    let write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Failed to clone stream: {e}{COLOR_RESET}");
            return;
        }
    };

    let mut rl: Editor<ChatCompleter, DefaultHistory> = match Editor::new() {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Failed to initialise readline: {e}{COLOR_RESET}");
            return;
        }
    };
    rl.set_helper(Some(ChatCompleter::new()));

    let printer = match rl.create_external_printer() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Failed to create printer: {e}{COLOR_RESET}");
            return;
        }
    };

    // Socket reader thread: reads from socket, decrypts, prints via ExternalPrinter
    let shutdown_rx = Arc::clone(&shutdown);
    let key_copy = *key;
    let username_owned = username.to_string();
    let topic_owned = topic.to_string();
    let reader_handle = thread::spawn(move || {
        socket_reader(
            &stream,
            &key_copy,
            &username_owned,
            &topic_owned,
            &shutdown_rx,
            printer,
        );
    });

    // Main thread: readline input loop
    stdin_writer(write_stream, key, username, topic, &shutdown, &mut rl);

    // Signal reader thread to stop and wait for it
    shutdown.store(true, Ordering::Relaxed);
    let _ = reader_handle.join();
}

fn stdin_writer(
    mut stream: UnixStream,
    key: &[u8; 32],
    username: &str,
    topic: &str,
    shutdown: &AtomicBool,
    rl: &mut Editor<ChatCompleter, DefaultHistory>,
) {
    let prompt = format!("{username}> ");

    loop {
        if signal::shutdown_requested(shutdown) {
            break;
        }

        match rl.readline(&prompt) {
            Ok(line) => {
                if line.is_empty() {
                    continue;
                }
                rl.add_history_entry(&line).ok();

                match slash_commands::try_execute(&line, username) {
                    Action::Continue => print_message(&mut stream, key, username, &line),
                    Action::Handled => continue,
                    Action::Quit => break,
                    Action::ShareFile(filename) => {
                        send_file(&mut stream, key, username, topic, &filename);
                    }
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("{COLOR_SYSTEM}Input error: {e}{COLOR_RESET}");
                break;
            }
        }
    }

    // Shut down the stream so socket_reader unblocks and exits too.
    shutdown.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn print_message(stream: &mut UnixStream, key: &[u8; 32], username: &str, line: &str) {
    // Print own message locally (move cursor up to overwrite the prompt line)
    print!("\x1b[A\x1b[2K");
    println!("{COLOR_SELF}{username}> {line}{COLOR_RESET}");

    let encrypted = match crypto::encrypt(key, username, line.as_bytes()) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Encryption error: {e}{COLOR_RESET}");
            return;
        }
    };

    if let Err(e) = protocol::write_message(stream, MessageType::Text, &encrypted) {
        eprintln!("{e}");
    }
}

fn send_file(
    stream: &mut UnixStream,
    key: &[u8; 32],
    username: &str,
    _topic: &str,
    filename: &str,
) {
    let path = Path::new(filename);
    let basename = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => {
            eprintln!("{COLOR_SYSTEM}Invalid filename: {filename}{COLOR_RESET}");
            return;
        }
    };

    let content = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Cannot read '{filename}': {e}{COLOR_RESET}");
            return;
        }
    };

    let basename_bytes = basename.as_bytes();
    if basename_bytes.len() > u16::MAX as usize {
        eprintln!("{COLOR_SYSTEM}Filename too long{COLOR_RESET}");
        return;
    }

    // Build file payload: [u16 BE filename_len][filename][content]
    let mut payload = Vec::with_capacity(2 + basename_bytes.len() + content.len());
    payload.extend_from_slice(&(basename_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(basename_bytes);
    payload.extend_from_slice(&content);

    let encrypted = match crypto::encrypt(key, username, &payload) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{COLOR_SYSTEM}Encryption error: {e}{COLOR_RESET}");
            return;
        }
    };

    if let Err(e) = protocol::write_message(stream, MessageType::File, &encrypted) {
        eprintln!("{COLOR_SYSTEM}Send error: {e}{COLOR_RESET}");
        return;
    }

    println!("{COLOR_SYSTEM}[you shared {basename}]{COLOR_RESET}");
}

/// Strip control characters that could manipulate the terminal.
/// Preserves printable ASCII, newlines, and valid multi-byte UTF-8.
fn sanitize_for_terminal(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || (c >= ' ' && c != '\x7f' && c != '\r'))
        .collect()
}

fn socket_reader(
    stream: &UnixStream,
    key: &[u8; 32],
    own_username: &str,
    topic: &str,
    shutdown: &AtomicBool,
    mut printer: impl rustyline::ExternalPrinter,
) {
    let mut reader = std::io::BufReader::new(stream);

    loop {
        if signal::shutdown_requested(shutdown) {
            break;
        }

        match protocol::read_message(&mut reader) {
            Ok(Some((MessageType::Text, data))) => match crypto::decrypt(key, &data) {
                Ok((sender, message)) => {
                    let msg_str = String::from_utf8_lossy(&message);
                    let safe_msg = sanitize_for_terminal(&msg_str);
                    let safe_sender = sanitize_for_terminal(&sender);
                    let color = if sender == own_username {
                        COLOR_SELF
                    } else {
                        COLOR_PEER
                    };
                    let _ = printer.print(format!("{color}{safe_sender}> {safe_msg}{COLOR_RESET}"));
                }
                Err(e) => {
                    let _ =
                        printer.print(format!("{COLOR_SYSTEM}Decryption error: {e}{COLOR_RESET}"));
                }
            },
            Ok(Some((MessageType::File, data))) => match crypto::decrypt(key, &data) {
                Ok((sender, file_payload)) => {
                    handle_received_file(&sender, &file_payload, topic, &mut printer);
                }
                Err(e) => {
                    let _ =
                        printer.print(format!("{COLOR_SYSTEM}Decryption error: {e}{COLOR_RESET}"));
                }
            },
            Ok(Some((MessageType::Unknown(t), _))) => {
                let _ = printer.print(format!(
                    "{COLOR_SYSTEM}Received unknown message type 0x{t:04X}, ignoring{COLOR_RESET}"
                ));
            }
            Ok(None) => break, // Clean disconnect
            Err(e) => {
                if !signal::shutdown_requested(shutdown) {
                    if e.to_string().contains("Interrupted") {
                        continue;
                    }
                    let _ = printer.print(format!("{COLOR_SYSTEM}Read error: {e}{COLOR_RESET}"));
                }
                break;
            }
        }
    }
}

/// Create a new file that does not overwrite any existing file.
/// Tries `name`, then `stem-1.ext`, `stem-2.ext`, etc.
/// Uses `create_new` (O_EXCL) so the creation is race-free.
fn create_unique_file(dir: &Path, name: &str) -> Option<(File, std::path::PathBuf)> {
    let path = dir.join(name);
    if let Ok(f) = File::create_new(&path) {
        return Some((f, path));
    }
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let ext = Path::new(name).extension().and_then(|s| s.to_str());
    for n in 1..1000u32 {
        let candidate = match ext {
            Some(e) => format!("{stem}-{n}.{e}"),
            None => format!("{stem}-{n}"),
        };
        let path = dir.join(&candidate);
        if let Ok(f) = File::create_new(&path) {
            return Some((f, path));
        }
    }
    None
}

fn handle_received_file(
    sender: &str,
    payload: &[u8],
    topic: &str,
    printer: &mut impl rustyline::ExternalPrinter,
) {
    if payload.len() < 2 {
        let _ = printer.print(format!(
            "{COLOR_SYSTEM}Malformed file message: too short{COLOR_RESET}"
        ));
        return;
    }

    let filename_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + filename_len {
        let _ = printer.print(format!(
            "{COLOR_SYSTEM}Malformed file message: filename truncated{COLOR_RESET}"
        ));
        return;
    }

    let filename = match std::str::from_utf8(&payload[2..2 + filename_len]) {
        Ok(s) => s,
        Err(_) => {
            let _ = printer.print(format!(
                "{COLOR_SYSTEM}Malformed file message: invalid filename encoding{COLOR_RESET}"
            ));
            return;
        }
    };

    // Sanitize: use only the basename, reject path traversal
    let safe_name = match Path::new(filename).file_name().and_then(|n| n.to_str()) {
        Some(n) if !n.is_empty() && n != ".." && n != "." => n,
        _ => {
            let _ = printer.print(format!(
                "{COLOR_SYSTEM}Received file with invalid name, ignoring{COLOR_RESET}"
            ));
            return;
        }
    };

    let content = &payload[2 + filename_len..];

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            let _ = printer.print(format!(
                "{COLOR_SYSTEM}HOME not set, cannot save file{COLOR_RESET}"
            ));
            return;
        }
    };

    let dir = Path::new(&home)
        .join("unix-chat")
        .join("shared")
        .join(topic);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        let _ = printer.print(format!(
            "{COLOR_SYSTEM}Cannot create directory '{}': {e}{COLOR_RESET}",
            dir.display()
        ));
        return;
    }

    let (mut file, dest) = match create_unique_file(&dir, safe_name) {
        Some(pair) => pair,
        None => {
            let _ = printer.print(format!(
                "{COLOR_SYSTEM}Cannot create file '{safe_name}' in '{}'{COLOR_RESET}",
                dir.display()
            ));
            return;
        }
    };
    if let Err(e) = file.write_all(content) {
        let _ = printer.print(format!(
            "{COLOR_SYSTEM}Cannot write file '{}': {e}{COLOR_RESET}",
            dest.display()
        ));
        return;
    }

    let safe_sender = sanitize_for_terminal(sender);
    let _ = printer.print(format!(
        "{COLOR_SYSTEM}[{safe_sender} shared {safe_name} -> {}]{COLOR_RESET}",
        dest.display()
    ));
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
