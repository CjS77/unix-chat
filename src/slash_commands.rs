const COLOR_SYSTEM: &str = "\x1b[33m";
const COLOR_RESET: &str = "\x1b[0m";

pub const SLASH_COMMANDS: &[&str] = &["/help", "/pubkey-broadcast", "/quit", "/share ", "/whoami"];

/// Result of executing a slash command.
pub enum Action {
    /// Continue the chat loop.
    Continue,
    /// The command was handled as a command
    Handled,
    /// Exit the chat loop.
    Quit,
    /// Share a file with the given path.
    ShareFile(String),
    /// Broadcast own public key to all peers.
    BroadcastPubkey,
}

/// Try to handle `line` as a slash command.
/// Returns `Some(action)` if the line was a command, `None` if it should be sent as a normal message.
pub fn try_execute(line: &str, username: &str) -> Action {
    let trimmed = line.trim();
    if !trimmed.starts_with('/') {
        return Action::Continue;
    }
    execute_slash_command(trimmed, username)
}

fn execute_slash_command(input: &str, username: &str) -> Action {
    let mut parts = input.split_whitespace();
    let command = parts.next().unwrap_or("");
    match command {
        "/help" => {
            println!("{COLOR_SYSTEM}Available commands:");
            println!("  /help             - Show this help message");
            println!("  /pubkey-broadcast - Broadcast your public key to all peers");
            println!("  /share <file>     - Share a file with the chat");
            println!("  /whoami           - Print your username");
            println!("  /quit             - Exit the chat{COLOR_RESET}");
            Action::Handled
        }
        "/share" => {
            let filename: String = parts.collect::<Vec<_>>().join(" ");
            if filename.is_empty() {
                println!("{COLOR_SYSTEM}Usage: /share <filename>{COLOR_RESET}");
                Action::Handled
            } else {
                Action::ShareFile(filename)
            }
        }
        "/whoami" => {
            println!("{COLOR_SYSTEM}{username}{COLOR_RESET}");
            Action::Handled
        }
        "/pubkey-broadcast" => Action::BroadcastPubkey,
        "/quit" => {
            println!("{COLOR_SYSTEM}Goodbye!{COLOR_RESET}");
            Action::Quit
        }
        _ => {
            println!("{COLOR_SYSTEM}Unknown command: {command}{COLOR_RESET}");
            Action::Handled
        }
    }
}
