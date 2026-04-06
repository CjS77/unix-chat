const COLOR_SYSTEM: &str = "\x1b[33m";
const COLOR_RESET: &str = "\x1b[0m";

/// Result of executing a slash command.
pub enum Action {
    /// Continue the chat loop.
    Continue,
    /// The test was handled as a command
    Handled,
    /// Exit the chat loop.
    Quit,
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

fn execute_slash_command(command: &str, username: &str) -> Action {
    let command = command.split_whitespace().next().unwrap_or("");
    match command {
        "/help" => {
            println!("{COLOR_SYSTEM}Available commands:");
            println!("  /help   - Show this help message");
            println!("  /whoami - Print your username");
            println!("  /quit   - Exit the chat{COLOR_RESET}");
            Action::Handled
        }
        "/whoami" => {
            println!("{COLOR_SYSTEM}{username}{COLOR_RESET}");
            Action::Handled
        }
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
