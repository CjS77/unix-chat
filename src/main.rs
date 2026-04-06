use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use unix_chat::error::ChatError;
use unix_chat::topic::Topic;
use unix_chat::{client, init, key_exchange, list, permissions, server, signal};

#[derive(Parser)]
#[command(name = "uc", about = "Peer-to-peer encrypted chat for local users", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a chat server and wait for incoming connections
    Start {
        /// Environment variable that holds the password for encrypting the session key
        #[arg(long)]
        password: Option<String>,
        /// Topic name for the chat socket (defaults to your username)
        #[arg(long)]
        topic: Option<Topic>,
        /// Allow any local user to connect (socket mode 0666 instead of group-restricted 0660)
        #[arg(long)]
        world: bool,
        /// Maximum number of simultaneous client connections
        #[arg(long, default_value_t = 10)]
        max_connections: usize,
    },
    /// Connect to a chat server
    Connect {
        /// Topic name or username of the chat server to connect to
        name: Topic,
    },
    /// List available chat servers on this machine
    List,
    /// Share your encryption key with another user
    ShareKey {
        /// Username of the recipient
        username: String,
        /// Allow any local user to connect to the key exchange socket (mode 0666)
        #[arg(long)]
        world: bool,
    },
    /// Receive an encryption key from another user
    ReceiveKey {
        /// Process ID printed by the sender's share-key command
        pid: u32,
    },
    /// Check environment and generate SSH key if needed
    Init,
}

fn main() {
    let shutdown: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    signal::install_handlers(shutdown.clone());

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Start {
            password: password_var,
            topic,
            world,
            max_connections,
        } => {
            let password = password_var.map(|var| {
                std::env::var(&var).unwrap_or_else(|_| {
                    eprintln!("Error: environment variable '{var}' is not set");
                    std::process::exit(1);
                })
            });
            let topic = topic.unwrap_or_else(Topic::from_username);
            server::run(
                password.as_deref(),
                &topic,
                world,
                max_connections,
                Arc::clone(&shutdown),
            )
        }
        Command::Connect { ref name } => client::run(name, Arc::clone(&shutdown)),
        Command::List => list::run(),
        Command::ShareKey {
            ref username,
            world,
        } => key_exchange::share_key(username, world, &shutdown),
        Command::ReceiveKey { pid } => key_exchange::receive_key(pid),
        Command::Init => init::run(),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        if matches!(&e, ChatError::PermissionDenied { .. }) {
            let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
            permissions::print_admin_instructions(&username, !permissions::group_exists());
        }
        std::process::exit(1);
    }
}
