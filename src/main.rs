use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use unix_chat::error::ChatError;
use unix_chat::topic::Topic;
use unix_chat::{client, init, list, permissions, server, signal};

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
        #[arg(long, conflicts_with = "peer")]
        password: Option<String>,
        /// Topic name for the chat socket (defaults to your username)
        #[arg(long, conflicts_with = "peer")]
        topic: Option<Topic>,
        /// Peer username for ECDH-encrypted direct chat
        #[arg(long, conflicts_with_all = ["password", "topic"])]
        peer: Option<String>,
        /// Maximum number of simultaneous client connections
        #[arg(long, default_value_t = 10)]
        max_connections: usize,
    },
    /// Connect to a chat server
    Connect {
        /// Topic name or username of the chat server to connect to (password mode)
        name: Option<Topic>,
        /// Peer username for ECDH-encrypted direct chat
        #[arg(long, conflicts_with = "name")]
        peer: Option<String>,
    },
    /// List available chat servers on this machine
    List,
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
            peer,
            max_connections,
        } => {
            let password = password_var.map(|var| {
                std::env::var(&var).unwrap_or_else(|_| {
                    eprintln!("Error: environment variable '{var}' is not set");
                    std::process::exit(1);
                })
            });
            if peer.is_none() && password.is_none() {
                eprintln!("Error: either --peer or --password is required");
                std::process::exit(1);
            }
            let topic = topic.unwrap_or_else(Topic::from_username);
            server::run(
                password.as_deref(),
                &topic,
                peer.as_deref(),
                max_connections,
                Arc::clone(&shutdown),
            )
        }
        Command::Connect { ref name, ref peer } => {
            if name.is_none() && peer.is_none() {
                eprintln!("Error: either <NAME> or --peer is required");
                std::process::exit(1);
            }
            client::run(name.as_ref(), peer.as_deref(), Arc::clone(&shutdown))
        }
        Command::List => list::run(),
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
