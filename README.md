# unix-chat

A peer-to-peer encrypted chat system for local users on the same machine, using Unix sockets and AES-256-GCM symmetric encryption with SSH
key-based key derivation.

## How it works

### Architecture

unix-chat uses **Unix domain sockets** in `/tmp/unix_chat_sockets/` for inter-process communication between users on the same host. Access
control is managed via a `unixchat` system group -- users in this group can create and connect to chat sockets. An `--world` flag is
available to bypass group restrictions.

### Encryption

Messages are encrypted with **AES-256-GCM** (authenticated encryption). The key lifecycle works as follows:

1. A random 16-byte salt is generated.
2. The user's **SSH private key** (`~/.ssh/id_ed25519_unix_chat`) is read and used as input keying material for **HKDF-SHA256**, producing a
   256-bit session key.
3. Each message is encrypted with a fresh random nonce and includes the sender's username in the authenticated ciphertext.

Alternatively, the server can publish a **password-protected session key** (`--password`), allowing clients to connect by entering the
shared password instead of performing a key exchange.

### Key exchange

Before two users can chat (without password mode), they must share the same session key. The `share-key` / `receive-key` commands set up a
temporary Unix socket (`/tmp/unix_chat_sockets/key_exchange_<pid>.sock`) to transfer the raw session key bytes from the server operator to
another user.

### Message protocol

Messages are framed as length-prefixed packets: a 4-byte big-endian length followed by the encrypted payload. The plaintext format embeds
the sender's username (1-byte length prefix + username bytes + message body), so the recipient knows who sent each message.

```
User A (stdin) --> AES-256-GCM encrypt --> unix socket --> AES-256-GCM decrypt --> User B (stdout)
User B (stdin) --> AES-256-GCM encrypt --> unix socket --> AES-256-GCM decrypt --> User A (stdout)
```

## Installation

```bash
cargo install --path .
```

Requires Rust 2024 edition (1.85+).

## Setup

Run `unix-chat init` to check your environment, generate the required SSH key, and configure group membership:

```bash
unix-chat init
```

This will:

- Check for `ssh-keygen` and offer to generate `~/.ssh/id_ed25519_unix_chat`
- Check for the `unixchat` system group and print admin instructions if needed
- Create the socket directory with correct permissions

## Usage

```
unix-chat {start|connect <name>|list|share-key <username>|receive-key <pid>|init}
```

### Start a chat server

```bash
unix-chat start
```

Creates a socket at `/tmp/unix_chat_sockets/<username>.sock`, derives an encryption key from your SSH key, and waits for incoming
connections. The server survives client disconnects and accepts new connections.

Options:

- `--topic <name>` -- use a custom topic name instead of your username
- `--password <pwd>` -- publish a password-protected session key so clients can connect without manual key exchange.
  **Security note:** the password will be visible in the process listing (e.g. `ps aux`). For sensitive sessions, prefer
  the key exchange workflow instead.
- `--world` -- set socket permissions to 0666 instead of group-restricted 0660

### Connect to a chat server

```bash
unix-chat connect alice
```

Connects to the socket for the given topic/username. The client resolves the session key by checking (in order):

1. A password-protected key file published by the server
2. A key previously received via `receive-key`

### List available chat servers

```bash
unix-chat list
```

Scans `/tmp/unix_chat_sockets/` for active `.sock` files and prints available topics.

### Share your encryption key

```bash
unix-chat share-key bob
```

Opens a one-shot key exchange socket and waits for the recipient to connect and retrieve the session key.

Options:

- `--world` -- allow any local user to connect to the exchange socket

### Receive an encryption key

```bash
# Using the PID printed by the sender:
unix-chat receive-key 12345
```

Connects to the sender's key exchange socket, downloads the session key, and saves it to `/tmp/.unix_chat_received_key_<username>`.

## In-chat commands

While chatting, the following slash commands are available:

| Command   | Description             |
|-----------|-------------------------|
| `/help`   | Show available commands |
| `/whoami` | Print your username     |
| `/quit`   | Exit the chat           |

## Example session

**Terminal 1 (alice) -- start with a password:**

```bash
alice$ unix-chat start --password s3cret
Session key published (password-protected)
Chat server started on /tmp/unix_chat_sockets/alice.sock
Waiting for connections...
```

**Terminal 2 (bob) -- connect with the password:**

```bash
bob$ unix-chat connect alice
Session password: s3cret
Decrypting session key.. OK!
Connected to alice!

bob> hello alice!
```

**Alternative: manual key exchange (no password)**

```bash
# Alice starts without --password
alice$ unix-chat start
# Alice shares her key
alice$ unix-chat share-key bob
Waiting for bob to receive the key...
On bob's terminal, run: unix-chat receive-key 54321

# Bob receives and connects
bob$ unix-chat receive-key 54321
Encryption key received and saved
bob$ unix-chat connect alice
Connected to alice!
```

## Limitations and Security Caveats

- **Single host only** -- sockets are local to the machine; this does not work across a network.
- **No peer authentication** -- any local user who can access the socket can attempt to connect. Encryption provides confidentiality but
  not identity verification. The username embedded in encrypted messages is self-asserted and can be spoofed by anyone holding the
  session key. The `share-key` / `receive-key` commands display a short verification code that both parties should compare out-of-band
  to confirm they exchanged keys with the intended peer.
- **Single client** -- the server handles one connected client at a time. A new client can connect after the previous one disconnects.
- **USER env var trusted for identity** -- the `USER` environment variable determines the local username displayed in chat. This can
  be overridden by any process and should not be relied upon for authentication.
- **No replay or reorder protection** -- AES-256-GCM provides per-message integrity and confidentiality, but there is no sequence
  numbering or replay detection. A local attacker with raw access to the Unix socket traffic could theoretically replay or reorder
  captured ciphertext.
- **`--password` visible in process listing** -- when using `--password <pwd>` on the command line, the password is visible to other
  local users via `ps`. Prefer key exchange for sensitive sessions.
