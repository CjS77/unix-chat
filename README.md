# unix-chat

A peer-to-peer encrypted chat system for local users on the same machine, using Unix sockets and AES-256-GCM symmetric encryption with SSH
key-based key derivation. Supports multiple simultaneous clients with message relay, and file transfer.

## How it works

### Architecture

unix-chat uses **Unix domain sockets** in `/tmp/unix_chat_sockets/` for inter-process communication between users on the same host. Access
control is managed via a `unixchat` system group -- users in this group can create and connect to chat sockets. An `--world` flag is
available to bypass group restrictions.

The server accepts **multiple simultaneous clients**. A relay layer broadcasts each incoming message to all other connected participants,
enabling group chat. The server operator also participates in the chat as a regular client.

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
another user. Both sides display a short authentication string (SAS) that should be compared out-of-band to confirm the exchange was not
tampered with.

### Wire protocol

Messages are framed as **type-tagged, length-prefixed** packets:

```
[2 bytes: MessageType (big-endian u16)]
[4 bytes: Payload length (big-endian u32)]
[N bytes: Encrypted payload]
```

**Message types:**

| Type ID  | Name    | Description                      |
|----------|---------|----------------------------------|
| `0x0001` | Text    | Chat message                     |
| `0x0002` | File    | File transfer (via `/share`)     |

Unknown message types are preserved for forward compatibility.

The maximum payload size is **1 MiB** (1,048,576 bytes).

**Plaintext format** (before encryption): `[1 byte: username length][username bytes][message body]`

**File payload format**: `[2 bytes BE: filename length][filename bytes][file content]`

**Encryption layer**: Each payload is encrypted with AES-256-GCM. The wire format for encrypted data is `[12-byte nonce][ciphertext + 16-byte GCM tag]`.

```
User A (stdin) --> AES-256-GCM encrypt --> [type|len|payload] --> unix socket
                                                                     |
                                                                   relay
                                                                     |
                                           [type|len|payload] --> AES-256-GCM decrypt --> User B (stdout)
                                           [type|len|payload] --> AES-256-GCM decrypt --> User C (stdout)
```

## Installation

```bash
cargo install --path .
```

Requires Rust 2024 edition (1.85+). The binary is called `uc`.

## Setup

Run `uc init` to check your environment, generate the required SSH key, and configure group membership:

```bash
uc init
```

This will:

- Check for `ssh-keygen` and offer to generate `~/.ssh/id_ed25519_unix_chat`
- Check for the `unixchat` system group and print admin instructions if needed
- Create the socket directory with correct permissions

## Usage

```
uc {start|connect <name>|list|share-key <username>|receive-key <pid>|init}
```

### Start a chat server

```bash
uc start
```

Creates a socket at `/tmp/unix_chat_sockets/<username>.sock`, derives an encryption key from your SSH key, and waits for incoming
connections. Multiple clients can connect simultaneously -- messages are relayed to all participants.

Options:

- `--topic <name>` -- use a custom topic name instead of your username
- `--password <pwd>` -- publish a password-protected session key so clients can connect without manual key exchange.
  **Security note:** the password will be visible in the process listing (e.g. `ps aux`). For sensitive sessions, prefer
  the key exchange workflow instead.
- `--world` -- set socket permissions to 0666 instead of group-restricted 0660

### Connect to a chat server

```bash
uc connect alice
```

Connects to the socket for the given topic/username. The client resolves the session key by checking (in order):

1. A password-protected key file published by the server
2. A key previously received via `receive-key`

### List available chat servers

```bash
uc list
```

Scans `/tmp/unix_chat_sockets/` for active `.sock` files and prints available topics.

### Share your encryption key

```bash
uc share-key bob
```

Opens a one-shot key exchange socket and waits for the recipient to connect and retrieve the session key. Both sides display a
short authentication string (SAS) for out-of-band verification.

Options:

- `--world` -- allow any local user to connect to the exchange socket

### Receive an encryption key

```bash
# Using the PID printed by the sender:
uc receive-key 12345
```

Connects to the sender's key exchange socket, downloads the session key, and saves it to `/tmp/.unix_chat_received_key_<username>`.

## In-chat commands

While chatting, the following slash commands are available:

| Command          | Description                                          |
|------------------|------------------------------------------------------|
| `/help`          | Show available commands                              |
| `/share <file>`  | Send a file to all connected participants            |
| `/whoami`        | Print your username                                  |
| `/quit`          | Exit the chat                                        |

Received files are saved to `~/unix-chat/shared/<topic>/`.

## Example session

**Terminal 1 (alice) -- start with a password:**

```bash
alice$ uc start --password s3cret
Session key published (password-protected)
Chat server started on /tmp/unix_chat_sockets/alice.sock
Waiting for connections...
```

**Terminal 2 (bob) -- connect with the password:**

```bash
bob$ uc connect alice
Session password: s3cret
Decrypting session key.. OK!
Connected to alice!

bob> hello alice!
```

**Terminal 3 (charlie) -- another participant joins:**

```bash
charlie$ uc connect alice
Session password: s3cret
Decrypting session key.. OK!
Connected to alice!

charlie> hey everyone!
```

**Sharing a file:**

```bash
bob> /share notes.txt
File sent: notes.txt (1234 bytes)
```

Alice and charlie each receive `notes.txt` saved to `~/unix-chat/shared/alice/notes.txt`.

**Alternative: manual key exchange (no password)**

```bash
# Alice starts without --password
alice$ uc start
# Alice shares her key
alice$ uc share-key bob
Waiting for bob to receive the key...
On bob's terminal, run: uc receive-key 54321

# Bob receives and connects
bob$ uc receive-key 54321
Encryption key received and saved
bob$ uc connect alice
Connected to alice!
```

## Limitations and Security Caveats

- **Single host only** -- sockets are local to the machine; this does not work across a network.
- **No peer authentication** -- any local user who can access the socket can attempt to connect. Encryption provides confidentiality but
  not identity verification. The username embedded in encrypted messages is self-asserted and can be spoofed by anyone holding the
  session key. The `share-key` / `receive-key` commands display a short verification code that both parties should compare out-of-band
  to confirm they exchanged keys with the intended peer.
- **USER env var trusted for identity** -- the `USER` environment variable determines the local username displayed in chat. This can
  be overridden by any process and should not be relied upon for authentication.
- **No replay or reorder protection** -- AES-256-GCM provides per-message integrity and confidentiality, but there is no sequence
  numbering or replay detection. A local attacker with raw access to the Unix socket traffic could theoretically replay or reorder
  captured ciphertext.
- **`--password` visible in process listing** -- when using `--password <pwd>` on the command line, the password is visible to other
  local users via `ps`. Prefer key exchange for sensitive sessions.
- **1 MiB message limit** -- individual messages and file transfers are capped at 1 MiB.
- **Socket creation race (TOCTOU)** -- a small window exists between removing a stale socket and binding a new one.  A local attacker
  who can write to the socket directory could theoretically exploit this to intercept connections. The window is very narrow and
  requires precise timing.
- **File receive directory race** -- when receiving a file, the save directory is created and then the file is written as two separate
  operations. Between these steps the directory could theoretically be replaced with a symlink by another local process, though the
  filename itself is sanitized to a basename.
