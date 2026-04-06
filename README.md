# unix-chat

A peer-to-peer encrypted chat system for local users on the same machine, using Unix abstract sockets and OpenSSL symmetric encryption with
SSH key-based key management.

## How it works

### Architecture

unix-chat uses **Unix sockets** for inter-process communication between users on the same host. 

### Encryption

Messages are encrypted with **AES-256**. The key lifecycle works as follows:

1. A random 256-bit key is generated with.
2. That key is encrypted using the user's **SSH public key** (derived from `~/.ssh/id_ed2551_unix_chat`) and stored in a temporary file (
   `/tmp/.unix_chat_chat_key_<pid>`).
3. At chat time the key is decrypted with the SSH private key and used for symmetric encryption/decryption of messages.
4. The temporary key file is removed on exit.

### Key exchange

Before two users can chat, they must share the same symmetric key. The `share_key` / `receive_key` commands set up a one-shot abstract
socket (`@key_exchange_<pid>`) to transfer the encrypted key file from one user to another.

### Message flow

```
User A (stdin) --> AES-256 encrypt --> unix socket --> AES-256 decrypt --> User B (stdout)
User B (stdin) --> AES-256 encrypt --> unix socket --> AES-256 decrypt --> User A (stdout)
```

## Usage

```
$ chat {start|connect <username>|list|share_key <username>|receive_key <pid>}
```

### Start a chat server

```bash
./chat start
```

Binds to `unix_chat_<your_username>`, generates an encryption key, and waits for incoming connections. Messages you type are 
encrypted and sent; incoming messages are decrypted and printed in real time.

### Connect to another user

```bash
./chat connect alice
```

Connects to the unix socket `unix_chat_alice` and begins an encrypted chat session.

### List available chat servers

```bash
./chat list
```

Scans for active `unix_chat_*` sockets and prints the usernames of available peers.

### Share your encryption key

```bash
# On your terminal:
./chat share_key bob

# The script prints instructions for the receiver:
# "On bob's terminal, run: ./chat receive_key 12345"
```

Opens a one-shot socket and waits for the other user to connect and retrieve the key.

### Receive an encryption key

```bash
# On bob's terminal (using the PID printed by the sender):
./chat receive_key 12345
```

Connects to the sender's key-exchange socket and saves the encrypted key locally.

## Example session

**Terminal 1 (alice):**

```bash
alice$ ./chat start
Starting encrypted chat server on abstract socket @unix_chat_alice
Waiting for connections...
```

**Terminal 2 (bob) -- key exchange, then connect:**

```text
# Alice shares her key with bob
alice$ ./chat share_key bob
Waiting for bob to receive the key...
On bob's terminal, run: ./chat receive_key 54321
>

# Bob receives the key
bob$ ./chat receive_key 54321
Receiving encryption key...
Encryption key received and saved

# Bob connects
bob$ ./chat connect alice
Connecting to alice's encrypted chat...
> hello alice!
```

## Limitations

- **Single host only** -- sockets are local to the machine; this does not work across a network.
- **No authentication** -- any local user who knows the socket name can attempt to connect. The encryption key exchange provides
  confidentiality but not identity verification.
