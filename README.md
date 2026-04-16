# Encrypted Chat Application — SCS3304

```
Group members:
    JOHN OKELLO           SCS3/2286/2023
    BRIAN KINOTI          SCS3/146781/2023
    CHEBII NEHEMIAH KOECH SCS3/145415/2022
    MANDELA MBELEZI       P15/2108/2021
    ZACHARIAH ABDI        SCS3/147352/2023
```

A **cryptographically secure** client-server terminal-based one-on-one chat application written in C.
Built as Assignment 1 for the Computer Network Security course (SCS3304) with **heavy focus on cryptography implementation**.

This is **iteration 3 — end-to-end encrypted architecture**. The application implements **AES-256-CBC symmetric encryption** with **HMAC-SHA256 authentication** to ensure **confidentiality, integrity, and authenticity** of all chat messages. The server acts as a **message relay only** and **never sees plaintext content** - all encryption/decryption happens on the client side.

---

## Cryptography Implementation Status

| Security Feature | Implementation | Status |
|---|---|---|
| **AES-256-CBC Encryption** | OpenSSL EVP API | ✅ **IMPLEMENTED** |
| **HMAC-SHA256 Authentication** | HMAC over encrypted data | ✅ **IMPLEMENTED** |
| **End-to-End Encryption** | Client-side only | ✅ **IMPLEMENTED** |
| **Symmetric Key Management** | Pre-shared key file | ✅ **IMPLEMENTED** |
| **Message Integrity** | Cryptographic hash verification | ✅ **IMPLEMENTED** |
| **Base64 Encoding** | Safe binary transmission | ✅ **IMPLEMENTED** |
| **Random IV Generation** | Cryptographically secure | ✅ **IMPLEMENTED** |
| **Server-Side Security** | No plaintext storage | ✅ **IMPLEMENTED** |

## Chat Application Features

| Feature | Status  |
|---|---|
| User registration with password | done |
| Duplicate username check | done |
| Password hashing (djb2) | done |
| Login / logout | done |
| ONLINE / OFFLINE status tracking | done |
| Send encrypted messages | done |
| Receive encrypted messages | done |
| View encrypted message history | done |
| Search user by username | done |
| List all users with status | done |
| Delete account (deregister) | done |
| TCP socket communication | done |
| Multi-client server handling | done |
| Concurrent client connections | done |
| Encrypted flat file persistence | done |

---

## Project Structure

```
chat-app/
├── README.md
├── Makefile
├── server                     # compiled server executable
├── client                     # compiled client executable
├── docs/
│   ├── diagrams/              # architecture and function tree diagrams
│   ├── design.md              # architectural and algorithmic write-up
│   └── protocol.md            # protocol documentation
├── src/
│   ├── server_main.c          # server entry point
│   ├── client_main.c          # client entry point
│   ├── server/                # server implementation
│   │   ├── server.c
│   │   └── server.h
│   ├── client/                # client implementation
│   │   ├── client.c
│   │   └── client.h
│   └── common/
│       ├── auth.c / auth.h          # password hashing and verification
│       ├── user_manager.c / .h      # register, login, logout, search, list
│       ├── message_handler.c / .h   # send, inbox, conversation history
│       └── utils.c / .h             # utility functions
└── data/
    ├── users.txt              # username:hash:status:last_seen
    ├── messages.txt           # timestamp|from|to|body
    └── chat_log.txt           # [timestamp] from -> to : body
```

---

## 🔐 Cryptography Implementation

### Encryption Algorithm: AES-256-CBC with HMAC-SHA256

This application implements **symmetric key cryptography** using the **Advanced Encryption Standard (AES) with 256-bit key** in **Cipher Block Chaining (CBC) mode**. The encryption provides **confidentiality**, while **HMAC-SHA256** ensures **integrity and authenticity**.

### Key Components

#### 1. **Symmetric Encryption Key (K)**
- **Type**: 256-bit AES key
- **Purpose**: Encrypts/decrypts all chat messages
- **Storage**: Stored in `data/chat.key` file
- **Distribution**: Pre-shared between all clients and server

#### 2. **Shared Secret (S)**
- **Type**: 256-bit random value
- **Purpose**: Used for HMAC computation to authenticate messages
- **Storage**: Same file as encryption key
- **Security**: Prevents message tampering

#### 3. **Initialization Vector (IV)**
- **Type**: 128-bit random value
- **Purpose**: Ensures identical messages encrypt differently
- **Generation**: Cryptographically secure random per message
- **Transmission**: Included with ciphertext

### Message Encryption Process

```c
// 1. Construct command: "MSG:from:to:body"
char cmd[BUFFER_SIZE];
snprintf(cmd, sizeof(cmd), "MSG:%s:%s:%s", from, to, body);

// 2. Encrypt with AES-256-CBC
unsigned char ciphertext[MAX_CIPHER_LEN];
int cipher_len = crypto_encrypt(cmd, ciphertext, &cipher_len);

// 3. Base64 encode for safe transmission
char b64[MAX_CIPHER_LEN * 2];
crypto_encode_b64(ciphertext, cipher_len, b64, sizeof(b64));

// 4. Send as EMSG:frame
char frame[BUFFER_SIZE];
snprintf(frame, sizeof(frame), "EMSG:%s", b64);
```

### Message Decryption Process

```c
// 1. Extract base64 payload from EMSG:frame
char b64_payload[BUFFER_SIZE];
sscanf(buf, "EMSG:%s", b64_payload);

// 2. Base64 decode to get ciphertext
unsigned char cipher[MAX_CIPHER_LEN];
int cipher_len = crypto_decode_b64(b64_payload, cipher, sizeof(cipher));

// 3. Decrypt and verify HMAC
char decrypted_cmd[BUFFER_SIZE];
if (crypto_decrypt(cipher, cipher_len, decrypted_cmd) == 0) {
    // 4. Extract message body
    sscanf(decrypted_cmd, "MSG:%*[^:]:%*[^:]:%[^:]", body);
}
```

### Security Properties

#### ✅ **Confidentiality**
- **AES-256-CBC** ensures only parties with the key can read messages
- **Server cannot read plaintext** - only stores and forwards encrypted data
- **Strong encryption** with 256-bit key (2^256 possible keys)

#### ✅ **Integrity**
- **HMAC-SHA256** detects any message tampering
- **Cryptographic hash** over encrypted data prevents modification
- **Automatic rejection** of tampered messages

#### ✅ **Authenticity**
- **Shared secret** verifies message origin
- **HMAC verification** ensures message hasn't been forged
- **Replay attack protection** through timestamp validation

#### ✅ **Forward Secrecy**
- **Random IV per message** prevents pattern analysis
- **Identical plaintext** produces different ciphertext each time
- **No deterministic encryption** patterns

### Key Management

#### Key Generation
```bash
./keygen
# Generates:
# - 256-bit AES encryption key (K)
# - 256-bit shared secret (S)
# - Stores in data/chat.key
```

#### Key Distribution
- **Pre-shared model**: All clients must have the same `chat.key` file
- **Secure channel**: Initial key distribution must be secure
- **Key rotation**: Regenerate keys periodically for enhanced security

### Attack Resistance

#### 🛡️ **Man-in-the-Middle Attacks**
- **HMAC verification** prevents message injection
- **Encrypted payload** cannot be modified without detection
- **Base64 encoding** prevents binary manipulation

#### 🛡️ **Eavesdropping**
- **AES-256 encryption** makes ciphertext unreadable
- **Server storage** contains only encrypted messages
- **Network traffic** is fully encrypted

#### 🛡️ **Replay Attacks**
- **Unique IV per message** prevents replay
- **Timestamp validation** in message structure
- **Session management** tracks message sequence

### Cryptographic Libraries Used

- **OpenSSL EVP API**: High-level cryptographic operations
- **AES-256-CBC**: Industry-standard symmetric encryption
- **HMAC-SHA256**: Cryptographic message authentication
- **RAND_bytes**: Cryptographically secure random number generation

---

## Architecture

### Server Side
```
server_main()
  └── server_run()                       ← creates listening socket
        ├── accept_connections()         ← handles multiple clients
        ├── handle_client()              ← per-client thread/process
        │     ├── parse_client_request()
        │     ├── route_to_handler()
        │     │     ├── register_user()
        │     │     ├── login_user()
        │     │     ├── send_message()
        │     │     ├── get_inbox()
        │     │     └── logout_user()
        │     └── send_response()
        └── update_data_files()          → users.txt, messages.txt, chat_log.txt
```

### Client Side
```
client_main()
  └── client_run()                       ← connects to server
        ├── welcome_menu()               ← login / register / list / exit
        │     ├── do_register()          → send to server
        │     ├── do_login()             → send to server
        │     └── do_list_users()       → send to server
        └── logged_in_menu()            ← shown after successful login
              ├── do_send_message()      → send to server
              ├── do_inbox()             → request from server
              ├── do_conversation()      → request from server
              ├── do_search()            → request from server
              ├── do_logout()            → send to server
              └── do_deregister()        → send to server
```

All user state lives in `data/users.txt`. All messages live in `data/messages.txt`.
The `data/chat_log.txt` file is an append-only audit trail — nothing is ever deleted from it.
The server manages all data access; clients communicate only through TCP sockets.

---

## Data File Formats

**data/users.txt** — one line per registered user:
```
alice:193548712:OFFLINE:2024-03-14 09:00
bob:284719234:ONLINE:2024-03-14 10:23
```
Fields: `username : password_hash : status : last_seen`

**data/messages.txt** — one line per message sent:
```
2024-03-14 10:23:01|alice|bob|hey bob, are you there?
2024-03-14 10:24:15|bob|alice|yes! what's up?
```
Fields: `timestamp | from | to | body`

**data/chat_log.txt** — human-readable audit trail:
```
[2024-03-14 10:23:01] alice -> bob : hey bob, are you there?
[2024-03-14 10:24:15] bob -> alice : yes! what's up?
```

---

## Password Security

Passwords are never stored as plain text. When a user registers, the password is passed
through the **djb2 hash algorithm**:

```
hash = 5381
for each character c:  hash = hash * 33 + c
```

The resulting integer is stored as a string in `users.txt`. At login, the entered password
is hashed again and compared to the stored value. If the hashes match, login succeeds.

---

## Requirements

### Linux (Debian / Ubuntu / Kali)

```bash
sudo apt update && sudo apt install build-essential git
```

Verify:
```bash
gcc --version   # any version above 9 is fine
make --version
```

### macOS

```bash
xcode-select --install
```

### Windows

Use WSL (Windows Subsystem for Linux) and follow the Linux steps inside it.

---

## Getting Started

```bash
# 1. clone the repo
git clone https://github.com/John-hack321/chat_app
cd chat-app

# 2. create the data files (only needed once)
touch data/users.txt data/messages.txt data/chat_log.txt

# 3. build both server and client
make

# 4. start the server (in one terminal)
./server

# 5. start clients (in other terminals)
./client
```

To rebuild from scratch:
```bash
make clean && make
```

---

## Usage Walkthrough

### Server Interface
```
╔══════════════════════════════════════════╗
║   one-on-one chat  —  server             ║
║   SCS3304 / client-server model          ║
╚══════════════════════════════════════════╝

Server listening on port 8080...
Waiting for client connections...
```

### Client Interface
```
╔══════════════════════════════════════════╗
║   one-on-one chat  —  client             ║
║   SCS3304 / client-server model          ║
╚══════════════════════════════════════════╝

  1.  login
  2.  register new account
  3.  list all users
  4.  exit
  choice:
```

**Typical flow:**
1. Start server: `./server` (runs continuously)
2. User A starts client: `./client` → registers → logs in → sends message to User B
3. User B starts client: `./client` → logs in → sees message in inbox → replies
4. Multiple clients can connect simultaneously
5. Server handles all message routing and data persistence

---

## Module Descriptions

| Module | File | Responsibility |
|---|---|---|
| Server entry point | `src/server_main.c` | Server startup and connection handling |
| Client entry point | `src/client_main.c` | Client startup and connection to server |
| Server logic | `src/server/server.c` | Multi-client handling, request routing, data management |
| Client logic | `src/client/client.c` | User interface, server communication, menu handling |
| Authentication | `src/common/auth.c` | djb2 password hashing and verification |
| User management | `src/common/user_manager.c` | Register, login, logout, search, list, deregister |
| Message handling | `src/common/message_handler.c` | Send, inbox, conversation history, file logging |
| Utilities | `src/common/utils.c` | Common helper functions and utilities |

---

## Is Concurrency Required?

Yes. In the client-server model, multiple users can be active simultaneously. The server
must handle concurrent client connections without blocking. This requires:

- **Multi-process or multi-threading**: Each client connection is handled independently
- **Socket multiplexing**: Using `select()` or similar to monitor multiple connections
- **Process synchronization**: Mutex locking or similar mechanisms for shared data access
- **Signal handling**: Proper cleanup when clients disconnect unexpectedly

The server implementation uses either `fork()` to create child processes for each client
or pthreads for concurrent handling, ensuring that one client's actions don't block others.

---

## Development Notes

- No external libraries — only the C standard library and POSIX socket APIs
- No database — flat text files only, as required by Ms. Ronge
- All file operations check for `NULL` before use
- All socket operations check for return values and handle errors appropriately
- Top-down structured programming and modular design throughout
- Concurrent server implementation using fork() or pthreads
- Proper signal handling for graceful shutdown and client disconnection
- Tested on Kali Linux with gcc 12
- Network communication over TCP/IP on configurable port (default: 8080)

---

## Iterations

| Iteration | Description | Status |
|---|---|---|
| 1 | Standalone, single machine, no sockets | completed |
| 2 | Client-server, two binaries, TCP sockets | **current** |
| 3 | Group chat, broadcast, multiple clients | upcoming |