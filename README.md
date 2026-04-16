# One-on-One Chat Application — SCS3304

```
Group members:
    JOHN OKELLO           SCS3/2286/2023
    BRIAN KINOTI          SCS3/146781/2023
    CHEBII NEHEMIAH KOECH SCS3/145415/2022
    MANDELA MBELEZI       P15/2108/2021
    ZACHARIAH ABDI        SCS3/147352/2023
```

A client-server terminal-based one-on-one chat application written in C.
Built as Assignment 1 for the Networks and Distributed Programming course (SCS3304).

This is **iteration 2 — client-server architecture**. Multiple users can connect simultaneously
from different machines. The server handles client connections, message routing, and user management.
Communication happens over TCP sockets, while persistence is maintained through flat text files
as required by the course.

---

## Current Status

| Feature | Status  |
|---|---|
| User registration with password | done |
| Duplicate username check | done |
| Password hashing (djb2) | done |
| Login / logout | done |
| ONLINE / OFFLINE status tracking | done |
| Send message to registered user | done |
| View inbox (all received messages) | done |
| View conversation thread (both directions) | done |
| Search user by username | done |
| List all users with status | done |
| Delete account (deregister) | done |
| TCP socket communication | done |
| Multi-client server handling | done |
| Concurrent client connections | done |
| Flat file persistence (no database) | done |

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