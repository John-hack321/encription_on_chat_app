/*
 * SCS3304 — One-on-One Chat Application
 * Server Module
 *
 * HOW THIS SERVER WORKS:
 *
 *   1. We create one listening socket and bind it to port 8080.
 *      This socket's only job is to wait for incoming connections.
 *
 *   2. When a client connects, accept() returns a brand new socket
 *      file descriptor just for that client. The listening socket
 *      stays open and keeps waiting for more clients.
 *
 *   3. We call fork() immediately after accept(). This creates a
 *      child process that is an exact copy of the server at that
 *      moment. The child closes the listening socket (it doesn't
 *      need it) and handles the client. The parent closes the
 *      client socket (the child has it) and loops back to accept().
 *
 *   4. The child process handles all commands from its client until
 *      the client disconnects, then exits.
 *
 *   CONCURRENCY ACHIEVED:
 *   Multiple clients are handled simultaneously — each in their own
 *   child process. File locks (flock in user_manager and
 *   message_handler) prevent those processes from corrupting shared
 *   data files.
 *
 *   ENCRYPTION INTEGRATION (diagram (d) from Lesson 6):
 *   When a client sends a message, it arrives as:
 *
 *     EMSG:<base64(IV + AES-256-CBC( MSG:from:to:body || H(MSG:from:to:body || S) ))>
 *
 *   The server:
 *     1. Decrypts and verifies the hash (rejects tampered messages)
 *     2. Parses the decrypted command (MSG:from:to:body)
 *     3. Stores the plaintext body to messages.txt
 *     4. If the recipient is online, re-encrypts and sends EDELIVER
 *     5. Sends ACK:OK back to the sender
 *
 *   Control commands (LOGIN, LOGOUT, LIST, etc.) are NOT encrypted
 *   because they carry no sensitive message content.
 */

 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <signal.h>
 #include <sys/socket.h>
 #include <sys/wait.h>
 #include <sys/file.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 
 #include "server.h"
 #include "../common/protocol.h"
 #include "../common/utils.h"
 #include "../common/user_manager.h"
 #include "../common/message_handler.h"
 #include "../common/crypto.h"
 
 /* ── active session: maps username → socket fd ── */
 #define SESSIONS_FILE "data/sessions.txt"
 
 /* ── write username:fd to sessions file so other processes can find it ── */
 static void session_register(const char *username, int fd) {
     FILE *fp = fopen(SESSIONS_FILE, "a");
     if (fp == NULL) return;
     flock(fileno(fp), LOCK_EX);
     fprintf(fp, "%s:%d\n", username, fd);
     flock(fileno(fp), LOCK_UN);
     fclose(fp);
 }
 
 /* ── remove a username from the sessions file on logout/disconnect ── */
 static void session_remove(const char *username) {
     char lines[MAX_USERS][64];
     int  count = 0;
 
     FILE *fp = fopen(SESSIONS_FILE, "r");
     if (fp == NULL) return;
     flock(fileno(fp), LOCK_SH);
     while (count < MAX_USERS && fgets(lines[count], 64, fp) != NULL)
         count++;
     flock(fileno(fp), LOCK_UN);
     fclose(fp);
 
     fp = fopen(SESSIONS_FILE, "w");
     if (fp == NULL) return;
     flock(fileno(fp), LOCK_EX);
     for (int i = 0; i < count; i++) {
         char name[50];
         sscanf(lines[i], "%49[^:]", name);
         if (strcasecmp(name, username) != 0)
             fputs(lines[i], fp);
     }
     flock(fileno(fp), LOCK_UN);
     fclose(fp);
 }
 
 /* ── look up the socket fd for a connected user ── */
 static int session_find_fd(const char *username) {
     FILE *fp = fopen(SESSIONS_FILE, "r");
     if (fp == NULL) return -1;
 
     flock(fileno(fp), LOCK_SH);
     char line[64];
     char name[50];
     int  fd;
     int  result = -1;
 
     while (fgets(line, sizeof(line), fp) != NULL) {
         if (sscanf(line, "%49[^:]:%d", name, &fd) == 2) {
             if (strcasecmp(name, username) == 0) { result = fd; break; }
         }
     }
     flock(fileno(fp), LOCK_UN);
     fclose(fp);
     return result;
 }
 
 /* ============================================================
  * FUNCTION : handle_encrypted_msg
  * PURPOSE  : Handle an EMSG frame — the encrypted message path.
  *
  *   EMSG:<base64(IV + ciphertext)>
  *
  *   Steps:
  *     1. Base64-decode to get raw ciphertext
  *     2. Decrypt with AES-256-CBC key K
  *     3. Verify H(plaintext || S) — reject if mismatch
  *     4. Parse decrypted command: MSG:from:to:body
  *     5. Store body to messages.txt (plaintext in storage)
  *     6. If recipient is online: re-encrypt and send EDELIVER
  *     7. Send ACK:OK back to sender
  *
  *   Storing plaintext in messages.txt is a deliberate choice for
  *   this iteration — it lets the server build inbox and history
  *   views without needing client-side decryption of stored messages.
  *   A future iteration could store ciphertext and move decryption
  *   entirely to the client.
  * ============================================================ */
 static void handle_encrypted_msg(int client_fd, const char *b64_payload) {
    char response[BUFFER_SIZE];

    /* DEBUG: Show received encrypted payload */
    printf("  [DEBUG] Received encrypted payload: %s\n", b64_payload);

    /* ── Step 1: base64 decode ── */
     unsigned char ciphertext[MAX_CIPHER_LEN];
     int cipher_len = crypto_decode_b64(b64_payload, ciphertext, sizeof(ciphertext));
     if (cipher_len < 0) {
         snprintf(response, sizeof(response), "%s:base64 decode failed", CMD_ACK_ERR);
         send_msg(client_fd, response);
         return;
     }
 
     /* ── Step 2 + 3: decrypt and verify hash ── */
     char plaintext[BUFFER_SIZE];
     if (crypto_decrypt(ciphertext, cipher_len, plaintext) != 0) {
         /*
          * Decryption failed OR hash mismatch.
          * This means the message was tampered with in transit.
          * Reject it — do not store or forward.
          */
         fprintf(stderr, "  [!] EMSG: rejected — decryption/auth failed\n");
         snprintf(response, sizeof(response), "%s:message authentication failed", CMD_ACK_ERR);
         send_msg(client_fd, response);
         return;
     }
 
     /* ── Step 4: parse decrypted command ── */
     /* plaintext is "MSG:from:to:body" */
     char a1[50] = {0}, a2[50] = {0}, body[MAX_BODY_LEN] = {0};
     sscanf(plaintext, "%*[^:]:%49[^:]:%49[^:]:%1023[^\n]", a1, a2, body);
 
     if (strlen(a1) == 0 || strlen(a2) == 0 || strlen(body) == 0) {
         snprintf(response, sizeof(response), "%s:malformed encrypted command", CMD_ACK_ERR);
         send_msg(client_fd, response);
         return;
     }
 
     printf("  [enc] %s → %s : [authenticated message]\n", a1, a2);
 
     /* ── Step 5: store encrypted payload to messages.txt */
    int r = store_encrypted_message(a1, a2, b64_payload);
     if (r != SUCCESS) {
         snprintf(response, sizeof(response), "%s:recipient not found", CMD_ACK_ERR);
         send_msg(client_fd, response);
         return;
     }
 
     /* ── Step 6: real-time encrypted delivery to recipient ── */
     int recipient_fd = session_find_fd(a2);
     if (recipient_fd > 0 && recipient_fd != client_fd) {
         /*
          * Re-encrypt the original plaintext command for the recipient.
          * We use a fresh random IV each time (handled inside crypto_encrypt)
          * so even if the recipient intercepts their own traffic the IVs differ.
          */
         unsigned char out_cipher[MAX_CIPHER_LEN];
         int out_len = 0;
 
         if (crypto_encrypt(plaintext, out_cipher, &out_len) == 0) {
             char b64_out[MAX_CIPHER_LEN * 2];
             crypto_encode_b64(out_cipher, out_len, b64_out, sizeof(b64_out));
 
             char deliver[BUFFER_SIZE];
             snprintf(deliver, sizeof(deliver), "EDELIVER:%s:%s", a1, b64_out);
 
             /* DEBUG: Show encrypted message before forwarding */
             printf("  [DEBUG] Forwarding encrypted message to %s: %s\n", a2, b64_out);
 
             send_msg(recipient_fd, deliver);
         } else {
             /* fallback: send plaintext DELIVER if re-encryption fails */
             char deliver[BUFFER_SIZE];
             snprintf(deliver, sizeof(deliver), "%s:%s:%s", CMD_DELIVER, a1, body);
             send_msg(recipient_fd, deliver);
         }
     }
 
     /* ── Step 7: ACK back to sender ── */
     send_msg(client_fd, CMD_ACK_OK);
 }
 
 /* ============================================================
  * FUNCTION : handle_command
  * PURPOSE  : Parse and execute one command from a client
  * INPUT    : client_fd      — socket for this client
  *            cmd            — the command string received
  *            session_user   — buffer holding logged-in username
  *                             (empty string = not logged in)
  * ============================================================ */
 static void handle_command(int client_fd, char *cmd, char *session_user) {
     char response[BUFFER_SIZE];
     char command[16] = {0};
     char a1[50]      = {0};
     char a2[50]      = {0};
     char body[MAX_BODY_LEN] = {0};
 
     sscanf(cmd, "%15[^:]", command);
 
     /* ── EMSG — encrypted message (diagram d) ── */
     if (strcmp(command, "EMSG") == 0) {
         /*
          * EMSG:<base64_payload>
          * Everything after "EMSG:" is the base64-encoded ciphertext.
          */
         const char *b64 = cmd + 5;   /* skip "EMSG:" */
         handle_encrypted_msg(client_fd, b64);
         return;
     }
 
     /* ── REGISTER ── REG:username:password ── */
     if (strcmp(command, CMD_REGISTER) == 0) {
         sscanf(cmd, "%*[^:]:%49[^:]:%49[^\n]", a1, a2);
         int r = register_user(a1, a2);
         if      (r == SUCCESS)       snprintf(response, sizeof(response), CMD_ACK_OK);
         else if (r == ERR_DUPLICATE) snprintf(response, sizeof(response), "%s:username already taken", CMD_ACK_ERR);
         else if (r == ERR_INVALID)   snprintf(response, sizeof(response), "%s:invalid username or password too short", CMD_ACK_ERR);
         else                         snprintf(response, sizeof(response), "%s:server error", CMD_ACK_ERR);
         send_msg(client_fd, response);
     }
 
     /* ── LOGIN ── LOGIN:username:password ── */
     else if (strcmp(command, CMD_LOGIN) == 0) {
         sscanf(cmd, "%*[^:]:%49[^:]:%49[^\n]", a1, a2);
         int r = login_user(a1, a2);
         if (r == SUCCESS) {
             strncpy(session_user, a1, MAX_NAME_LEN);
             session_register(a1, client_fd);
             printf("  [+] %s logged in (fd=%d)\n", a1, client_fd);
             send_msg(client_fd, CMD_ACK_OK);
         } else if (r == ERR_NOT_FOUND)  { snprintf(response, sizeof(response), "%s:user not found",    CMD_ACK_ERR); send_msg(client_fd, response); }
         else if   (r == ERR_WRONG_PASS) { snprintf(response, sizeof(response), "%s:wrong password",    CMD_ACK_ERR); send_msg(client_fd, response); }
         else if   (r == ERR_ALREADY_ON) { snprintf(response, sizeof(response), "%s:already logged in", CMD_ACK_ERR); send_msg(client_fd, response); }
         else                            { snprintf(response, sizeof(response), "%s:login failed",       CMD_ACK_ERR); send_msg(client_fd, response); }
     }
 
     /* ── LOGOUT ── LOGOUT:username ── */
     else if (strcmp(command, CMD_LOGOUT) == 0) {
         sscanf(cmd, "%*[^:]:%49[^\n]", a1);
         logout_user(a1);
         session_remove(a1);
         session_user[0] = '\0';
         printf("  [*] %s logged out\n", a1);
         send_msg(client_fd, CMD_ACK_OK);
     }
 
     /* ── DEREGISTER ── DEREG:username ── */
     else if (strcmp(command, CMD_DEREGISTER) == 0) {
         sscanf(cmd, "%*[^:]:%49[^\n]", a1);
         logout_user(a1);
         session_remove(a1);
         int r = deregister_user(a1);
         session_user[0] = '\0';
         send_msg(client_fd, r == SUCCESS ? CMD_ACK_OK : CMD_ACK_ERR);
     }
 
     /* ── LIST ── LIST ── */
     else if (strcmp(command, CMD_LIST) == 0) {
         build_user_list(response, sizeof(response));
         send_msg(client_fd, response);
     }
 
     /* ── SEARCH ── SEARCH:username ── */
     else if (strcmp(command, CMD_SEARCH) == 0) {
         sscanf(cmd, "%*[^:]:%49[^\n]", a1);
         if (user_exists(a1))
             snprintf(response, sizeof(response), "SEARCH_RESULT:%s:%s",
                      a1, is_online(a1) ? STATUS_ONLINE : STATUS_OFFLINE);
         else
             snprintf(response, sizeof(response), "SEARCH_RESULT:not_found");
         send_msg(client_fd, response);
     }
 
     /* ── SEND MESSAGE (plaintext fallback) ── MSG:from:to:body ── */
     /*    In normal operation the client uses EMSG instead.         */
     /*    This branch handles the case where crypto is unavailable. */
     else if (strcmp(command, CMD_MSG) == 0) {
         sscanf(cmd, "%*[^:]:%49[^:]:%49[^:]:%1023[^\n]", a1, a2, body);
         int r = store_message(a1, a2, body);
         if (r != SUCCESS) {
             snprintf(response, sizeof(response), "%s:recipient not found", CMD_ACK_ERR);
             send_msg(client_fd, response);
             return;
         }
         int recipient_fd = session_find_fd(a2);
         if (recipient_fd > 0 && recipient_fd != client_fd) {
             char deliver[BUFFER_SIZE];
             snprintf(deliver, sizeof(deliver), "%s:%s:%s", CMD_DELIVER, a1, body);
             send_msg(recipient_fd, deliver);
         }
         send_msg(client_fd, CMD_ACK_OK);
     }
 
     /* ── INBOX ── INBOX:username ── */
     else if (strcmp(command, CMD_INBOX) == 0) {
         sscanf(cmd, "%*[^:]:%49[^\n]", a1);
         build_inbox_str(a1, response, sizeof(response));
         send_msg(client_fd, response);
     }
 
     /* ── HISTORY ── HISTORY:user_a:user_b ── */
     else if (strcmp(command, CMD_HISTORY) == 0) {
         send_msg(client_fd, CMD_ACK_OK);
     }
 
     /* ── RECENT ── RECENT:user_a:user_b — last 8 messages ── */
     else if (strcmp(command, CMD_RECENT) == 0) {
         sscanf(cmd, "%*[^:]:%49[^:]:%49[^\n]", a1, a2);
         build_recent_str(a1, a2, 8, response, sizeof(response));
         send_msg(client_fd, response);
     }
 
     /* ── SENDERS ── SENDERS:username ── */
     else if (strcmp(command, "SENDERS") == 0) {
         sscanf(cmd, "%*[^:]:%49[^\n]", a1);
         build_inbox_senders(a1, response, sizeof(response));
         send_msg(client_fd, response);
     }
 
     /* ── unknown command ── */
     else {
         snprintf(response, sizeof(response), "%s:unknown command", CMD_ACK_ERR);
         send_msg(client_fd, response);
     }
 }
 
 /* ============================================================
  * FUNCTION : client_session
  * ============================================================ */
 static void client_session(int client_fd) {
     char buf[BUFFER_SIZE];
     char session_user[MAX_NAME_LEN + 1] = "";
 
     while (1) {
         if (recv_msg(client_fd, buf, sizeof(buf)) < 0) break;
         handle_command(client_fd, buf, session_user);
     }
 
     if (session_user[0] != '\0') {
         logout_user(session_user);
         session_remove(session_user);
         printf("  [*] %s disconnected (session ended)\n", session_user);
     }
     close(client_fd);
 }
 
 /* ============================================================
  * FUNCTION : server_run
  * ============================================================ */
 void server_run(void) {
     int server_fd;
     struct sockaddr_in addr;
     int opt = 1;
 
     signal(SIGCHLD, SIG_IGN);
 
     /* load crypto key material */
     if (crypto_init() != 0) {
         fprintf(stderr, "  [!] cannot start without key file — run ./keygen first\n\n");
         return;
     }
 
     /* clear sessions file on startup */
     FILE *sf = fopen(SESSIONS_FILE, "w");
     if (sf) fclose(sf);
 
     server_fd = socket(AF_INET, SOCK_STREAM, 0);
     if (server_fd < 0) { perror("  [!] socket() failed"); return; }
 
     setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
 
     memset(&addr, 0, sizeof(addr));
     addr.sin_family      = AF_INET;
     addr.sin_port        = htons(SERVER_PORT);
     addr.sin_addr.s_addr = inet_addr(SERVER_IP);
 
     if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
         perror("  [!] bind() failed"); return;
     }
 
     if (listen(server_fd, BACKLOG) < 0) {
         perror("  [!] listen() failed"); return;
     }
 
     printf("  [*] server listening on %s:%d\n", SERVER_IP, SERVER_PORT);
     printf("  [*] end-to-end encryption active (AES-256 + SHA-256)\n");
     printf("  [*] waiting for clients — press Ctrl+C to stop\n\n");
 
     while (1) {
         struct sockaddr_in client_addr;
         socklen_t addr_len = sizeof(client_addr);
 
         int client_fd = accept(server_fd,
                                (struct sockaddr *)&client_addr,
                                &addr_len);
         if (client_fd < 0) { perror("  [!] accept() failed"); continue; }
 
         printf("  [+] client connected from %s (fd=%d)\n",
                inet_ntoa(client_addr.sin_addr), client_fd);
 
         pid_t pid = fork();
 
         if (pid == 0) {
             close(server_fd);
             client_session(client_fd);
             exit(0);
         } else if (pid > 0) {
             close(client_fd);
         } else {
             perror("  [!] fork() failed");
             close(client_fd);
         }
     }
 }