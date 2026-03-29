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
 *   CONNECTED CLIENTS TABLE:
 *   The server maintains a shared table of online clients and their
 *   socket file descriptors. This enables real-time message delivery
 *   — when client A sends a message to client B, the server looks up
 *   B's socket fd and delivers the message instantly if B is online.
 *
 *   Because the table is shared between processes (via a memory-mapped
 *   file approach — we use a simple flat file here for clarity), we
 *   protect it with flock as well.
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
 
     /*
      * Extract the command word — everything before the first colon.
      * e.g.  "LOGIN:alice:pass"  →  command = "LOGIN"
      */
     sscanf(cmd, "%15[^:]", command);
 
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
 
     /* ── SEND MESSAGE ── MSG:from:to:body ── */
     else if (strcmp(command, CMD_MSG) == 0) {
         /*
          * Parse: skip "MSG:", read from, to, then everything
          * remaining is the body (it may contain colons).
          */
         sscanf(cmd, "%*[^:]:%49[^:]:%49[^:]:%1023[^\n]", a1, a2, body);
 
         /* store to file */
         int r = store_message(a1, a2, body);
         if (r != SUCCESS) {
             snprintf(response, sizeof(response), "%s:recipient not found", CMD_ACK_ERR);
             send_msg(client_fd, response);
             return;
         }
 
         /*
          * Real-time delivery: look up recipient's socket fd.
          * Only deliver to the RECIPIENT (a2), never back to the
          * sender (a1/client_fd) — the sender already echoed their
          * own message locally so delivering it again causes duplicates.
          */
         int recipient_fd = session_find_fd(a2);
         if (recipient_fd > 0 && recipient_fd != client_fd) {
             char deliver[BUFFER_SIZE];
             snprintf(deliver, sizeof(deliver), "%s:%s:%s", CMD_DELIVER, a1, body);
             send_msg(recipient_fd, deliver);
         }
 
         /*
          * Send ACK:OK back to the sender so the client knows the
          * message was stored. We use a silent ACK that the chat loop
          * will receive and discard — it does NOT print anything.
          */
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
         /* history is displayed on client side using shared files */
         send_msg(client_fd, CMD_ACK_OK);
     }
 
     /* ── RECENT ── RECENT:user_a:user_b — last 8 messages between them ── */
     else if (strcmp(command, CMD_RECENT) == 0) {
         sscanf(cmd, "%*[^:]:%49[^:]:%49[^\n]", a1, a2);
         build_recent_str(a1, a2, 8, response, sizeof(response));
         send_msg(client_fd, response);
     }
 
     /* ── SENDERS ── SENDERS:username — who has messaged this user ── */
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
  * PURPOSE  : Handle one connected client until they disconnect.
  *            Runs in a child process created by fork().
  * INPUT    : client_fd — socket for this client
  * ============================================================ */
 static void client_session(int client_fd) {
     char buf[BUFFER_SIZE];
     char session_user[MAX_NAME_LEN + 1] = "";   /* empty = not logged in */
 
     while (1) {
         /*
          * recv_msg blocks until a complete message arrives.
          * Returns -1 when the client closes the connection.
          */
         if (recv_msg(client_fd, buf, sizeof(buf)) < 0) break;
         handle_command(client_fd, buf, session_user);
     }
 
     /* clean up when client disconnects unexpectedly */
     if (session_user[0] != '\0') {
         logout_user(session_user);
         session_remove(session_user);
         printf("  [*] %s disconnected (session ended)\n", session_user);
     }
     close(client_fd);
 }
 
 /* ============================================================
  * FUNCTION : server_run
  * PURPOSE  : Main server loop — bind, listen, accept, fork
  * ============================================================ */
 void server_run(void) {
     int server_fd;
     struct sockaddr_in addr;
     int opt = 1;
 
     /*
      * SIGCHLD: when a child process (forked per client) finishes,
      * the OS sends SIGCHLD to the parent. Setting it to SIG_IGN
      * tells the OS to automatically clean up zombie processes
      * without us needing to call wait() manually.
      */
     signal(SIGCHLD, SIG_IGN);
 
     /* clear sessions file on startup */
     FILE *sf = fopen(SESSIONS_FILE, "w");
     if (sf) fclose(sf);
 
     /* ── step 1: create the TCP socket ── */
     server_fd = socket(AF_INET,     /* IPv4                  */
                        SOCK_STREAM, /* TCP (reliable stream) */
                        0);          /* protocol auto-select  */
     if (server_fd < 0) { perror("  [!] socket() failed"); exit(1); }
 
     /*
      * SO_REUSEADDR: if the server crashes and restarts, the port
      * may still be marked "in use" by the OS for a short time.
      * This option lets us bind again immediately.
      */
     setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
 
     /* ── step 2: bind to 127.0.0.1:8080 ── */
     memset(&addr, 0, sizeof(addr));
     addr.sin_family      = AF_INET;
     addr.sin_port        = htons(SERVER_PORT);
     addr.sin_addr.s_addr = inet_addr(SERVER_IP);
 
     if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
         perror("  [!] bind() failed");
         exit(1);
     }
 
     /* ── step 3: listen — mark socket as passive/accepting ── */
     if (listen(server_fd, BACKLOG) < 0) {
         perror("  [!] listen() failed");
         exit(1);
     }
 
     printf("  [*] server listening on %s:%d\n", SERVER_IP, SERVER_PORT);
     printf("  [*] waiting for clients — press Ctrl+C to stop\n\n");
 
     /* ── step 4: accept loop ── */
     while (1) {
         struct sockaddr_in client_addr;
         socklen_t addr_len = sizeof(client_addr);
 
         /*
          * accept() BLOCKS here — the process sleeps until a client
          * connects. When one does, it returns a new socket fd
          * dedicated to that client. The original server_fd stays
          * open and keeps listening.
          */
         int client_fd = accept(server_fd,
                                (struct sockaddr *)&client_addr,
                                &addr_len);
         if (client_fd < 0) { perror("  [!] accept() failed"); continue; }
 
         printf("  [+] client connected from %s (fd=%d)\n",
                inet_ntoa(client_addr.sin_addr), client_fd);
 
         /*
          * fork() — create a child process.
          *
          * After fork():
          *   pid == 0  → we are in the CHILD  process
          *   pid >  0  → we are in the PARENT process
          *   pid <  0  → fork failed (error)
          *
          * The child handles this client then exits.
          * The parent closes the client fd and loops back to accept().
          */
         pid_t pid = fork();
 
         if (pid == 0) {
             /* ── CHILD: handle client ── */
             close(server_fd);       /* child doesn't need the listening socket */
             client_session(client_fd);
             exit(0);
 
         } else if (pid > 0) {
             /* ── PARENT: go back to accepting ── */
             close(client_fd);       /* parent doesn't need this client's socket */
 
         } else {
             perror("  [!] fork() failed");
             close(client_fd);
         }
     }
 }