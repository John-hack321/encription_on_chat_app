/*
 * SCS3304 — One-on-One Chat Application
 * Client Module
 *
 * HOW THE CLIENT WORKS:
 *
 *   The client connects to the server via a TCP socket, then presents
 *   a menu. Every menu action sends a command string to the server and
 *   waits for a response. The server does the actual work (file I/O,
 *   user lookups) and sends back a result.
 *
 *   LIVE CHAT — select():
 *   During a chat session, we need to watch TWO things at once:
 *     1. The keyboard  — the user might type a message
 *     2. The socket    — the other user might send a message
 *
 *   We cannot use blocking read() on both — if we block on keyboard
 *   input, we'd miss incoming messages. If we block on the socket,
 *   the user can't type.
 *
 *   select() solves this. It watches a set of file descriptors and
 *   returns as soon as ANY of them has data ready. We watch stdin
 *   (fd=0) and the socket simultaneously. Whichever has data first
 *   gets processed. This is the concurrency mechanism on the client.
 */

 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <sys/socket.h>
 #include <sys/select.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 
 #include "client.h"
 #include "../common/protocol.h"
 #include "../common/utils.h"
 #include "../common/user_manager.h"
 #include "../common/message_handler.h"
 
 static int  sock_fd = -1;
 static char me[MAX_NAME_LEN + 1] = "";
 
 /* ── helpers ── */
 static void clear_screen(void)           { printf("\033[2J\033[H"); }
 static void print_error(const char *m)   { printf("  [!] %s\n", m); }
 static void print_success(const char *m) { printf("  [+] %s\n", m); }
 static void print_info(const char *m)    { printf("  [*] %s\n", m); }
 
 static void read_line(char *buf, int size) {
     if (fgets(buf, size, stdin)) buf[strcspn(buf, "\n")] = 0;
     else buf[0] = 0;
 }
 
 /* ── send command, receive response in one call ── */
 static int exchange(const char *cmd, char *resp, int resp_size) {
     if (send_msg(sock_fd, cmd) < 0)              return -1;
     if (recv_msg(sock_fd, resp, resp_size) < 0)  return -1;
     return 0;
 }
 
 /* ============================================================
  * FUNCTION : chat_loop
  * PURPOSE  : Live two-way chat session with another user.
  *
  *   Uses select() to monitor both stdin and the socket fd.
  *   Whichever becomes readable first gets processed:
  *     - stdin ready   → user typed something → send to server
  *     - socket ready  → incoming message      → display it
  *
  *   Type /quit to leave the chat and return to the main menu.
  * ============================================================ */
 static void chat_loop(const char *partner) {
     char input[MAX_BODY_LEN];
     char buf[BUFFER_SIZE];
     char cmd[BUFFER_SIZE];
     fd_set read_fds;
 
     clear_screen();
     printf("\n  ╔══════════════════════════════════════════╗\n");
     printf("  ║  chatting with: %-25s║\n", partner);
     printf("  ║  type /quit to leave                     ║\n");
     printf("  ╚══════════════════════════════════════════╝\n\n");
     printf("  you: ");
     fflush(stdout);
 
     while (1) {
         /*
          * Set up the fd_set — a set of file descriptors for select().
          * We must call FD_ZERO and FD_SET every loop because
          * select() modifies the set when it returns.
          */
         FD_ZERO(&read_fds);
         FD_SET(STDIN_FILENO, &read_fds);   /* fd 0 — keyboard */
         FD_SET(sock_fd,      &read_fds);   /* our socket       */
 
         /*
          * select() blocks until one of our fds has data.
          * max_fd must be the highest fd + 1.
          * NULL timeout means block forever until something arrives.
          */
         int max_fd = sock_fd + 1;
         if (select(max_fd, &read_fds, NULL, NULL, NULL) < 0) break;
 
         /* ── incoming message from server ── */
         if (FD_ISSET(sock_fd, &read_fds)) {
             if (recv_msg(sock_fd, buf, sizeof(buf)) < 0) {
                 print_error("lost connection to server.");
                 break;
             }
             /* DELIVER:from:body */
             if (strncmp(buf, CMD_DELIVER, strlen(CMD_DELIVER)) == 0) {
                 char from[50], body[MAX_BODY_LEN];
                 sscanf(buf, "%*[^:]:%49[^:]:%1023[^\n]", from, body);
                 /* move to new line, print message, reprint prompt */
                 printf("\r  \033[36m%-10s\033[0m: %s\n  you: ", from, body);
                 fflush(stdout);
             }
         }
 
         /* ── keyboard input from user ── */
         if (FD_ISSET(STDIN_FILENO, &read_fds)) {
             if (fgets(input, sizeof(input), stdin) == NULL) break;
             input[strcspn(input, "\n")] = 0;
 
             if (strlen(input) == 0) {
                 printf("  you: "); fflush(stdout);
                 continue;
             }
 
             /* /quit — leave chat */
             if (strcmp(input, "/quit") == 0) {
                 print_info("left the chat.");
                 break;
             }
 
             /* send message to server */
             snprintf(cmd, sizeof(cmd), "%s:%s:%s:%s", CMD_MSG, me, partner, input);
             char resp[BUFFER_SIZE];
             if (exchange(cmd, resp, sizeof(resp)) < 0) {
                 print_error("send failed.");
                 break;
             }
 
             /* echo own message in yellow */
             printf("  \033[33myou\033[0m: %s\n  you: ", input);
             fflush(stdout);
         }
     }
     printf("\n");
 }
 
 /* ============================================================
  * SCREEN : screen_register
  * ============================================================ */
 static void screen_register(void) {
     char username[MAX_NAME_LEN + 1], password[64], confirm[64];
     char cmd[BUFFER_SIZE], resp[BUFFER_SIZE];
 
     clear_screen();
     printf("\n  ╔══════════════════════════════════════════╗\n");
     printf("  ║  register new account                    ║\n");
     printf("  ╚══════════════════════════════════════════╝\n\n");
 
     printf("  username (no spaces)   : "); read_line(username, sizeof(username));
     printf("  password (min 4 chars) : "); read_line(password, sizeof(password));
     printf("  confirm password       : "); read_line(confirm,  sizeof(confirm));
 
     if (strcmp(password, confirm) != 0) { print_error("passwords do not match."); return; }
 
     snprintf(cmd, sizeof(cmd), "%s:%s:%s", CMD_REGISTER, username, password);
     if (exchange(cmd, resp, sizeof(resp)) < 0) { print_error("server error."); return; }
 
     if (strcmp(resp, CMD_ACK_OK) == 0)
         print_success("account created. you can now log in.");
     else
         print_error(resp + strlen(CMD_ACK_ERR) + 1);
 }
 
 /* ============================================================
  * SCREEN : screen_login
  * OUTPUT  : 1 on success, 0 on failure
  * ============================================================ */
 static int screen_login(void) {
     char username[MAX_NAME_LEN + 1], password[64];
     char cmd[BUFFER_SIZE], resp[BUFFER_SIZE];
 
     clear_screen();
     printf("\n  ╔══════════════════════════════════════════╗\n");
     printf("  ║  login                                   ║\n");
     printf("  ╚══════════════════════════════════════════╝\n\n");
 
     printf("  username : "); read_line(username, sizeof(username));
     printf("  password : "); read_line(password, sizeof(password));
 
     snprintf(cmd, sizeof(cmd), "%s:%s:%s", CMD_LOGIN, username, password);
     if (exchange(cmd, resp, sizeof(resp)) < 0) { print_error("server error."); return 0; }
 
     if (strcmp(resp, CMD_ACK_OK) == 0) {
         strncpy(me, username, MAX_NAME_LEN);
         printf("\n  welcome, %s!\n", me);
         return 1;
     }
 
     print_error(resp + strlen(CMD_ACK_ERR) + 1);
     return 0;
 }
 
 /* ============================================================
  * SCREEN : screen_start_chat
  * PURPOSE : List users, pick one, enter the chat loop
  * ============================================================ */
 static void screen_start_chat(void) {
     char resp[BUFFER_SIZE];
 
     /* ask server for user list */
     if (exchange(CMD_LIST, resp, sizeof(resp)) < 0) { print_error("server error."); return; }
 
     /* parse LIST_RESULT:name:status|name:status|... */
     if (strncmp(resp, CMD_LIST_RESULT, strlen(CMD_LIST_RESULT)) != 0) return;
 
     clear_screen();
     printf("\n  ╔══════════════════════════════════════════╗\n");
     printf("  ║  select a user to chat with              ║\n");
     printf("  ╚══════════════════════════════════════════╝\n");
 
     char *data = resp + strlen(CMD_LIST_RESULT) + 1;
     char  names[MAX_USERS][50];
     char  statuses[MAX_USERS][10];
     int   count = 0;
 
     /* split on | to get individual entries */
     char data_copy[BUFFER_SIZE];
     strncpy(data_copy, data, sizeof(data_copy));
     char *token = strtok(data_copy, "|");
 
     printf("\n  ┌────┬───────────────────┬──────────┐\n");
     printf("  │ #  │ username          │ status   │\n");
     printf("  ├────┼───────────────────┼──────────┤\n");
 
     while (token != NULL && count < MAX_USERS) {
         sscanf(token, "%49[^:]:%9s", names[count], statuses[count]);
         if (strcasecmp(names[count], me) != 0) {   /* skip ourselves */
             if (strcmp(statuses[count], STATUS_ONLINE) == 0)
                 printf("  │ %-2d │ %-17s │ \033[32m%-8s\033[0m │\n",
                        count + 1, names[count], statuses[count]);
             else
                 printf("  │ %-2d │ %-17s │ %-8s │\n",
                        count + 1, names[count], statuses[count]);
         }
         count++;
         token = strtok(NULL, "|");
     }
     printf("  └────┴───────────────────┴──────────┘\n");
 
     printf("\n  enter number (0 to cancel): ");
     int pick;
     if (scanf("%d", &pick) != 1) { while(getchar()!='\n'); return; }
     while (getchar() != '\n');
 
     if (pick < 1 || pick > count) return;
 
     char partner[50];
     strncpy(partner, names[pick - 1], sizeof(partner));
 
     if (strcasecmp(partner, me) == 0) { print_error("cannot chat with yourself."); return; }
 
     chat_loop(partner);
 }
 
 /* ============================================================
  * SCREEN : screen_inbox
  * ============================================================ */
 static void screen_inbox(void) {
     char cmd[BUFFER_SIZE], resp[BUFFER_SIZE];
     snprintf(cmd, sizeof(cmd), "%s:%s", CMD_INBOX, me);
     if (exchange(cmd, resp, sizeof(resp)) < 0) { print_error("server error."); return; }
 
     clear_screen();
     printf("\n  ╔══════════════════════════════════════════╗\n");
     printf("  ║  inbox for: %-29s║\n", me);
     printf("  ╚══════════════════════════════════════════╝\n");
 
     /* parse INBOX_RESULT:entry~~entry~~ */
     if (strncmp(resp, "INBOX_RESULT:", 13) != 0) { print_info("inbox empty."); return; }
 
     char *data = resp + 13;
     if (strlen(data) == 0) { print_info("no messages yet."); return; }
 
     /* split on ~~ delimiter */
     char *entry = strtok(data, "~~");
     int   count = 0;
     while (entry != NULL) {
         printf("  %s\n", entry);
         count++;
         entry = strtok(NULL, "~~");
     }
     if (count == 0) print_info("no messages yet.");
 }
 
 /* ============================================================
  * SCREEN : screen_search
  * ============================================================ */
 static void screen_search(void) {
     char target[MAX_NAME_LEN + 1], cmd[BUFFER_SIZE], resp[BUFFER_SIZE];
 
     clear_screen();
     printf("\n  ╔══════════════════════════════════════════╗\n");
     printf("  ║  search user                             ║\n");
     printf("  ╚══════════════════════════════════════════╝\n\n");
     printf("  username to search: "); read_line(target, sizeof(target));
 
     snprintf(cmd, sizeof(cmd), "%s:%s", CMD_SEARCH, target);
     if (exchange(cmd, resp, sizeof(resp)) < 0) { print_error("server error."); return; }
 
     if (strncmp(resp, "SEARCH_RESULT:", 14) == 0) {
         char *data = resp + 14;
         if (strcmp(data, "not_found") == 0) { print_error("user not found."); return; }
         char name[50], status[10];
         sscanf(data, "%49[^:]:%9s", name, status);
         printf("  ┌─────────────────────────────┐\n");
         printf("  │ username : %-16s│\n", name);
         printf("  │ status   : %-16s│\n", status);
         printf("  └─────────────────────────────┘\n");
     }
 }
 
 /* ============================================================
  * MENU : logged_in_menu
  * ============================================================ */
 static void logged_in_menu(void) {
     int choice;
     char cmd[BUFFER_SIZE], resp[BUFFER_SIZE];
 
     while (1) {
         clear_screen();
         printf("\n  ╔══════════════════════════════════════════╗\n");
         printf("  ║  logged in as: %-26s║\n", me);
         printf("  ╠══════════════════════════════════════════╣\n");
         printf("  ║  1.  start chat                          ║\n");
         printf("  ║  2.  view inbox                          ║\n");
         printf("  ║  3.  search user                         ║\n");
         printf("  ║  4.  list all users                      ║\n");
         printf("  ║  5.  logout                              ║\n");
         printf("  ║  6.  delete account                      ║\n");
         printf("  ╚══════════════════════════════════════════╝\n");
         printf("  choice: ");
 
         if (scanf("%d", &choice) != 1) { while(getchar()!='\n'); continue; }
         while (getchar() != '\n');
 
         switch (choice) {
             case 1: screen_start_chat(); break;
             case 2: screen_inbox();      break;
             case 3: screen_search();     break;
             case 4:
                 clear_screen();
                 if (exchange(CMD_LIST, resp, sizeof(resp)) == 0) {
                     /* parse and display */
                     char data_copy[BUFFER_SIZE];
                     strncpy(data_copy, resp + strlen(CMD_LIST_RESULT) + 1, sizeof(data_copy));
                     char names[MAX_USERS][50], statuses[MAX_USERS][10];
                     int  count = 0;
                     char *t = strtok(data_copy, "|");
                     printf("\n  ┌────┬───────────────────┬──────────┐\n");
                     printf("  │ #  │ username          │ status   │\n");
                     printf("  ├────┼───────────────────┼──────────┤\n");
                     while (t && count < MAX_USERS) {
                         sscanf(t, "%49[^:]:%9s", names[count], statuses[count]);
                         if (strcmp(statuses[count], STATUS_ONLINE) == 0)
                             printf("  │ %-2d │ %-17s │ \033[32m%-8s\033[0m │\n", count+1, names[count], statuses[count]);
                         else
                             printf("  │ %-2d │ %-17s │ %-8s │\n", count+1, names[count], statuses[count]);
                         count++; t = strtok(NULL, "|");
                     }
                     printf("  └────┴───────────────────┴──────────┘\n");
                 }
                 break;
             case 5:
                 snprintf(cmd, sizeof(cmd), "%s:%s", CMD_LOGOUT, me);
                 exchange(cmd, resp, sizeof(resp));
                 print_success("logged out.");
                 me[0] = '\0';
                 return;
             case 6: {
                 char confirm[8];
                 printf("  type YES to confirm account deletion: ");
                 read_line(confirm, sizeof(confirm));
                 if (strcmp(confirm, "YES") == 0) {
                     snprintf(cmd, sizeof(cmd), "%s:%s", CMD_DEREGISTER, me);
                     exchange(cmd, resp, sizeof(resp));
                     print_success("account deleted.");
                     me[0] = '\0';
                     return;
                 }
                 break;
             }
             default: print_error("invalid choice.");
         }
 
         printf("\n  press Enter to continue..."); getchar();
     }
 }
 
 /* ============================================================
  * FUNCTION : client_run
  * PURPOSE  : Connect to server and run the welcome menu
  * ============================================================ */
 void client_run(void) {
     struct sockaddr_in server_addr;
 
     /*
      * Create a TCP socket — this is just a file descriptor at this point,
      * not yet connected to anything.
      */
     sock_fd = socket(AF_INET, SOCK_STREAM, 0);
     if (sock_fd < 0) { perror("  [!] socket() failed"); exit(1); }
 
     memset(&server_addr, 0, sizeof(server_addr));
     server_addr.sin_family      = AF_INET;
     server_addr.sin_port        = htons(SERVER_PORT);
     server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
 
     /*
      * connect() reaches out to the server at 127.0.0.1:8080.
      * This triggers the server's accept() to return.
      * If the server isn't running yet, this will fail with
      * "Connection refused".
      */
     if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
         perror("  [!] connect() failed — is the server running?");
         exit(1);
     }
 
     print_info("connected to server.");
 
     /* welcome menu loop */
     int choice;
     while (1) {
         clear_screen();
         printf("\n  ╔══════════════════════════════════════════╗\n");
         printf("  ║      one-on-one chat  —  SCS3304         ║\n");
         printf("  ║      client-server / single machine      ║\n");
         printf("  ╠══════════════════════════════════════════╣\n");
         printf("  ║  1.  login                               ║\n");
         printf("  ║  2.  register new account                ║\n");
         printf("  ║  3.  exit                                ║\n");
         printf("  ╚══════════════════════════════════════════╝\n");
         printf("  choice: ");
 
         if (scanf("%d", &choice) != 1) { while(getchar()!='\n'); continue; }
         while (getchar() != '\n');
 
         if (choice == 1) {
             if (screen_login()) logged_in_menu();
             else { printf("\n  press Enter to try again..."); getchar(); }
         } else if (choice == 2) {
             screen_register();
             printf("\n  press Enter to continue..."); getchar();
         } else if (choice == 3) {
             printf("  goodbye.\n\n");
             close(sock_fd);
             exit(0);
         }
     }
 }