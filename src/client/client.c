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
#include "../common/crypto.h"

static int  sock_fd = -1;
static char me[MAX_NAME_LEN + 1] = "";

static void clear_screen(void)           { printf("\033[2J\033[H"); }
static void print_error(const char *m)   { printf("  [!] %s\n", m); }
static void print_success(const char *m) { printf("  [+] %s\n", m); }
static void print_info(const char *m)    { printf("  [*] %s\n", m); }

static void read_line(char *buf, int size) {
    if (fgets(buf, size, stdin)) buf[strcspn(buf, "\n")] = 0;
    else buf[0] = 0;
}

static int exchange(const char *cmd, char *resp, int resp_size) {
    if (send_msg(sock_fd, cmd) < 0)             return -1;
    if (recv_msg(sock_fd, resp, resp_size) < 0) return -1;
    return 0;
}

static int send_encrypted_msg(const char *cmd_str) {
    unsigned char ciphertext[MAX_CIPHER_LEN];
    int           cipher_len = 0;

    /* encrypt the full command string E(K, [cmd || H(cmd || S)]) */
    if (crypto_encrypt(cmd_str, ciphertext, &cipher_len) != 0) {
        print_error("encryption failed — message not sent.");
        return -1;
    }

    /* base64 encode so binary travels safely through text framing */
    char b64[MAX_CIPHER_LEN * 2];
    crypto_encode_b64(ciphertext, cipher_len, b64, sizeof(b64));

    /* build EMSG frame */
    char frame[BUFFER_SIZE];
    snprintf(frame, sizeof(frame), "EMSG:%s", b64);

    return send_msg(sock_fd, frame);
}


static void print_recent_messages(const char *partner) {
    char cmd[BUFFER_SIZE], resp[BUFFER_SIZE];
    snprintf(cmd, sizeof(cmd), "%s:%s:%s", CMD_RECENT, me, partner);

    if (exchange(cmd, resp, sizeof(resp)) < 0) return;
    if (strncmp(resp, "RECENT_RESULT:", 14) != 0) return;

    char *data = resp + 14;
    if (strlen(data) == 0) {
        print_info("no previous messages — start the conversation!");
        printf("\n");
        return;
    }

    printf("  ┌──────────────────────────────────────────────────────┐\n");
    printf("  │  last messages with %-32s│\n", partner);
    printf("  ├──────────────────────────────────────────────────────┤\n");

    char data_copy[BUFFER_SIZE];
    strncpy(data_copy, data, sizeof(data_copy) - 1);
    data_copy[sizeof(data_copy) - 1] = '\0';

    char *entry = strtok(data_copy, "~~");
    while (entry != NULL && strlen(entry) > 0) {
        char sender[50], body[MAX_BODY_LEN];
        if (sscanf(entry, "%49[^|]|%1023[^\n]", sender, body) == 2) {
            /* Check if body is encrypted and decrypt it */
            if (strncmp(body, "ENC:", 4) == 0) {
                const char *b64 = body + 4; /* skip "ENC:" */
                unsigned char cipher[MAX_CIPHER_LEN];
                int cipher_len = crypto_decode_b64(b64, cipher, sizeof(cipher));

                if (cipher_len > 0) {
                    char decrypted_cmd[BUFFER_SIZE];
                    if (crypto_decrypt(cipher, cipher_len, decrypted_cmd) == 0) {
                        /* Extract body from "MSG:from:to:body" */
                        sscanf(decrypted_cmd, "%*[^:]:%*[^:]:%*[^:]:%1023[^\n]", body);
                    }
                }
            }
            if (strcasecmp(sender, me) == 0)
                printf("  │  \033[33myou\033[0m: %s\n", body);
            else
                printf("  │  \033[36m%-10s\033[0m: %s\n", sender, body);
        }
        entry = strtok(NULL, "~~");
    }

    printf("  └──────────────────────────────────────────────────────┘\n");
    printf("  (continuing — type /quit to leave)\n\n");
}


static void chat_loop(const char *partner) {
    char input[MAX_BODY_LEN];
    char buf[BUFFER_SIZE];
    char cmd[BUFFER_SIZE];
    fd_set read_fds;

    int waiting_for_ack = 0;

    clear_screen();
    printf("\n  ╔══════════════════════════════════════════╗\n");
    printf("  ║  chat: %-15s  ↔  %-12s║\n", me, partner);
    printf("  ║  /quit to leave    [end-to-end encrypted] ║\n");
    printf("  ╚══════════════════════════════════════════╝\n\n");

    print_recent_messages(partner);

    printf("  you: ");
    fflush(stdout);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sock_fd,      &read_fds);

        if (select(sock_fd + 1, &read_fds, NULL, NULL, NULL) < 0) break;

        /* ── data arrived on the socket ── */
        if (FD_ISSET(sock_fd, &read_fds)) {
            if (recv_msg(sock_fd, buf, sizeof(buf)) < 0) {
                printf("\n");
                print_error("lost connection to server.");
                break;
            }

            if (waiting_for_ack) {
                /* silently discard ACK:OK from our last send */
                waiting_for_ack = 0;

            } else if (strncmp(buf, "EDELIVER:", 9) == 0) {
                /*
                 * Encrypted delivery from the server.
                 * Format:  EDELIVER:from:<base64(IV+cipher)>
                 * Decrypt, verify hash, then display.
                 */
                char from[50], b64[BUFFER_SIZE];
                sscanf(buf, "%*[^:]:%49[^:]:%2047[^\n]", from, b64);

                unsigned char cipher[MAX_CIPHER_LEN];
                int cipher_len = crypto_decode_b64(b64, cipher, sizeof(cipher));

                char decrypted_cmd[BUFFER_SIZE];
                if (cipher_len > 0 &&
                    crypto_decrypt(cipher, cipher_len, decrypted_cmd) == 0) {
                    /* decrypted_cmd is "MSG:from:to:body" — extract body */
                    char body[MAX_BODY_LEN] = {0};
                    sscanf(decrypted_cmd, "%*[^:]:%*[^:]:%*[^:]:%1023[^\n]", body);
                    printf("\r  \033[36m%-10s\033[0m: %s\n  you: ", from, body);
                } else {
                    printf("\r  \033[36m%-10s\033[0m: [decryption failed]\n  you: ", from);
                }
                fflush(stdout);

            } else if (strncmp(buf, CMD_DELIVER, strlen(CMD_DELIVER)) == 0) {
                /*
                 * Plaintext delivery (fallback — server did not re-encrypt).
                 * Kept for backward compatibility.
                 */
                char from[50], body[MAX_BODY_LEN];
                sscanf(buf, "%*[^:]:%49[^:]:%1023[^\n]", from, body);
                printf("\r  \033[36m%-10s\033[0m: %s\n  you: ", from, body);
                fflush(stdout);
            }
        }

        /* ── user typed something ── */
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(input, sizeof(input), stdin) == NULL) break;
            input[strcspn(input, "\n")] = 0;

            if (strlen(input) == 0) { printf("  you: "); fflush(stdout); continue; }

            if (strcmp(input, "/quit") == 0) { print_info("left the chat."); break; }

            /*
             * Build the protocol command string, then ENCRYPT it before
             * sending. The server will decrypt it, verify authenticity,
             * store the plaintext body, and forward an encrypted copy to
             * the recipient if they are online.
             */
            snprintf(cmd, sizeof(cmd), "%s:%s:%s:%s", CMD_MSG, me, partner, input);

            if (send_encrypted_msg(cmd) < 0) {
                print_error("send failed.");
                break;
            }
            waiting_for_ack = 1;

            /* echo our own message immediately */
            printf("  \033[33myou\033[0m: %s\n  you: ", input);
            fflush(stdout);
        }
    }
    printf("\n");
}


static void screen_inbox(void) {
    char cmd[BUFFER_SIZE], resp[BUFFER_SIZE];

    snprintf(cmd, sizeof(cmd), "SENDERS:%s", me);
    if (exchange(cmd, resp, sizeof(resp)) < 0) { print_error("server error."); return; }

    clear_screen();
    printf("\n  ╔══════════════════════════════════════════╗\n");
    printf("  ║  inbox — %-31s║\n", me);
    printf("  ║  select a conversation to open           ║\n");
    printf("  ╚══════════════════════════════════════════╝\n");

    if (strncmp(resp, "SENDERS_RESULT:", 15) != 0 || strlen(resp + 15) == 0) {
        printf("\n");
        print_info("inbox is empty — nobody has sent you a message yet.");
        printf("\n  press Enter to continue..."); getchar();
        return;
    }

    char *data = resp + 15;
    char  senders[50][50];
    int   count = 0;

    char data_copy[BUFFER_SIZE];
    strncpy(data_copy, data, sizeof(data_copy) - 1);
    char *token = strtok(data_copy, "|");

    printf("\n  ┌────┬─────────────────────────────────────┐\n");
    printf("  │ #  │ conversation with                   │\n");
    printf("  ├────┼─────────────────────────────────────┤\n");

    while (token != NULL && count < 50 && strlen(token) > 0) {
        strncpy(senders[count], token, 49);
        senders[count][49] = '\0';
        printf("  │ %-2d │ %-35s │\n", count + 1, senders[count]);
        count++;
        token = strtok(NULL, "|");
    }

    if (count == 0) {
        printf("  │  no conversations yet.                 │\n");
        printf("  └────┴─────────────────────────────────────┘\n");
        printf("\n  press Enter to continue..."); getchar();
        return;
    }

    printf("  └────┴─────────────────────────────────────┘\n");
    printf("\n  enter number to open (0 to cancel): ");

    int pick;
    if (scanf("%d", &pick) != 1) { while(getchar()!='\n'); return; }
    while (getchar() != '\n');

    if (pick < 1 || pick > count) return;

    chat_loop(senders[pick - 1]);
}


static void screen_start_chat(void) {
    char resp[BUFFER_SIZE];

    if (exchange(CMD_LIST, resp, sizeof(resp)) < 0) { print_error("server error."); return; }
    if (strncmp(resp, CMD_LIST_RESULT, strlen(CMD_LIST_RESULT)) != 0) return;

    clear_screen();
    printf("\n  ╔══════════════════════════════════════════╗\n");
    printf("  ║  start chat — pick a user                ║\n");
    printf("  ╚══════════════════════════════════════════╝\n");

    char *data = resp + strlen(CMD_LIST_RESULT) + 1;
    char  names[MAX_USERS][50], statuses[MAX_USERS][10];
    int   count = 0;

    char data_copy[BUFFER_SIZE];
    strncpy(data_copy, data, sizeof(data_copy) - 1);
    char *token = strtok(data_copy, "|");

    printf("\n  ┌────┬───────────────────┬──────────┐\n");
    printf("  │ #  │ username          │ status   │\n");
    printf("  ├────┼───────────────────┼──────────┤\n");

    while (token != NULL && count < MAX_USERS) {
        sscanf(token, "%49[^:]:%9s", names[count], statuses[count]);
        if (strcasecmp(names[count], me) != 0) {
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
    strncpy(partner, names[pick - 1], sizeof(partner) - 1);
    if (strcasecmp(partner, me) == 0) { print_error("cannot chat with yourself."); return; }

    chat_loop(partner);
}


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


static void logged_in_menu(void) {
    int choice;
    char cmd[BUFFER_SIZE], resp[BUFFER_SIZE];

    while (1) {
        clear_screen();
        printf("\n  ╔══════════════════════════════════════════╗\n");
        printf("  ║  logged in as: %-26s║\n", me);
        printf("  ╠══════════════════════════════════════════╣\n");
        printf("  ║  1.  inbox  (reply to messages)          ║\n");
        printf("  ║  2.  start new chat                      ║\n");
        printf("  ║  3.  search user                         ║\n");
        printf("  ║  4.  list all users                      ║\n");
        printf("  ║  5.  logout                              ║\n");
        printf("  ║  6.  delete account                      ║\n");
        printf("  ╚══════════════════════════════════════════╝\n");
        printf("  choice: ");

        if (scanf("%d", &choice) != 1) { while(getchar()!='\n'); continue; }
        while (getchar() != '\n');

        switch (choice) {
            case 1: screen_inbox();      break;
            case 2: screen_start_chat(); break;
            case 3: screen_search();     break;
            case 4:
                clear_screen();
                if (exchange(CMD_LIST, resp, sizeof(resp)) == 0) {
                    char dc[BUFFER_SIZE];
                    strncpy(dc, resp + strlen(CMD_LIST_RESULT) + 1, sizeof(dc) - 1);
                    char names[MAX_USERS][50], statuses[MAX_USERS][10];
                    int  n = 0;
                    char *t = strtok(dc, "|");
                    printf("\n  ┌────┬───────────────────┬──────────┐\n");
                    printf("  │ #  │ username          │ status   │\n");
                    printf("  ├────┼───────────────────┼──────────┤\n");
                    while (t && n < MAX_USERS) {
                        sscanf(t, "%49[^:]:%9s", names[n], statuses[n]);
                        if (strcmp(statuses[n], STATUS_ONLINE) == 0)
                            printf("  │ %-2d │ %-17s │ \033[32m%-8s\033[0m │\n", n+1, names[n], statuses[n]);
                        else
                            printf("  │ %-2d │ %-17s │ %-8s │\n", n+1, names[n], statuses[n]);
                        n++; t = strtok(NULL, "|");
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
                printf("  type YES to confirm: ");
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


void client_run(void) {
    struct sockaddr_in server_addr;

    /* load crypto key material before connecting */
    if (crypto_init() != 0) {
        printf("  [!] cannot start without key file — run ./keygen first\n\n");
        return;
    }

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("  [!] socket() failed"); return; }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("  [!] connect() failed — is the server running?");
        return;
    }

    print_info("connected to server (end-to-end encryption active).");

    int choice;
    while (1) {
        clear_screen();
        printf("\n  ╔══════════════════════════════════════════╗\n");
        printf("  ║      one-on-one chat  —  SCS3304         ║\n");
        printf("  ║      client-server / encrypted           ║\n");
        printf("  ╠══════════════════════════════════════════╣\n");
        printf("  ║  1.  login                               ║\n");
        printf("  ║  2.  register new account                ║\n");
        printf("  ║  3.  exit                                ║\n");
        printf("  ╚══════════════════════════════════════════╝\n");
        printf("  choice: ");

        if (scanf("%d", &choice) != 1) { while(getchar()!='\n'); continue; }
        while (getchar() != '\n');

        if      (choice == 1) { if (screen_login()) logged_in_menu(); else { printf("\n  press Enter to try again..."); getchar(); } }
        else if (choice == 2) { screen_register(); printf("\n  press Enter to continue..."); getchar(); }
        else if (choice == 3) { printf("  goodbye.\n\n"); close(sock_fd); return; }
    }
}