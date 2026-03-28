/*
 * SCS3304 — One-on-One Chat Application
 * Message Handler Module — Client-Server Version
 *
 * flock() is used on every file write for the same reason as in
 * user_manager.c — multiple clients may send messages simultaneously
 * and we must prevent concurrent writes from corrupting the files.
 */

 #include <stdio.h>
 #include <string.h>
 #include <time.h>
 #include <sys/file.h>
 #include "message_handler.h"
 #include "user_manager.h"
 
 static void now(char *buf, int size) {
     time_t t = time(NULL);
     struct tm *tm_info = localtime(&t);
     strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
 }
 
 /* ============================================================
  * FUNCTION : store_message
  * PURPOSE  : Persist a message to messages.txt and chat_log.txt
  * OUTPUT   : SUCCESS or ERR_NOT_FOUND if recipient missing
  * ============================================================ */
 int store_message(const char *from, const char *to, const char *body) {
     if (!user_exists(to)) return ERR_NOT_FOUND;
 
     char timestamp[24];
     now(timestamp, sizeof(timestamp));
 
     /* write to messages.txt — lock while writing */
     FILE *fp = fopen(MESSAGES_FILE, "a");
     if (fp != NULL) {
         flock(fileno(fp), LOCK_EX);
         fprintf(fp, "%s|%s|%s|%s\n", timestamp, from, to, body);
         flock(fileno(fp), LOCK_UN);
         fclose(fp);
     }
 
     /* write to chat_log.txt — separate lock */
     fp = fopen(LOG_FILE, "a");
     if (fp != NULL) {
         flock(fileno(fp), LOCK_EX);
         fprintf(fp, "[%s] %s -> %s : %s\n", timestamp, from, to, body);
         flock(fileno(fp), LOCK_UN);
         fclose(fp);
     }
 
     return SUCCESS;
 }
 
 /* ============================================================
  * FUNCTION : show_inbox
  * PURPOSE  : Print all messages addressed to username (terminal)
  * ============================================================ */
 void show_inbox(const char *username) {
     FILE *fp = fopen(MESSAGES_FILE, "r");
     if (fp == NULL) { printf("  [*] inbox is empty.\n"); return; }
 
     flock(fileno(fp), LOCK_SH);
 
     char line[MAX_BODY_LEN + 128];
     char ts[24], from[50], to[50], body[MAX_BODY_LEN];
     int  count = 0;
 
     printf("\n  ┌──────────────────────────────────────────────────────┐\n");
     printf("  │  inbox for: %-40s│\n", username);
     printf("  ├──────────────────────────────────────────────────────┤\n");
 
     while (fgets(line, sizeof(line), fp) != NULL) {
         if (sscanf(line, "%23[^|]|%49[^|]|%49[^|]|%1023[^\n]",
                    ts, from, to, body) == 4) {
             if (strcasecmp(to, username) == 0) {
                 printf("  │ from: %-15s   at %s\n", from, ts);
                 printf("  │   %s\n", body);
                 printf("  ├──────────────────────────────────────────────────────┤\n");
                 count++;
             }
         }
     }
     if (count == 0)
         printf("  │  no messages yet.                                    │\n");
     printf("  │  %d message(s)                                        \n", count);
     printf("  └──────────────────────────────────────────────────────┘\n");
 
     flock(fileno(fp), LOCK_UN);
     fclose(fp);
 }
 
 /* ============================================================
  * FUNCTION : show_history
  * PURPOSE  : Print message thread between two users (terminal)
  * ============================================================ */
 void show_history(const char *user_a, const char *user_b) {
     FILE *fp = fopen(MESSAGES_FILE, "r");
     if (fp == NULL) { printf("  [*] no history yet.\n"); return; }
 
     flock(fileno(fp), LOCK_SH);
 
     char line[MAX_BODY_LEN + 128];
     char ts[24], from[50], to[50], body[MAX_BODY_LEN];
     int  count = 0;
 
     printf("\n  ┌──────────────────────────────────────────────────────┐\n");
     printf("  │  %s  ↔  %-38s│\n", user_a, user_b);
     printf("  ├──────────────────────────────────────────────────────┤\n");
 
     while (fgets(line, sizeof(line), fp) != NULL) {
         if (sscanf(line, "%23[^|]|%49[^|]|%49[^|]|%1023[^\n]",
                    ts, from, to, body) == 4) {
             int a_b = strcasecmp(from,user_a)==0 && strcasecmp(to,user_b)==0;
             int b_a = strcasecmp(from,user_b)==0 && strcasecmp(to,user_a)==0;
             if (a_b || b_a) {
                 printf("  │ [%s] %s:\n  │   %s\n  │\n", ts, from, body);
                 count++;
             }
         }
     }
     if (count == 0)
         printf("  │  no messages exchanged yet.\n");
     printf("  └──────────────────────────────────────────────────────┘\n");
 
     flock(fileno(fp), LOCK_UN);
     fclose(fp);
 }
 
 /* ============================================================
  * FUNCTION : build_inbox_str
  * PURPOSE  : Build inbox as a single string to send over socket
  *            Each message separated by  ~~  as delimiter
  * ============================================================ */
 void build_inbox_str(const char *username, char *buf, int buf_size) {
     FILE *fp = fopen(MESSAGES_FILE, "r");
     snprintf(buf, buf_size, "INBOX_RESULT:");
     if (fp == NULL) return;
 
     flock(fileno(fp), LOCK_SH);
 
     char line[MAX_BODY_LEN + 128];
     char ts[24], from[50], to[50], body[MAX_BODY_LEN];
 
     while (fgets(line, sizeof(line), fp) != NULL) {
         if (sscanf(line, "%23[^|]|%49[^|]|%49[^|]|%1023[^\n]",
                    ts, from, to, body) == 4) {
             if (strcasecmp(to, username) == 0) {
                 char entry[MAX_BODY_LEN + 128];
                 snprintf(entry, sizeof(entry), "[%s] %s: %s~~", ts, from, body);
                 strncat(buf, entry, buf_size - strlen(buf) - 1);
             }
         }
     }
 
     flock(fileno(fp), LOCK_UN);
     fclose(fp);
 }