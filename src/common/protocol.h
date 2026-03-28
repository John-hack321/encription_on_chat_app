/*
 * SCS3304 — One-on-One Chat Application
 * Client-Server Model — Single Machine
 * Protocol Header
 *
 * This file defines every constant shared between the client and server.
 * Think of it as the rulebook both sides agree on before talking.
 *
 * MESSAGE FORMAT (layer 5 — application protocol):
 *   Every message sent over the socket looks like:
 *   [4-byte length][COMMAND:arg1:arg2:...]
 *
 *   The 4-byte length header solves the TCP framing problem —
 *   TCP is a stream, not a message system, so without a length
 *   prefix the receiver doesn't know where one message ends.
 */

 #ifndef PROTOCOL_H
 #define PROTOCOL_H
 
 /* ── network settings ── */
 #define SERVER_IP       "127.0.0.1"   /* localhost — same machine */
 #define SERVER_PORT     8080
 #define BACKLOG         10            /* max queued connections   */
 #define BUFFER_SIZE     2048
 
 /* ── client → server commands ── */
 #define CMD_REGISTER    "REG"         /* REG:username:password            */
 #define CMD_LOGIN       "LOGIN"       /* LOGIN:username:password          */
 #define CMD_LOGOUT      "LOGOUT"      /* LOGOUT:username                  */
 #define CMD_DEREGISTER  "DEREG"       /* DEREG:username                   */
 #define CMD_LIST        "LIST"        /* LIST                             */
 #define CMD_SEARCH      "SEARCH"      /* SEARCH:username                  */
 #define CMD_MSG         "MSG"         /* MSG:from:to:body                 */
 #define CMD_INBOX       "INBOX"       /* INBOX:username                   */
 #define CMD_HISTORY     "HISTORY"     /* HISTORY:user_a:user_b            */
 #define CMD_RECENT      "RECENT"      /* RECENT:user_a:user_b — last 8 msgs */
 
 /* ── server → client responses ── */
 #define CMD_ACK_OK      "ACK:OK"
 #define CMD_ACK_ERR     "ACK:ERR"     /* ACK:ERR:reason                   */
 #define CMD_DELIVER     "DELIVER"     /* DELIVER:from:body                */
 #define CMD_LIST_RESULT "LIST_RESULT" /* LIST_RESULT:name:status|...      */
 
 #endif