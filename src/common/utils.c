/*
 * SCS3304 — One-on-One Chat Application
 * Network Utility Functions
 *
 * WHY FRAMING EXISTS:
 *   TCP does not preserve message boundaries. If you send "hello"
 *   followed by "world", the receiver might get "helloworld" in one
 *   recv() call, or "hel" then "loworld" in two calls. This makes it
 *   impossible to know where one message ends.
 *
 *   The fix: prepend every message with its length as a 4-byte integer.
 *   The receiver reads 4 bytes first to learn the length, then reads
 *   exactly that many bytes. One complete message, every time.
 *
 * BYTE ORDER:
 *   Different CPUs store multi-byte integers differently (big-endian
 *   vs little-endian). htonl() converts our integer to "network byte
 *   order" (big-endian) before sending. ntohl() converts it back on
 *   the receiving end. This ensures both sides agree on the value.
 */

 #include <stdio.h>
 #include <string.h>
 #include <stdint.h>
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include "utils.h"
 
 /* ============================================================
  * FUNCTION : send_msg
  * PURPOSE  : Send one complete framed message over a socket
  * INPUT    : fd  — socket file descriptor to write to
  *            msg — null-terminated string to send
  * OUTPUT   : 0 on success, -1 on failure
  * STEPS    : 1. Measure message length
  *            2. Convert length to network byte order
  *            3. Send the 4-byte length header
  *            4. Send the message body
  * ============================================================ */
 int send_msg(int fd, const char *msg) {
     uint32_t len     = (uint32_t)strlen(msg);
     uint32_t net_len = htonl(len);          /* host → network byte order */
 
     /* send length header first */
     if (send(fd, &net_len, sizeof(net_len), 0) != sizeof(net_len))
         return -1;
 
     /* send message body */
     if (send(fd, msg, len, 0) != (ssize_t)len)
         return -1;
 
     return 0;
 }
 
 /* ============================================================
  * FUNCTION : recv_msg
  * PURPOSE  : Receive one complete framed message from a socket
  * INPUT    : fd       — socket file descriptor to read from
  *            buf      — buffer to write the message into
  *            buf_size — size of the buffer (prevents overflow)
  * OUTPUT   : 0 on success, -1 on failure or closed connection
  * STEPS    : 1. Read exactly 4 bytes → that is the message length
  *            2. Clamp length to buffer size for safety
  *            3. Read exactly that many bytes into buf
  *            4. Null-terminate so buf is a valid C string
  * ============================================================ */
 int recv_msg(int fd, char *buf, int buf_size) {
     uint32_t net_len;
 
     /*
      * MSG_WAITALL tells the OS: don't return until you have
      * exactly sizeof(net_len) bytes. Without this, recv()
      * might return fewer bytes and we'd misread the length.
      */
     if (recv(fd, &net_len, sizeof(net_len), MSG_WAITALL) <= 0)
         return -1;
 
     uint32_t len = ntohl(net_len);          /* network → host byte order */
 
     /* safety: never write more than the buffer can hold */
     if ((int)len >= buf_size)
         len = (uint32_t)(buf_size - 1);
 
     if (recv(fd, buf, len, MSG_WAITALL) <= 0)
         return -1;
 
     buf[len] = '\0';                        /* null-terminate */
     return 0;
 }