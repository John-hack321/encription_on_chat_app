/*
 * SCS3304 — One-on-One Chat Application
 * Client Entry Point
 *
 * Run: ./client
 *
 * Make sure the server is already running before starting the client.
 */

 #include <stdio.h>
 #include "client/client.h"
 
 int main(void) {
     printf("\n  ╔══════════════════════════════════════════╗\n");
     printf("  ║   one-on-one chat  —  client             ║\n");
     printf("  ║   SCS3304 / client-server model          ║\n");
     printf("  ╚══════════════════════════════════════════╝\n\n");
     client_run();
     return 0;
 }