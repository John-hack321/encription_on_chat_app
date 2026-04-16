/*
 * SCS3304 — One-on-One Chat Application
 * Key Generation Utility
 *
 * Run ONCE to create data/chat.key before starting the server or client.
 * The same key file must be present on both sides (client and server).
 *
 * Usage:
 *   ./keygen
 *
 * Output:
 *   data/chat.key  — contains AES-256 key K and shared secret S (hex)
 *
 * After running:
 *   ./server    (reads data/chat.key automatically)
 *   ./client    (reads data/chat.key automatically)
 */

#include <stdio.h>
#include "common/crypto.h"

int main(void) {
    printf("\n  ╔══════════════════════════════════════════╗\n");
    printf("  ║   chat key generator  —  SCS3304         ║\n");
    printf("  ║   generates AES-256 key + shared secret  ║\n");
    printf("  ╚══════════════════════════════════════════╝\n\n");

    printf("  [*] generating 256-bit AES key (K) ...\n");
    printf("  [*] generating 256-bit shared secret (S) ...\n\n");

    if (crypto_generate_keyfile() != 0) {
        printf("  [!] key generation failed.\n\n");
        return 1;
    }

    printf("\n  [*] both client and server must have this file\n");
    printf("  [*] never regenerate the key while users are chatting\n");
    printf("  [*] keep data/chat.key secret — it protects all messages\n\n");
    return 0;
}