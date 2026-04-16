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