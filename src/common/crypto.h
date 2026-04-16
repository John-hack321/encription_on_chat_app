/*
 * SCS3304 — One-on-One Chat Application
 * Cryptography Module Header
 *
 * Implements diagram (d) from the Computing Security lesson:
 *
 *   SENDER:
 *     1. Concatenate message M with shared secret S:  M || S
 *     2. Hash the concatenation:                      H(M || S)
 *     3. Encrypt message + hash with key K:           E(K, [M || H(M || S)])
 *     4. Send the ciphertext
 *
 *   RECEIVER:
 *     1. Decrypt with key K:                          D(K, ciphertext) → M, H(M || S)
 *     2. Concatenate decrypted M with own copy of S:  M || S
 *     3. Hash it:                                     H(M || S)
 *     4. Compare computed hash with decrypted hash
 *     5. If equal → message is authentic and unaltered
 *
 * Provides: confidentiality (AES-256-CBC) + authentication + integrity (HMAC-SHA256)
 *
 * Libraries: OpenSSL (libssl, libcrypto)
 * Build:     link with -lssl -lcrypto
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

/* ── sizes ── */
#define AES_KEY_BYTES    32    /* 256-bit AES key                */
#define AES_IV_BYTES     16    /* 128-bit AES IV (CBC mode)      */
#define SHA256_BYTES     32    /* 256-bit SHA-256 hash output    */
#define SECRET_BYTES     32    /* 256-bit shared secret S        */
#define MAX_PLAIN_LEN   1024   /* max plaintext message length   */
#define MAX_CIPHER_LEN  1400   /* max ciphertext buffer size     */

/* key file path — both client and server must read the same file */
#define CRYPTO_KEY_FILE  "data/chat.key"

/*
 * crypto_init
 * Load the shared key K and secret S from CRYPTO_KEY_FILE.
 * Must be called once at startup before any encrypt/decrypt calls.
 * Returns 0 on success, -1 on failure.
 */
int crypto_init(void);

/*
 * crypto_encrypt
 * Implements sender side of diagram (d):
 *   plaintext  → [M || H(M || S)]  → E(K, [M || H(M || S)])
 *
 * Input:
 *   plaintext      — the message string to protect
 *   ciphertext     — output buffer for the encrypted bytes
 *   ciphertext_len — set to the number of bytes written
 *
 * Returns 0 on success, -1 on failure.
 */
int crypto_encrypt(const char *plaintext,
                   unsigned char *ciphertext,
                   int *ciphertext_len);

/*
 * crypto_decrypt
 * Implements receiver side of diagram (d):
 *   ciphertext → D(K, ...) → verify H(M || S) → plaintext
 *
 * Input:
 *   ciphertext     — the encrypted bytes received
 *   ciphertext_len — number of bytes in ciphertext
 *   plaintext      — output buffer for the recovered message
 *
 * Returns 0 if decryption AND authentication both succeed.
 * Returns -1 if decryption fails or hash mismatch (tampered message).
 */
int crypto_decrypt(const unsigned char *ciphertext,
                   int ciphertext_len,
                   char *plaintext);

/*
 * crypto_generate_keyfile
 * Generate a new random key K and secret S and write them to
 * CRYPTO_KEY_FILE. Run this ONCE on the server side, then copy
 * the file to the client. Never regenerate after deployment.
 *
 * Returns 0 on success, -1 on failure.
 */
int crypto_generate_keyfile(void);

/*
 * crypto_encode_b64 / crypto_decode_b64
 * Base-64 helpers so we can transmit binary ciphertext safely
 * over our existing text-based socket protocol without breaking
 * the framing or delimiter logic.
 *
 * encode: binary → printable ASCII string (null-terminated)
 * decode: ASCII string → binary bytes, sets *out_len
 */
void crypto_encode_b64(const unsigned char *in, int in_len,
                       char *out, int out_size);
int  crypto_decode_b64(const char *in,
                       unsigned char *out, int out_size);

#endif /* CRYPTO_H */