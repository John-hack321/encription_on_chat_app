/*
 * SCS3304 — One-on-One Chat Application
 * Cryptography Module Implementation
 *
 * Implements diagram (d) from Computing Security Lesson 6:
 *
 *   Sender:   E(K, [M || H(M || S)])
 *   Receiver: D(K, cipher) → verify H(M || S)
 *
 * Algorithm choices:
 *   Encryption : AES-256-CBC  (symmetric, same K on both sides)
 *   Hash       : SHA-256      (applied to M || S)
 *   Key size   : 256-bit key + 256-bit secret, stored in data/chat.key
 *   IV         : Random 16-byte IV prepended to ciphertext each message
 *                (so identical messages produce different ciphertext)
 *
 * Wire format (what goes on the socket after base64):
 *   [ 16 bytes IV ][ N bytes AES-CBC ciphertext ]
 *
 * Plaintext block that AES encrypts:
 *   [ message bytes ][ 0x00 separator ][ 32 bytes SHA-256(M || S) ]
 *
 * Compile: gcc ... -lssl -lcrypto
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #include <openssl/evp.h>
 #include <openssl/rand.h>
 #include <openssl/bio.h>
 #include <openssl/buffer.h>
 #include <openssl/err.h>
 
 #include "crypto.h"
 
 /* ── module-level key material (loaded once by crypto_init) ── */
 static unsigned char g_key[AES_KEY_BYTES];    /* K — AES-256 key   */
 static unsigned char g_secret[SECRET_BYTES];  /* S — shared secret */
 static int           g_initialized = 0;
 
 /* ── internal: print OpenSSL errors to stderr ── */
 static void ssl_error(const char *ctx) {
     fprintf(stderr, "  [!] crypto: %s failed — ", ctx);
     ERR_print_errors_fp(stderr);
 }
 
 /* ============================================================
  * FUNCTION : crypto_generate_keyfile
  * PURPOSE  : Create data/chat.key with random K and S.
  *            Run ONCE, then distribute to both client and server.
  * FORMAT   : 32 bytes key (hex) newline 32 bytes secret (hex) newline
  * ============================================================ */
 int crypto_generate_keyfile(void) {
     unsigned char key[AES_KEY_BYTES];
     unsigned char secret[SECRET_BYTES];
 
     if (RAND_bytes(key, sizeof(key)) != 1 ||
         RAND_bytes(secret, sizeof(secret)) != 1) {
         ssl_error("RAND_bytes");
         return -1;
     }
 
     FILE *fp = fopen(CRYPTO_KEY_FILE, "w");
     if (fp == NULL) {
         perror("  [!] crypto: cannot create key file");
         return -1;
     }
 
     /* write key as hex */
     for (int i = 0; i < AES_KEY_BYTES; i++) fprintf(fp, "%02x", key[i]);
     fprintf(fp, "\n");
 
     /* write secret as hex */
     for (int i = 0; i < SECRET_BYTES; i++) fprintf(fp, "%02x", secret[i]);
     fprintf(fp, "\n");
 
     fclose(fp);
     printf("  [+] crypto: key file generated at %s\n", CRYPTO_KEY_FILE);
     return 0;
 }
 
 /* ── internal: parse one hex string into bytes ── */
 static int hex_to_bytes(const char *hex, unsigned char *out, int expected_len) {
     for (int i = 0; i < expected_len; i++) {
         unsigned int byte;
         if (sscanf(hex + 2 * i, "%02x", &byte) != 1) return -1;
         out[i] = (unsigned char)byte;
     }
     return 0;
 }
 
 /* ============================================================
  * FUNCTION : crypto_init
  * PURPOSE  : Load K and S from CRYPTO_KEY_FILE into module globals.
  * ============================================================ */
 int crypto_init(void) {
     FILE *fp = fopen(CRYPTO_KEY_FILE, "r");
     if (fp == NULL) {
         fprintf(stderr, "  [!] crypto: key file not found: %s\n"
                         "  [!]   run keygen first:  ./keygen\n",
                         CRYPTO_KEY_FILE);
         return -1;
     }
 
     char key_hex[AES_KEY_BYTES * 2 + 2];
     char secret_hex[SECRET_BYTES * 2 + 2];
 
     if (fgets(key_hex,    sizeof(key_hex),    fp) == NULL ||
         fgets(secret_hex, sizeof(secret_hex), fp) == NULL) {
         fprintf(stderr, "  [!] crypto: key file is malformed\n");
         fclose(fp);
         return -1;
     }
     fclose(fp);
 
     /* strip trailing newline */
     key_hex[strcspn(key_hex, "\n")]       = '\0';
     secret_hex[strcspn(secret_hex, "\n")] = '\0';
 
     if (hex_to_bytes(key_hex,    g_key,    AES_KEY_BYTES) != 0 ||
         hex_to_bytes(secret_hex, g_secret, SECRET_BYTES)  != 0) {
         fprintf(stderr, "  [!] crypto: failed to parse key file\n");
         return -1;
     }
 
     g_initialized = 1;
     printf("  [+] crypto: key material loaded from %s\n", CRYPTO_KEY_FILE);
     return 0;
 }
 
 /* ============================================================
  * FUNCTION : compute_hmac
  * PURPOSE  : Compute SHA-256( M || S ) — the hash in diagram (d)
  *
  * We concatenate the message bytes and the secret bytes in a
  * single buffer, then pass that to SHA-256. This is the H(M||S)
  * step from the diagram.
  *
  * Output: 32 bytes written to `hash_out`
  * ============================================================ */
 static int compute_hmac(const char *message, unsigned char *hash_out) {
     /* build  M || S  in one contiguous buffer */
     size_t msg_len    = strlen(message);
     size_t total      = msg_len + SECRET_BYTES;
     unsigned char *ms = (unsigned char *)malloc(total);
     if (ms == NULL) return -1;
 
     memcpy(ms,           message,  msg_len);
     memcpy(ms + msg_len, g_secret, SECRET_BYTES);
 
     /* SHA-256 hash */
     unsigned int out_len = 0;
     EVP_MD_CTX *ctx = EVP_MD_CTX_new();
     if (ctx == NULL) { free(ms); return -1; }
 
     int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
              EVP_DigestUpdate(ctx, ms, total)            &&
              EVP_DigestFinal_ex(ctx, hash_out, &out_len);
 
     EVP_MD_CTX_free(ctx);
     free(ms);
     return ok ? 0 : -1;
 }
 
 /* ============================================================
  * FUNCTION : crypto_encrypt
  * PURPOSE  : Sender side of diagram (d)
  *
  *   Step 1: compute hash = H(M || S)            — SHA-256
  *   Step 2: build plaintext block = M + '\0' + hash
  *   Step 3: generate random IV
  *   Step 4: AES-256-CBC encrypt the block
  *   Step 5: output = IV + ciphertext
  * ============================================================ */
 int crypto_encrypt(const char *plaintext,
                    unsigned char *ciphertext,
                    int *ciphertext_len) {
     if (!g_initialized) { fprintf(stderr, "  [!] crypto not initialised\n"); return -1; }
 
     /* ── Step 1: H(M || S) ── */
     unsigned char hash[SHA256_BYTES];
     if (compute_hmac(plaintext, hash) != 0) { ssl_error("compute_hmac"); return -1; }
 
     /* ── Step 2: build block = M + \0 + H(M||S) ── */
     size_t msg_len   = strlen(plaintext);
     size_t block_len = msg_len + 1 + SHA256_BYTES;   /* +1 for the '\0' separator */
 
     unsigned char *block = (unsigned char *)malloc(block_len);
     if (block == NULL) return -1;
 
     memcpy(block,               plaintext, msg_len);
     block[msg_len] = '\0';                           /* separator */
     memcpy(block + msg_len + 1, hash,      SHA256_BYTES);
 
     /* ── Step 3: random IV ── */
     unsigned char iv[AES_IV_BYTES];
     if (RAND_bytes(iv, sizeof(iv)) != 1) {
         ssl_error("RAND_bytes IV"); free(block); return -1;
     }
 
     /* ── Step 4: AES-256-CBC encrypt ── */
     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
     if (ctx == NULL) { free(block); return -1; }
 
     int len = 0, total_len = 0;
     unsigned char *cipher_body = ciphertext + AES_IV_BYTES;   /* leave room for IV */
 
     if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_key, iv) ||
         !EVP_EncryptUpdate(ctx, cipher_body, &len, block, (int)block_len)) {
         ssl_error("AES encrypt"); EVP_CIPHER_CTX_free(ctx); free(block); return -1;
     }
     total_len = len;
 
     if (!EVP_EncryptFinal_ex(ctx, cipher_body + total_len, &len)) {
         ssl_error("AES final"); EVP_CIPHER_CTX_free(ctx); free(block); return -1;
     }
     total_len += len;
     EVP_CIPHER_CTX_free(ctx);
     free(block);
 
     /* ── Step 5: prepend IV ── */
     memcpy(ciphertext, iv, AES_IV_BYTES);
     *ciphertext_len = AES_IV_BYTES + total_len;
 
     return 0;
 }
 
 /* ============================================================
  * FUNCTION : crypto_decrypt
  * PURPOSE  : Receiver side of diagram (d)
  *
  *   Step 1: split ciphertext → IV + cipher_body
  *   Step 2: AES-256-CBC decrypt → block = M + '\0' + H(M||S)
  *   Step 3: split block → message M + stored_hash
  *   Step 4: recompute H(M || S) using our copy of S
  *   Step 5: compare computed hash with stored_hash
  *   Step 6: if equal → authentic; return message
  * ============================================================ */
 int crypto_decrypt(const unsigned char *ciphertext,
                    int ciphertext_len,
                    char *plaintext) {
     if (!g_initialized) { fprintf(stderr, "  [!] crypto not initialised\n"); return -1; }
     if (ciphertext_len <= AES_IV_BYTES) return -1;
 
     /* ── Step 1: extract IV ── */
     unsigned char iv[AES_IV_BYTES];
     memcpy(iv, ciphertext, AES_IV_BYTES);
     const unsigned char *cipher_body = ciphertext + AES_IV_BYTES;
     int cipher_body_len = ciphertext_len - AES_IV_BYTES;
 
     /* ── Step 2: AES-256-CBC decrypt ── */
     unsigned char *block = (unsigned char *)malloc(cipher_body_len + 32);
     if (block == NULL) return -1;
 
     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
     if (ctx == NULL) { free(block); return -1; }
 
     int len = 0, total_len = 0;
 
     if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_key, iv) ||
         !EVP_DecryptUpdate(ctx, block, &len, cipher_body, cipher_body_len)) {
         ssl_error("AES decrypt"); EVP_CIPHER_CTX_free(ctx); free(block); return -1;
     }
     total_len = len;
 
     if (!EVP_DecryptFinal_ex(ctx, block + total_len, &len)) {
         /* Final fails → padding error → tampered or wrong key */
         fprintf(stderr, "  [!] crypto: decryption failed — message may be tampered\n");
         EVP_CIPHER_CTX_free(ctx); free(block); return -1;
     }
     total_len += len;
     EVP_CIPHER_CTX_free(ctx);
 
     /* ── Step 3: split block → M and stored_hash ── */
     /* Block layout: [message bytes][0x00][32 hash bytes] */
     int sep = -1;
     for (int i = 0; i < total_len - (int)SHA256_BYTES; i++) {
         if (block[i] == '\0') { sep = i; break; }
     }
     if (sep < 0 || (sep + 1 + (int)SHA256_BYTES) > total_len) {
         fprintf(stderr, "  [!] crypto: block format invalid\n");
         free(block); return -1;
     }
 
     /* extract the message portion as a C string */
     char msg_buf[MAX_PLAIN_LEN];
     if (sep >= MAX_PLAIN_LEN) { free(block); return -1; }
     memcpy(msg_buf, block, sep);
     msg_buf[sep] = '\0';
 
     /* extract stored hash */
     unsigned char stored_hash[SHA256_BYTES];
     memcpy(stored_hash, block + sep + 1, SHA256_BYTES);
     free(block);
 
     /* ── Step 4: recompute H(M || S) ── */
     unsigned char computed_hash[SHA256_BYTES];
     if (compute_hmac(msg_buf, computed_hash) != 0) return -1;
 
     /* ── Step 5: compare ── */
     if (memcmp(stored_hash, computed_hash, SHA256_BYTES) != 0) {
         fprintf(stderr, "  [!] crypto: authentication FAILED — hash mismatch!\n");
         return -1;  /* message was tampered */
     }
 
     /* ── Step 6: return authenticated plaintext ── */
     strncpy(plaintext, msg_buf, MAX_PLAIN_LEN - 1);
     plaintext[MAX_PLAIN_LEN - 1] = '\0';
     return 0;
 }
 
 /* ============================================================
  * BASE-64 HELPERS
  * We need to transmit binary ciphertext over a text socket.
  * Base64 converts arbitrary bytes to printable ASCII so the
  * existing send_msg / recv_msg framing is not disrupted.
  * ============================================================ */
 
 void crypto_encode_b64(const unsigned char *in, int in_len,
                        char *out, int out_size) {
     BIO *b64  = BIO_new(BIO_f_base64());
     BIO *bmem = BIO_new(BIO_s_mem());
     b64 = BIO_push(b64, bmem);
 
     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);   /* no line breaks */
     BIO_write(b64, in, in_len);
     BIO_flush(b64);
 
     BUF_MEM *bptr;
     BIO_get_mem_ptr(b64, &bptr);
 
     int copy = (int)bptr->length < out_size - 1 ? (int)bptr->length : out_size - 1;
     memcpy(out, bptr->data, copy);
     out[copy] = '\0';
 
     BIO_free_all(b64);
 }
 
 int crypto_decode_b64(const char *in, unsigned char *out, int out_size) {
     BIO *b64  = BIO_new(BIO_f_base64());
     BIO *bmem = BIO_new_mem_buf(in, -1);
     bmem = BIO_push(b64, bmem);
 
     BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
     int decoded_len = BIO_read(bmem, out, out_size);
     BIO_free_all(bmem);
 
     return (decoded_len > 0) ? decoded_len : -1;
 }