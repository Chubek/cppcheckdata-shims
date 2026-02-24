/*
 * cpc_test.c — exercise cases for CryptoProtocolChecker.py
 *
 * Produce dump:  cppcheck --dump cpc_test.c
 * Run addon:     python3 CryptoProtocolChecker.py cpc_test.c.dump
 *
 * Lines marked EXPECT_CPC-XX should trigger that checker.
 * Lines marked CLEAN should produce no finding.
 */

#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <curl/curl.h>

/* =========================================================================
 * CPC-01  weak_hash_algorithm
 * ===================================================================== */
void cpc01_examples(void) {
    unsigned char digest[16];

    /* EXPECT_CPC-01: direct MD5 call */
    MD5((const unsigned char *)"hello", 5, digest);

    /* EXPECT_CPC-01: SHA1 init */
    SHA1((const unsigned char *)"hello", 5, digest);

    /* EXPECT_CPC-01: EVP algorithm selector */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);   /* weak selector */

    /* CLEAN: SHA-256 */
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    EVP_MD_CTX_free(ctx);
}

/* =========================================================================
 * CPC-02  weak_cipher_algorithm
 * ===================================================================== */
void cpc02_examples(void) {
    /* EXPECT_CPC-02: DES cipher */
    const EVP_CIPHER *des = EVP_des_cbc();
    (void)des;

    /* EXPECT_CPC-02: RC4 */
    const EVP_CIPHER *rc4 = EVP_rc4();
    (void)rc4;

    /* CLEAN: AES-256-GCM */
    const EVP_CIPHER *aes = EVP_aes_256_gcm();
    (void)aes;
}

/* =========================================================================
 * CPC-03  hardcoded_key_or_iv
 * ===================================================================== */
void cpc03_examples(void) {
    /* EXPECT_CPC-03: hardcoded string key */
    const char *key = "SuperSecretKey!!";

    /* EXPECT_CPC-03: hardcoded integer key */
    unsigned int secret = 0xDEADBEEF;
    (void)secret;

    /* EXPECT_CPC-03: hardcoded byte-array IV */
    unsigned char iv[] = {0x00, 0x01, 0x02, 0x03,
                          0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B,
                          0x0C, 0x0D, 0x0E, 0x0F};
    (void)iv;

    /* CLEAN: key loaded from environment */
    const char *env_key = getenv("APP_KEY");
    (void)env_key;

    (void)key;
}

/* =========================================================================
 * CPC-04  null_iv
 * ===================================================================== */
void cpc04_examples(EVP_CIPHER_CTX *ctx, const unsigned char *key_buf) {
    /* EXPECT_CPC-04: NULL IV */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_buf, NULL);

    /* EXPECT_CPC-04: zero-literal IV */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_buf, 0);

    /* CLEAN: random IV */
    unsigned char rand_iv[16];
    RAND_bytes(rand_iv, sizeof rand_iv);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_buf, rand_iv);
}

/* =========================================================================
 * CPC-05  ecb_mode
 * ===================================================================== */
void cpc05_examples(void) {
    /* EXPECT_CPC-05: AES-128-ECB */
    const EVP_CIPHER *ecb128 = EVP_aes_128_ecb();
    (void)ecb128;

    /* EXPECT_CPC-05: AES-256-ECB */
    const EVP_CIPHER *ecb256 = EVP_aes_256_ecb();
    (void)ecb256;

    /* CLEAN: AES-128-GCM */
    const EVP_CIPHER *gcm = EVP_aes_128_gcm();
    (void)gcm;
}

/* =========================================================================
 * CPC-06  weak_prng_for_crypto
 * ===================================================================== */
void cpc06_examples(void) {
    unsigned char key[16];

    /* Crypto context established — PRNG calls below are flagged */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    (void)ctx;

    /* EXPECT_CPC-06: rand() in a TU containing crypto operations */
    for (int i = 0; i < 16; i++) {
        key[i] = (unsigned char)rand();
    }
    (void)key;

    /* CLEAN: crypto-quality randomness */
    unsigned char good_key[16];
    RAND_bytes(good_key, sizeof good_key);
}

/* =========================================================================
 * CPC-07  insufficient_key_size
 * ===================================================================== */
void cpc07_examples(void) {
    /* EXPECT_CPC-07: RSA 512-bit key — far too small */
    RSA *rsa = RSA_generate_key(512, 65537, NULL, NULL);
    (void)rsa;

    /* EXPECT_CPC-07: RSA 1024-bit key — still too small */
    RSA *rsa2 = RSA_generate_key(1024, 65537, NULL, NULL);
    (void)rsa2;

    /* CLEAN: RSA 4096-bit */
    RSA *strong = RSA_generate_key(4096, 65537, NULL, NULL);
    (void)strong;
}

/* =========================================================================
 * CPC-08  non_constant_time_compare
 * ===================================================================== */
int cpc08_examples(const unsigned char *token, const unsigned char *expected,
                   size_t len) {
    /* EXPECT_CPC-08: memcmp on a token — timing oracle */
    if (memcmp(token, expected, len) != 0)
        return 0;

    /* CLEAN: constant-time comparison */
    if (CRYPTO_memcmp(token, expected, len) != 0)
        return 0;

    return 1;
}

/* =========================================================================
 * CPC-09  deprecated_tls_version
 * ===================================================================== */
void cpc09_examples(void) {
    /* EXPECT_CPC-09: SSLv3 method */
    SSL_CTX *ctx_v3  = SSL_CTX_new(SSLv3_method());
    (void)ctx_v3;

    /* EXPECT_CPC-09: TLS 1.0 method */
    SSL_CTX *ctx_10  = SSL_CTX_new(TLSv1_method());
    (void)ctx_10;

    /* EXPECT_CPC-09: TLS 1.1 method */
    SSL_CTX *ctx_11  = SSL_CTX_new(TLSv1_1_method());
    (void)ctx_11;

    /* CLEAN: negotiate best available, then enforce minimum */
    SSL_CTX *ctx_ok  = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx_ok, TLS1_2_VERSION);
    (void)ctx_ok;
}

/* =========================================================================
 * CPC-10  ssl_verification_disabled
 * ===================================================================== */
void cpc10_examples(SSL_CTX *ctx, CURL *curl) {
    /* EXPECT_CPC-10: OpenSSL verification disabled */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* EXPECT_CPC-10: curl peer verification disabled */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    /* EXPECT_CPC-10: curl host verification disabled */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    /* CLEAN: full verification enabled */
    SSL_CTX_set_verify(ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
}

/* =========================================================================
 * CPC-11  unauthenticated_encryption
 * ===================================================================== */
void cpc11_bad(EVP_CIPHER_CTX *ctx, const unsigned char *key,
               const unsigned char *iv,
               const unsigned char *pt, int pt_len,
               unsigned char *ct) {
    /* EXPECT_CPC-11: AES-CBC with no adjacent authentication */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    int out_len;
    EVP_EncryptUpdate(ctx, ct, &out_len, pt, pt_len);
    EVP_EncryptFinal_ex(ctx, ct + out_len, &out_len);
}

void cpc11_good(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *pt, int pt_len,
                unsigned char *ct, unsigned char *tag) {
    /* CLEAN: AES-GCM (authenticated encryption) */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    int out_len;
    EVP_EncryptUpdate(ctx, ct, &out_len, pt, pt_len);
    EVP_EncryptFinal_ex(ctx, ct + out_len, &out_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
}

/* =========================================================================
 * CPC-12  hardcoded_salt_constant
 * ===================================================================== */
void cpc12_examples(const char *password, unsigned char *key_out) {
    /* EXPECT_CPC-12: short constant salt */
    PKCS5_PBKDF2_HMAC(
        password, -1,
        (const unsigned char *)"salt",  /* short literal salt */
        4,
        100000,
        EVP_sha256(),
        32, key_out
    );

    /* EXPECT_CPC-12: NULL salt */
    PKCS5_PBKDF2_HMAC(
        password, -1,
        NULL, 0,
        100000,
        EVP_sha256(),
        32, key_out
    );

    /* CLEAN: random per-user salt */
    unsigned char rand_salt[16];
    RAND_bytes(rand_salt, sizeof rand_salt);
    PKCS5_PBKDF2_HMAC(
        password, -1,
        rand_salt, sizeof rand_salt,
        100000,
        EVP_sha256(),
        32, key_out
    );
}
