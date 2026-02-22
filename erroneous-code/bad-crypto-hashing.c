/*
 * bad_crypto_hashing.c
 *
 * Expected findings:
 *   [weakHashMD5]           — MD5_Init / MD5_Update / MD5_Final / EVP_md5
 *   [weakHashSHA1]          — SHA1 / CC_SHA1
 *   [weakHashStringSelector]— EVP_get_digestbyname("md5")
 *   [weakPRNG]              — rand() used for salt
 *   [weakPRNGSeed]          — srand() call
 *   [hardcodedCryptoKey]    — secret = "hunter2..."
 *   [keyInGlobalScope]      — global hmac_key array
 *   [keyLoggedOrPrinted]    — printf(key)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* ── CWE-312 / CWE-316: key material in global scope ─────────────────── */
unsigned char hmac_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

/* ── CWE-321: hard-coded secret ───────────────────────────────────────── */
const char *secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/* ── MD5 password hashing — CWE-328 ──────────────────────────────────── */
void hash_password_md5(const char *password, unsigned char *out_digest)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);                          /* weakHashMD5 */
    MD5_Update(&ctx, password, strlen(password));
    MD5_Final(out_digest, &ctx);             /* weakHashMD5 */
}

/* ── SHA-1 file integrity check — CWE-328 ────────────────────────────── */
void check_integrity_sha1(const unsigned char *data, size_t len,
                           unsigned char *out)
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);                         /* weakHashSHA1 */
    SHA1_Update(&ctx, data, len);
    SHA1_Final(out, &ctx);                   /* weakHashSHA1 */
}

/* ── EVP digest selector — CWE-327 ───────────────────────────────────── */
const EVP_MD *pick_digest(void)
{
    /* weakHashStringSelector — "md5" in string literal */
    return EVP_get_digestbyname("md5");
}

/* ── Salt generation using non-CSPRNG — CWE-338 ─────────────────────── */
unsigned int make_salt(void)
{
    srand(12345);          /* weakPRNGSeed */
    return (unsigned int)rand();   /* weakPRNG */
}

/* ── Key printed to stdout — CWE-312 ─────────────────────────────────── */
void debug_dump_key(void)
{
    /* keyLoggedOrPrinted: hmac_key passed to printf */
    printf("Current HMAC key: %s\n", hmac_key);
}

int main(void)
{
    unsigned char digest[MD5_DIGEST_LENGTH];
    hash_password_md5("correct-horse-battery-staple", digest);

    unsigned char sha_digest[SHA_DIGEST_LENGTH];
    const unsigned char sample[] = "important data";
    check_integrity_sha1(sample, sizeof(sample) - 1, sha_digest);

    const EVP_MD *md = pick_digest();
    (void)md;

    unsigned int salt = make_salt();
    printf("Salt: %u\n", salt);

    debug_dump_key();

    /* Hard-coded assignment — hardcodedCryptoKey */
    const char *key = "0123456789abcdef0123456789abcdef";
    printf("Key: %s\n", key);

    return 0;
}
