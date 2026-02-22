/*
 * bad_crypto_cipher.c
 *
 * Expected findings:
 *   [weakCipherDES]          — EVP_des_cbc / DES_ecb_encrypt / mbedtls_des_crypt_cbc
 *   [weakCipherRC4]          — RC4 / EVP_rc4
 *   [weakCipherECB]          — EVP_aes_128_ecb (ECB mode, no semantic security)
 *   [weakCipherBlowfish]     — EVP_bf_cbc
 *   [weakCipherStringSelector]— EVP_get_cipherbyname("des-cbc")
 *   [missingCSPRNG]          — crypto setup without any RAND_bytes / getrandom
 *   [hardcodedCryptoKeyBytes]— 32-char hex literal to AES_set_encrypt_key
 *   [customCryptoFunction]   — function named xor_cipher
 *   [suspiciousBitOpDensity] — xor_cipher body is dense in ^, >>, <<, &
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/* ════════════════════════════════════════════════════════════════════
 * SECTION A — Weak symmetric ciphers
 * ════════════════════════════════════════════════════════════════════ */

/* ── DES-CBC via low-level API — CWE-327 ─────────────────────────── */
void encrypt_des_cbc(const unsigned char *in, unsigned char *out,
                     DES_key_schedule *ks, DES_cblock *iv)
{
    DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out,
                    ks, DES_ENCRYPT);          /* weakCipherDES */
}

/* ── RC4 stream cipher — CWE-327 ─────────────────────────────────── */
void encrypt_rc4(unsigned char *key_data, int key_len,
                 unsigned char *data, int data_len)
{
    RC4_KEY key;
    RC4_set_key(&key, key_len, key_data);      /* weakCipherRC4 */
    RC4(&key, data_len, data, data);           /* weakCipherRC4 */
}

/* ── Blowfish via EVP — CWE-327 ──────────────────────────────────── */
void encrypt_blowfish(const unsigned char *plaintext, int pt_len,
                      const unsigned char *key,  int key_len,
                      const unsigned char *iv,
                      unsigned char *ciphertext, int *ct_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx,
                       EVP_bf_cbc(),            /* weakCipherBlowfish */
                       NULL, key, iv);
    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len);
    *ct_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    *ct_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

/* ── AES-128-ECB — ECB mode is not semantically secure — CWE-327 ── */
void encrypt_aes_ecb(const unsigned char *in, unsigned char *out,
                     const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_EncryptInit_ex(ctx,
                       EVP_aes_128_ecb(),       /* weakCipherECB */
                       NULL, key, NULL);
    EVP_EncryptUpdate(ctx, out, &len, in, 16);
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

/* ── String-based cipher selector — CWE-327 ─────────────────────── */
const EVP_CIPHER *select_cipher(void)
{
    return EVP_get_cipherbyname("des-cbc");     /* weakCipherStringSelector */
}

/* ════════════════════════════════════════════════════════════════════
 * SECTION B — Hard-coded key passed to AES — CWE-321
 * ════════════════════════════════════════════════════════════════════ */

void setup_aes_with_hardcoded_key(AES_KEY *aes_ks)
{
    /*
     * "00112233445566778899aabbccddeeff" is 32 hex chars = 128-bit key
     * hardcodedCryptoKeyBytes fires here
     */
    AES_set_encrypt_key(
        (const unsigned char *)"00112233445566778899aabbccddeeff",
        128,
        aes_ks                                 /* hardcodedCryptoKeyBytes */
    );
}

/* ════════════════════════════════════════════════════════════════════
 * SECTION C — Hand-rolled XOR cipher — CWE-327
 * customCryptoFunction + suspiciousBitOpDensity
 * ════════════════════════════════════════════════════════════════════ */

/*
 * xor_cipher — name matches _CUSTOM_CRYPTO_NAME_RE ("cipher" stem).
 * Body is also extremely dense in bitwise operators, triggering
 * suspiciousBitOpDensity when the ratio exceeds 18 %.
 */
void xor_cipher(uint8_t *data, size_t len, const uint8_t *key, size_t klen)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t k  = key[i % klen];
        uint8_t lo = (k & 0x0F) ^ (data[i] & 0x0F);   /* ^ & ^ & */
        uint8_t hi = (k >> 4)   ^ (data[i] >> 4);      /* >> ^ >> */
        uint8_t r  = ((hi & 0x0F) << 4) | (lo & 0x0F); /* & << | & */
        r  ^= (r >> 2) ^ (r << 6);                      /* ^ >> ^ << */
        r  &= 0xFF;                                      /* & */
        data[i] = r ^ k ^ (uint8_t)(i & 0xFF);          /* ^ ^ & */
    }
}

/* ── A second hand-rolled function using the "encrypt" stem ──────── */
void my_encrypt(uint8_t *buf, size_t n, uint8_t seed)
{
    /* customCryptoFunction — "my_" prefix + "encrypt" stem */
    for (size_t i = 0; i < n; i++) {
        seed  = (seed ^ 0xA5) & 0xFF;          /* ^ & */
        seed  = (seed << 1) | (seed >> 7);     /* << | >> */
        buf[i] ^= seed;                         /* ^= */
        buf[i]  = (buf[i] >> 1) | (buf[i] << 7); /* >> | << */
    }
}

int main(void)
{
    /* missingCSPRNG fires here:
     * EVP_EncryptInit_ex is present but no RAND_bytes / getrandom anywhere.
     */
    unsigned char key[16]  = {0};
    unsigned char iv[8]    = {0};
    unsigned char plain[]  = "Secret message!!";
    unsigned char cipher_buf[64] = {0};
    int ct_len = 0;

    encrypt_blowfish(plain, (int)sizeof(plain), key, 16, iv,
                     cipher_buf, &ct_len);

    unsigned char msg[] = "Hello";
    uint8_t k[] = {0xDE, 0xAD, 0xBE, 0xEF};
    xor_cipher(msg, sizeof(msg), k, sizeof(k));
    my_encrypt(msg, sizeof(msg), 0x42);

    AES_KEY aes_ks;
    setup_aes_with_hardcoded_key(&aes_ks);

    encrypt_aes_ecb(plain, cipher_buf, key);
    encrypt_rc4(key, 16, plain, (int)sizeof(plain));

    const EVP_CIPHER *c = select_cipher();
    (void)c;

    return 0;
}
