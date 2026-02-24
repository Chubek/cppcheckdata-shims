/* ckl_test.c — exercise every CKL-0x checker
 * Compile:  gcc -Wall -o ckl_test ckl_test.c -lssl -lcrypto
 * Analyse:  cppcheck --addon=CryptoKeyLifecycle.py ckl_test.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include <openssl/rc4.h>

/* ------------------------------------------------------------------ */
/* CKL-10  hardcoded key / secret                                      */
/* ------------------------------------------------------------------ */
static const char *password  = "s3cr3tPassw0rd!";   /* CKL-10 */
static const char *apikey    = "AKIAIOSFODNN7EXAMPLE"; /* CKL-10 */
static unsigned char aeskey[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,   /* not a literal — OK */
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

/* ------------------------------------------------------------------ */
/* CKL-02  weak cipher                                                 */
/* ------------------------------------------------------------------ */
void weak_cipher_des(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[8] = {0};
    unsigned char iv[8]  = {0};
    /* CKL-02: DES */
    EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_free(ctx);
}

void weak_cipher_rc4(void) {
    RC4_KEY rc4key;
    unsigned char key[16] = {0};
    /* CKL-02: RC4 */
    RC4_set_key(&rc4key, 16, key);
}

/* ------------------------------------------------------------------ */
/* CKL-03  insufficient key size                                       */
/* ------------------------------------------------------------------ */
void bad_rsa_key_size(void) {
    /* hypothetical call — flagged because 1024 < 2048 for RSA */
    /* RSA_generate_key_ex(rsa, 1024, e, NULL);  -- CKL-03 */
    (void)0;
}

/* ------------------------------------------------------------------ */
/* CKL-04  weak RNG for key material                                   */
/* ------------------------------------------------------------------ */
void weak_rng_key(void) {
    unsigned char key[16];
    /* CKL-04: rand() fills key buffer */
    for (int i = 0; i < 16; i++)
        key[i] = (unsigned char)rand();   /* CKL-04 */
    (void)key;
}

/* ------------------------------------------------------------------ */
/* CKL-05  constant IV                                                 */
/* ------------------------------------------------------------------ */
void constant_iv_literal(void) {
    unsigned char key[16], out[64];
    int outl;
    /* CKL-05: string literal as IV */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key,
                       (unsigned char *)"0000000000000000"); /* CKL-05 */
    EVP_CIPHER_CTX_free(ctx);
}

void constant_iv_variable(void) {
    /* CKL-05: IV variable assigned a constant */
    unsigned char iv[16];
    unsigned char *nonce = "AAAAAAAAAAAAAAAA";   /* CKL-05 */
    (void)nonce;
}

/* ------------------------------------------------------------------ */
/* CKL-06  key in log sink                                             */
/* ------------------------------------------------------------------ */
void key_in_log(void) {
    unsigned char key[32];
    RAND_bytes(key, 32);
    /* CKL-06: tainted key printed */
    printf("DEBUG key = %s\n", key);            /* CKL-06 */
}

void secret_in_log(void) {
    const char *secret = "topsecret";
    fprintf(stderr, "auth secret = %s\n", secret); /* CKL-06 */
}

/* ------------------------------------------------------------------ */
/* CKL-07  key material to file                                        */
/* ------------------------------------------------------------------ */
void key_to_file(void) {
    unsigned char key[32];
    RAND_bytes(key, 32);
    FILE *f = fopen("/tmp/debug.log", "w");
    if (f) {
        fwrite(key, 1, 32, f);   /* CKL-07 */
        fclose(f);
    }
}

/* ------------------------------------------------------------------ */
/* CKL-08  ECB mode                                                    */
/* ------------------------------------------------------------------ */
void ecb_mode(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[16] = {0};
    /* CKL-08: AES-128-ECB */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL); /* CKL-08 */
    EVP_CIPHER_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* CKL-09  missing AEAD auth-tag check                                 */
/* ------------------------------------------------------------------ */
void aead_no_check(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[256];
    int outl = 0;
    /* CKL-09: return value of EVP_DecryptFinal_ex not checked */
    EVP_DecryptFinal_ex(ctx, out, &outl);    /* CKL-09 */
    EVP_CIPHER_CTX_free(ctx);
}

void aead_with_check(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[256];
    int outl = 0;
    /* OK: return value is checked */
    if (EVP_DecryptFinal_ex(ctx, out, &outl) != 1) {
        abort();
    }
    EVP_CIPHER_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* CKL-01  key not zeroed before free / exit                           */
/* ------------------------------------------------------------------ */
void key_no_erase(void) {
    unsigned char *key = malloc(32);
    RAND_bytes(key, 32);
    /* use key … */
    free(key);   /* CKL-01: no explicit_bzero before free */
}

void key_with_erase(void) {
    unsigned char *key = malloc(32);
    RAND_bytes(key, 32);
    /* OK */
    explicit_bzero(key, 32);
    free(key);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
    weak_cipher_des();
    weak_cipher_rc4();
    weak_rng_key();
    constant_iv_literal();
    constant_iv_variable();
    key_in_log();
    secret_in_log();
    key_to_file();
    ecb_mode();
    aead_no_check();
    aead_with_check();
    key_no_erase();
    key_with_erase();
    return 0;
}
