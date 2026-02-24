/*
 * sbh_test.c — Reference test cases for StackBufferHardenLint.py
 *
 * Build dump:
 *   cppcheck --dump sbh_test.c
 * Run addon:
 *   python3 StackBufferHardenLint.py sbh_test.c.dump
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

/* ================================================================== */
/* SBH-01 : unsafe_string_function                                     */
/* ================================================================== */

void sbh01_bad_strcpy(char *dst, const char *src) {
    strcpy(dst, src);           /* SBH-01: no size check */
}

void sbh01_bad_strcat(char *dst, const char *src) {
    strcat(dst, src);           /* SBH-01 */
}

void sbh01_bad_sprintf(char *buf, int val) {
    sprintf(buf, "%d", val);    /* SBH-01 */
}

void sbh01_good_strncpy(char *dst, const char *src, size_t n) {
    strncpy(dst, src, n);       /* OK: bounded variant */
    dst[n - 1] = '\0';
}

/* ================================================================== */
/* SBH-02 : bounded_func_size_mismatch                                 */
/* ================================================================== */

void sbh02_bad_too_large(void) {
    char buf[64];
    strncpy(buf, "hello", 128); /* SBH-02: 128 > 64 */
}

void sbh02_bad_strncat_full(void) {
    char buf[64] = "abc";
    strncat(buf, "xyz", 64);    /* SBH-02: n should be < remaining space */
}

void sbh02_good_strncpy(void) {
    char buf[64];
    strncpy(buf, "hello", 63);  /* OK: 63 < 64, leaves room for NUL */
    buf[63] = '\0';
}

void sbh02_good_snprintf(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", 42);  /* OK */
}

/* ================================================================== */
/* SBH-03 : alloca_unchecked                                           */
/* ================================================================== */

void sbh03_bad_alloca_variable(size_t n) {
    char *buf = alloca(n);      /* SBH-03: n may be unbounded */
    buf[0] = 0;
}

void sbh03_bad_alloca_huge(void) {
    char *buf = alloca(131072); /* SBH-03: 128 KiB on stack */
    buf[0] = 0;
}

void sbh03_good_alloca_small(void) {
    char *buf = alloca(256);    /* OK: small constant size */
    buf[0] = 0;
}

void sbh03_good_alloca_guarded(size_t n) {
    if (n > 4096) return;       /* guard before alloca */
    char *buf = alloca(n);
    buf[0] = 0;
}

/* ================================================================== */
/* SBH-04 : vla_unbounded                                              */
/* ================================================================== */

void sbh04_bad_vla(int n) {
    char buf[n];                /* SBH-04: VLA, n unchecked */
    buf[0] = 0;
}

void sbh04_good_vla_guarded(int n) {
    if (n <= 0 || n > 4096) return;
    char buf[n];                /* Still a VLA but guarded — SBH-04 may fire;
                                   use malloc for fully safe code */
    buf[0] = 0;
}

void sbh04_good_fixed(void) {
    char buf[256];              /* OK: constant size */
    buf[0] = 0;
}

/* ================================================================== */
/* SBH-05 : stack_address_returned                                     */
/* ================================================================== */

char *sbh05_bad_return_local(void) {
    char buf[64];
    return buf;                 /* SBH-05: pointer to local */
}

int *sbh05_bad_return_local_int(void) {
    int x = 42;
    return &x;                  /* SBH-05: address of local int */
}

char *sbh05_good_return_heap(void) {
    char *buf = malloc(64);
    return buf;                 /* OK: heap allocation survives return */
}

static char sbh05_good_static_buf[64];
char *sbh05_good_return_static(void) {
    return sbh05_good_static_buf; /* OK: static storage */
}

/* ================================================================== */
/* SBH-06 : fixed_array_index_unchecked                                */
/* ================================================================== */

void sbh06_bad_unchecked_index(int i) {
    int arr[16];
    arr[i] = 0;                 /* SBH-06: i not validated against 16 */
}

void sbh06_good_checked_index(int i) {
    int arr[16];
    if (i >= 0 && i < 16)
        arr[i] = 0;             /* OK: guarded */
}

void sbh06_good_literal_index(void) {
    int arr[16];
    arr[5] = 0;                 /* OK: literal index in range */
}

/* ================================================================== */
/* SBH-07 : gets_usage                                                 */
/* ================================================================== */

void sbh07_bad_gets(void) {
    char buf[64];
    gets(buf);                  /* SBH-07: gets() is always unsafe */
}

void sbh07_good_fgets(void) {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);  /* OK */
    /* strip newline if needed */
}

/* ================================================================== */
/* SBH-08 : off_by_one_size_arg                                        */
/* ================================================================== */

void sbh08_bad_sizeof_plus_one(const char *src) {
    char buf[64];
    strncpy(buf, src, sizeof(buf) + 1);  /* SBH-08: writes beyond buf */
}

void sbh08_bad_sizeof_minus_zero(const char *src) {
    char buf[64];
    strncpy(buf, src, sizeof(buf) - 0); /* SBH-08: no room for NUL */
}

void sbh08_good_sizeof_minus_one(const char *src) {
    char buf[64];
    strncpy(buf, src, sizeof(buf) - 1); /* OK: leaves room for NUL */
    buf[63] = '\0';
}

/* ================================================================== */
/* Combined edge cases                                                  */
/* ================================================================== */

char *combined_bad(int n, const char *src) {
    /* SBH-04 (VLA) + SBH-01 (strcpy into it) + SBH-05 (return local) */
    char buf[n];
    strcpy(buf, src);
    return buf;
}
