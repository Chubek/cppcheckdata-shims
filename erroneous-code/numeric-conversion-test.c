/*
 * nca_test.c — exercise all 9 NumericConversionAuditor rules
 *
 * Compile and dump:
 *   cppcheck --dump nca_test.c
 *   python NumericConversionAuditor.py nca_test.c.dump
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* ── NCA-06: enum with known valid values ──────────────────────────────── */
typedef enum { COLOR_RED = 0, COLOR_GREEN = 1, COLOR_BLUE = 2 } Color;

/* ── NCA-08: function declares int return, computes in long long ────────── */
int narrow_return(long long x) {
    long long result = x * 1000LL;   /* wide computation */
    return result;                    /* NCA-08: widening→narrowing return  */
}

int main(void) {
    /* ── NCA-01: signed → unsigned, can be negative ───────────────────── */
    int  signed_val = -5;
    unsigned int u = signed_val;      /* NCA-01: signed-to-unsigned wrap    */

    /* ── NCA-02: unsigned → signed, may exceed SIGNED_MAX ─────────────── */
    unsigned int big_u = 3000000000U;
    int signed_dest = big_u;          /* NCA-02: unsigned-to-signed overflow */

    /* ── NCA-03: explicit narrowing cast ───────────────────────────────── */
    long long wide = 0x1_0000_0000LL;
    int narrow = (int)wide;           /* NCA-03: high 32 bits discarded     */

    /* ── NCA-04: float → int, fractional part lost ─────────────────────── */
    double d = 3.14;
    int   as_int = (int)d;            /* NCA-04: 0.14 silently truncated    */

    /* ── NCA-05: large int → float, precision lost ─────────────────────── */
    long long big_int = 0x7FFFFFFFFFFFFFFFLL;
    float f = (float)big_int;         /* NCA-05: 40 bits of precision lost  */

    /* ── NCA-06: enum cast with out-of-range integer ───────────────────── */
    int raw = 99;
    Color c = (Color)raw;             /* NCA-06: 99 has no Color enumerator */

    /* ── NCA-07: plain char in sign-sensitive comparison ───────────────── */
    char ch;
    while ((ch = getchar()) != EOF) { /* NCA-07: plain char vs. int EOF=-1  */
        putchar(ch);
    }

    /* ── NCA-08: triggered by narrow_return() definition above ─────────── */

    /* ── NCA-09: tainted value flows into conversion sink ──────────────── */
    int net_len;
    recv(3, &net_len, sizeof(net_len), 0);   /* taint source               */
    /* net_len is now tainted */
    size_t alloc_sz = (size_t)net_len;       /* NCA-09: tainted cast       */
    char  *buf = malloc(alloc_sz);           /* NCA-09: tainted alloc size */
    if (buf) {
        recv(3, buf, alloc_sz, 0);
        free(buf);
    }

    return 0;
}
