/*
 * ing_test.c — Reference test cases for IntegerNarrowingGuard.py
 *
 * Build dump:
 *   cppcheck --dump ing_test.c
 * Run addon:
 *   python3 IntegerNarrowingGuard.py ing_test.c.dump
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* ING-01 : implicit_truncation_assignment                            */
/* ------------------------------------------------------------------ */

void ing01_bad(long val) {
    char c   = val;          /* ING-01: 64-bit -> 8-bit */
    short s  = val;          /* ING-01: 64-bit -> 16-bit */
    int   i  = val;          /* ING-01: 64-bit -> 32-bit */
    (void)c; (void)s; (void)i;
}

void ing01_good(long val) {
    char  c  = (char)val;    /* explicit cast — suppressed */
    long  l  = val;          /* same width — OK */
    (void)c; (void)l;
}

/* ------------------------------------------------------------------ */
/* ING-02 : signed_to_unsigned_comparison                             */
/* ------------------------------------------------------------------ */

void ing02_bad(int count, unsigned int limit) {
    if (count < limit) {     /* ING-02: signed vs unsigned */
        /* ... */
    }
}

void ing02_good(unsigned int count, unsigned int limit) {
    if (count < limit) {     /* both unsigned — OK */
        /* ... */
    }
}

void ing02_suppress(unsigned int u) {
    if (2 < u) {             /* literal 2 is non-negative — suppressed */
        /* ... */
    }
}

/* ------------------------------------------------------------------ */
/* ING-03 : loop_counter_overflow                                     */
/* ------------------------------------------------------------------ */

void ing03_bad(void) {
    for (uint8_t i = 0; i < 300; i++) {   /* ING-03: 300 >= 256 */
        /* infinite loop: i wraps to 0 at 255 */
    }
}

void ing03_good(void) {
    for (uint8_t i = 0; i < 200; i++) {   /* 200 < 256 — OK */
        /* ... */
    }
    for (int i = 0; i < 300; i++) {       /* signed int — OK */
        /* ... */
    }
}

/* ------------------------------------------------------------------ */
/* ING-04 : return_truncation                                         */
/* ------------------------------------------------------------------ */

int ing04_bad(long long val) {
    return val;              /* ING-04: 64-bit returned from 32-bit func */
}

long long ing04_good(long long val) {
    return val;              /* same width — OK */
}

/* ------------------------------------------------------------------ */
/* ING-05 : size_t_downcast                                           */
/* ------------------------------------------------------------------ */

void ing05_bad(const char *s) {
    int len = (int)strlen(s);    /* ING-05: size_t -> signed int */
    (void)len;
}

void ing05_good(const char *s) {
    size_t len = strlen(s);      /* correct type — OK */
    (void)len;
}

/* ------------------------------------------------------------------ */
/* ING-06 : shift_width_exceeds_type                                  */
/* ------------------------------------------------------------------ */

void ing06_bad(uint32_t x) {
    uint32_t a = x << 32;    /* ING-06: shift by 32 on 32-bit type — UB */
    uint32_t b = x >> 33;    /* ING-06: shift by 33 — UB */
    (void)a; (void)b;
}

void ing06_good(uint32_t x) {
    uint32_t a = x << 31;    /* 31 < 32 — OK */
    uint64_t b = (uint64_t)x << 32;  /* widened first — OK */
    (void)a; (void)b;
}

/* ------------------------------------------------------------------ */
/* ING-07 : negation_of_unsigned                                      */
/* ------------------------------------------------------------------ */

void ing07_bad(unsigned int u) {
    unsigned int neg = -u;   /* ING-07: wraps silently */
    (void)neg;
}

void ing07_good(int s) {
    int neg = -s;            /* signed — OK */
    (void)neg;
}

/* ------------------------------------------------------------------ */
/* ING-08 : multiplication_before_widening                            */
/* ------------------------------------------------------------------ */

void ing08_bad(int rows, int cols) {
    int64_t size = rows * cols;       /* ING-08: 32*32 overflows before widening */
    (void)size;
}

void ing08_good_cast(int rows, int cols) {
    int64_t size = (int64_t)rows * cols;   /* one operand cast first — OK */
    (void)size;
}

void ing08_good_small(void) {
    int64_t size = 100 * 200;         /* both literals, product fits — OK */
    (void)size;
}
