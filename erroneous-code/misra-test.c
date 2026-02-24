/* msl_test.c — reference test cases for MisraSubsetLint.py
 *
 * Compile and dump:
 *   cppcheck --dump msl_test.c
 *   python3 MisraSubsetLint.py msl_test.c.dump
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── MSL-08: #define redefines keyword ──────────────────────────────────── */
#define if(x) (x)          /* VIOLATION MSL-08 */
#define SAFE_WORD  42      /* OK — not a keyword */

/* ── MSL-09: banned memory functions ────────────────────────────────────── */
void test_banned_memory(void)
{
    int *p = (int *)malloc(sizeof(int) * 10);   /* VIOLATION MSL-09 */
    if (p != NULL) {
        p[0] = 1;
        free(p);                                /* VIOLATION MSL-09 */
    }
}

/* ── MSL-03: switch missing default ─────────────────────────────────────── */
void test_switch_no_default(int x)
{
    switch (x) {            /* VIOLATION MSL-03 */
    case 1:
        break;
    case 2:
        break;
    }
}

/* ── MSL-04: default not last ───────────────────────────────────────────── */
void test_switch_default_not_last(int x)
{
    switch (x) {            /* VIOLATION MSL-04 */
    default:
        break;
    case 1:
        break;
    case 2:
        break;
    }
}

/* ── MSL-02: multiple return statements ─────────────────────────────────── */
int test_multiple_returns(int x)
{
    if (x < 0) {
        return -1;          /* first return — OK */
    }
    if (x == 0) {
        return 0;           /* VIOLATION MSL-02 (second return) */
    }
    return 1;               /* third return */
}

/* ── MSL-01: non-boolean controlling expression ─────────────────────────── */
void test_non_bool_control(int flag)
{
    if (flag) {             /* VIOLATION MSL-01: plain int, no comparison */
        flag = 0;
    }
    while (flag) {          /* VIOLATION MSL-01 */
        flag--;
    }
    if (flag == 0) {        /* OK */
        flag = 1;
    }
}

/* ── MSL-05: mixed arithmetic and bitwise ───────────────────────────────── */
void test_mixed_ops(unsigned int a, unsigned int b, unsigned int c)
{
    unsigned int r;
    r = a + b & c;          /* VIOLATION MSL-05 */
    r = (a + b) & c;        /* OK — explicit parens */
    (void)r;
}

/* ── MSL-06: inc/dec in boolean sub-expression ──────────────────────────── */
void test_inc_in_bool(int a, int b)
{
    int c = a++ && b;       /* VIOLATION MSL-06 */
    int d = a   && b;       /* OK */
    (void)c; (void)d;
}

/* ── MSL-07: ignored return value ───────────────────────────────────────── */
void test_ignored_return(const char *src, char *dst)
{
    memcpy(dst, src, 10);   /* VIOLATION MSL-07 */
    char *copy = memcpy(dst, src, 10);  /* OK — value captured */
    (void)copy;
}

/* ── MSL-10: multiple break in loop ─────────────────────────────────────── */
void test_multiple_break(int *arr, int n)
{
    for (int i = 0; i < n; i++) {
        if (arr[i] < 0) {
            break;          /* first break OK */
        }
        if (arr[i] > 100) {
            break;          /* VIOLATION MSL-10 */
        }
    }
}

/* ── CLEAN function (no violations) ─────────────────────────────────────── */
int clean_function(int x)
{
    int result = 0;
    switch (x) {
    case 1:
        result = 10;
        break;
    case 2:
        result = 20;
        break;
    default:
        result = -1;
        break;
    }
    return result;
}
