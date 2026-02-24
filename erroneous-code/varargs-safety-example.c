/*
 * vsc_test.c — exercises all 10 VarargsSafetyChecker rules
 *
 *   cppcheck --dump vsc_test.c
 *   python VarargsSafetyChecker.py vsc_test.c.dump
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ── VSC-01: non-literal format string ──────────────────────────────── */
void vsc01_demo(const char *user_fmt) {
    printf(user_fmt);               /* VSC-01 + VSC-09 if tainted       */
}

/* ── VSC-02: too few arguments ──────────────────────────────────────── */
void vsc02_demo(void) {
    printf("%d %s %f\n", 42);       /* VSC-02: needs 3 args, got 1      */
}

/* ── VSC-03: too many arguments ─────────────────────────────────────── */
void vsc03_demo(void) {
    printf("%d\n", 1, 2, 3);       /* VSC-03: needs 1 arg, got 3       */
}

/* ── VSC-04: type mismatch ───────────────────────────────────────────── */
void vsc04_demo(void) {
    printf("%d\n", 3.14f);          /* VSC-04: float passed for %d      */
    printf("%s\n", 42);             /* VSC-04: int passed for %s        */
}

/* ── VSC-05: va_start wrong parameter ───────────────────────────────── */
void vsc05_demo(int first, int second, ...) {
    va_list ap;
    va_start(ap, first);            /* VSC-05: should be 'second'       */
    va_end(ap);
}

/* ── VSC-06: va_arg before va_start ─────────────────────────────────── */
void vsc06_demo(int count, ...) {
    va_list ap;
    int x = va_arg(ap, int);       /* VSC-06: va_arg before va_start   */
    va_start(ap, count);
    va_end(ap);
}

/* ── VSC-07: va_arg after va_end ────────────────────────────────────── */
void vsc07_demo(int count, ...) {
    va_list ap;
    va_start(ap, count);
    va_end(ap);
    int x = va_arg(ap, int);       /* VSC-07: va_arg after va_end      */
}

/* ── VSC-08: va_list double-free ─────────────────────────────────────── */
void vsc08_demo(int count, ...) {
    va_list ap;
    va_start(ap, count);
    va_end(ap);
    va_end(ap);                     /* VSC-08: va_end called twice      */
}

/* ── VSC-09: tainted format string ──────────────────────────────────── */
void vsc09_demo(void) {
    char *fmt = getenv("LOG_FMT");  /* taint source                     */
    printf(fmt, 42);                /* VSC-09: fmt derived from getenv  */
}

/* ── VSC-10: unchecked scanf return ─────────────────────────────────── */
void vsc10_demo(void) {
    int n;
    scanf("%d", &n);                /* VSC-10: return value not checked  */
    printf("Got: %d\n", n);
}

/* ── CORRECT usage (regression baseline — should produce NO findings) ── */
void correct_printf(void) {
    printf("%d %s %.2f\n", 42, "hello", 3.14);   /* ok: literal, 3 args */
}

void correct_scanf(void) {
    int n;
    if (scanf("%d", &n) == 1) {    /* ok: return value checked          */
        printf("n=%d\n", n);
    }
}

void correct_varargs(int first, int second, ...) {
    va_list ap;
    va_start(ap, second);          /* ok: last named parameter          */
    int v = va_arg(ap, int);
    va_end(ap);
}

int main(int argc, char *argv[]) {
    vsc01_demo(argv[1]);           /* argv[1] tainted → VSC-09          */
    vsc02_demo();
    vsc03_demo();
    vsc04_demo();
    vsc05_demo(1, 2, 3);
    vsc06_demo(1, 10);
    vsc07_demo(1, 10);
    vsc08_demo(1, 10);
    vsc09_demo();
    vsc10_demo();
    correct_printf();
    correct_scanf();
    correct_varargs(0, 1, 99);
    return 0;
}
