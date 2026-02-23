/*
 * ssl_signal_test.c — exercise all 6 SignalSafetyLint checks.
 *
 * Compile and dump:
 *   cppcheck --dump ssl_signal_test.c
 *   python SignalSafetyLint.py ssl_signal_test.c.dump
 *
 * Intentionally contains every defect pattern; do NOT use in production.
 */

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Shared state ──────────────────────────────────────────────── */

/* WRONG: should be  volatile sig_atomic_t  (sig-02, sig-03) */
static int g_caught = 0;

/* Correct flag — used in good_handler only */
static volatile sig_atomic_t g_clean_flag = 0;

/* setjmp buffer for sig-06 test */
static jmp_buf g_jmpbuf;

/* ════════════════════════════════════════════════════════════════
 * bad_handler — triggers sig-01, sig-02, sig-03, sig-04, sig-05
 * ════════════════════════════════════════════════════════════════ */
static void bad_handler(int sig)
{
    /* sig-02 + sig-03: write to non-volatile, non-sig_atomic_t global */
    g_caught = 1;

    /* sig-01: printf is async-signal-unsafe */
    printf("caught signal %d\n", sig);

    /* sig-05: write() may clobber errno; no save/restore present */
    write(STDERR_FILENO, "signal!\n", 8);

    /* sig-01: malloc is async-signal-unsafe */
    void *tmp = malloc(16);
    free(tmp);                /* sig-01: free is async-signal-unsafe */

    /* sig-04: re-registering the signal inside the handler */
    signal(sig, bad_handler);
}

/* ════════════════════════════════════════════════════════════════
 * longjmp_handler — triggers sig-06
 * ════════════════════════════════════════════════════════════════ */
static void longjmp_handler(int sig)
{
    /* sig-06: longjmp from handler is prohibited */
    longjmp(g_jmpbuf, 1);
}

/* ════════════════════════════════════════════════════════════════
 * good_handler — no defects (regression / true-negative guard)
 * ════════════════════════════════════════════════════════════════ */
static void good_handler(int sig)
{
    /* Correct errno save/restore pattern */
    int saved_errno = errno;

    /* write() is async-signal-safe */
    write(STDERR_FILENO, "ok\n", 3);

    /* Correct flag type */
    g_clean_flag = 1;

    errno = saved_errno;
}

/* ════════════════════════════════════════════════════════════════
 * main
 * ════════════════════════════════════════════════════════════════ */
int main(void)
{
    /* Register bad_handler for SIGINT */
    signal(SIGINT, bad_handler);

    /* Register longjmp_handler for SIGTERM */
    signal(SIGTERM, longjmp_handler);

    /* Register good_handler for SIGUSR1 via sigaction */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = good_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    if (setjmp(g_jmpbuf) == 0) {
        /* normal path */
        while (!g_clean_flag) {
            pause();
        }
    } else {
        /* longjmp recovery */
    }

    return 0;
}
