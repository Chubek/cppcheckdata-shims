/*
 * cic_test.c — Reference test cases for ConcurrencyInvariantChecker.py
 *
 * cppcheck --dump cic_test.c
 * python3 ConcurrencyInvariantChecker.py cic_test.c.dump
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdatomic.h>

static pthread_mutex_t mu_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mu_b = PTHREAD_MUTEX_INITIALIZER;
static int shared_counter   = 0;  /* global — CIC-04 target */
static _Atomic int flag     = 0;

/* ── CIC-01: lock not released ───────────────────────────────── */
void cic01_bad(void) {
    pthread_mutex_lock(&mu_a);
    shared_counter++;
    /* BUG: never unlocked → CIC-01 */
}
void cic01_good(void) {
    pthread_mutex_lock(&mu_a);
    shared_counter++;
    pthread_mutex_unlock(&mu_a);    /* OK */
}

/* ── CIC-02: double lock ─────────────────────────────────────── */
void cic02_bad(void) {
    pthread_mutex_lock(&mu_a);
    pthread_mutex_lock(&mu_a);      /* CIC-02: deadlock on non-recursive */
    pthread_mutex_unlock(&mu_a);
    pthread_mutex_unlock(&mu_a);
}

/* ── CIC-03: unlock without lock ────────────────────────────── */
void cic03_bad(void) {
    pthread_mutex_unlock(&mu_b);    /* CIC-03: never locked */
}

/* ── CIC-04: shared var written without lock ─────────────────── */
void cic04_bad(void) {
    shared_counter = 42;            /* CIC-04: no lock held */
}
void cic04_good(void) {
    pthread_mutex_lock(&mu_a);
    shared_counter = 42;            /* OK: protected */
    pthread_mutex_unlock(&mu_a);
}

/* ── CIC-05: lock order inversion ────────────────────────────── */
void cic05_thread1(void) {
    pthread_mutex_lock(&mu_a);      /* A then B */
    pthread_mutex_lock(&mu_b);
    shared_counter++;
    pthread_mutex_unlock(&mu_b);
    pthread_mutex_unlock(&mu_a);
}
void cic05_thread2(void) {
    pthread_mutex_lock(&mu_b);      /* B then A → CIC-05 inversion */
    pthread_mutex_lock(&mu_a);
    shared_counter++;
    pthread_mutex_unlock(&mu_a);
    pthread_mutex_unlock(&mu_b);
}

/* ── CIC-06: cond_wait not in while loop ─────────────────────── */
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int ready = 0;

void cic06_bad(void) {
    pthread_mutex_lock(&mu_a);
    if (!ready)                     /* CIC-06: should be while */
        pthread_cond_wait(&cv, &mu_a);
    pthread_mutex_unlock(&mu_a);
}
void cic06_good(void) {
    pthread_mutex_lock(&mu_a);
    while (!ready)                  /* OK: while loop */
        pthread_cond_wait(&cv, &mu_a);
    pthread_mutex_unlock(&mu_a);
}

/* ── CIC-07: atomic store with relaxed ordering ──────────────── */
void cic07_bad(void) {
    atomic_store_explicit(&flag, 1,
        memory_order_relaxed);      /* CIC-07: relaxed on flag */
}
void cic07_good(void) {
    atomic_store_explicit(&flag, 1,
        memory_order_release);      /* OK: release semantics */
}

/* ── CIC-08: sleep under lock ────────────────────────────────── */
void cic08_bad(void) {
    pthread_mutex_lock(&mu_a);
    sleep(1);                       /* CIC-08: holding lock while sleeping */
    pthread_mutex_unlock(&mu_a);
}
void cic08_good(void) {
    pthread_mutex_unlock(&mu_a);    /* release first */
    sleep(1);
    pthread_mutex_lock(&mu_a);      /* re-acquire */
}

/* ── CIC-09: trylock result unchecked ───────────────────────── */
void cic09_bad(void) {
    pthread_mutex_trylock(&mu_a);   /* CIC-09: result discarded */
    shared_counter++;
    pthread_mutex_unlock(&mu_a);
}
void cic09_good(void) {
    if (pthread_mutex_trylock(&mu_a) == 0) {  /* OK: result checked */
        shared_counter++;
        pthread_mutex_unlock(&mu_a);
    }
}

/* ── CIC-10: TOCTOU race ─────────────────────────────────────── */
void cic10_bad(const char *path) {
    if (access(path, W_OK) == 0)    /* CIC-10: check */
        open(path, O_WRONLY);       /* CIC-10: use — race window */
}
void cic10_good(const char *path) {
    /* Use O_CREAT|O_EXCL for atomic create-or-fail */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) perror("open");
}
