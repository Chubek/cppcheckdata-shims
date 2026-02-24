/*
 * acl_test.c  — exercises all 10 AtomicCorrectnessLint rules
 *
 *   cppcheck --dump acl_test.c
 *   python AtomicCorrectnessLint.py acl_test.c.dump
 *
 * Compile check (not meant to be run):
 *   cc -std=c11 -Wall -Wextra -c acl_test.c
 */
#include <stdatomic.h>
#include <signal.h>
#include <stddef.h>

/* ── Shared state ───────────────────────────────────────────────────── */
static _Atomic int      g_counter  = ATOMIC_VAR_INIT(0);
static atomic_flag      g_lock     = ATOMIC_FLAG_INIT;
static atomic_flag      g_lock2    = ATOMIC_FLAG_INIT;

/* ACL-06: sig_atomic_t without volatile */
static sig_atomic_t     g_got_sig;           /* ACL-06 */
static volatile sig_atomic_t g_got_sig_ok;   /* correct — no flag */

struct SharedStruct {
    _Atomic int counter;
    char        padding[60];
};
static struct SharedStruct g_shared;

/* ═══════════════ ACL-01: load-store TOCTOU ════════════════════════ */
void acl01_demo(void) {
    int val = atomic_load(&g_counter);      /* load   */
    if (val < 100)
        atomic_store(&g_counter, val + 1);  /* ACL-01 */
}

void acl01_correct(void) {
    atomic_fetch_add(&g_counter, 1);        /* ok: atomic RMW */
}

/* ═══════════════ ACL-02: plain operator on _Atomic ════════════════ */
void acl02_demo(void) {
    g_counter = 0;     /* ACL-02: plain = on _Atomic int  */
    g_counter++;       /* ACL-02: plain ++ on _Atomic int */
    g_counter += 5;    /* ACL-02: plain += on _Atomic int */
}

void acl02_correct(void) {
    atomic_store(&g_counter, 0);
    atomic_fetch_add(&g_counter, 1);
    atomic_fetch_add(&g_counter, 5);
}

/* ═══════════════ ACL-03: relaxed mixed with seq_cst ═══════════════ */
static _Atomic int g_flag = ATOMIC_VAR_INIT(0);

void acl03_writer(void) {
    atomic_store_explicit(&g_flag, 1, memory_order_seq_cst);  /* strong */
}

void acl03_reader(void) {
    /* ACL-03: relaxed used on same variable that has seq_cst elsewhere */
    int v = atomic_load_explicit(&g_flag, memory_order_relaxed);
    (void)v;
}

/* ═══════════════ ACL-04: double-lock ══════════════════════════════ */
void acl04_demo(void) {
    atomic_flag_test_and_set(&g_lock2);  /* first acquire  */
    atomic_flag_test_and_set(&g_lock2);  /* ACL-04: second acquire */
    atomic_flag_clear(&g_lock2);
}

void acl04_correct(void) {
    atomic_flag_test_and_set(&g_lock2);
    atomic_flag_clear(&g_lock2);
    atomic_flag_test_and_set(&g_lock2);  /* ok: after clear */
    atomic_flag_clear(&g_lock2);
}

/* ═══════════════ ACL-05: flag acquired but never cleared ══════════ */
void acl05_demo(void) {
    atomic_flag_test_and_set(&g_lock);   /* ACL-05: no clear in this fn */
    /* ... critical section ... */
    /* forgot atomic_flag_clear! */
}

void acl05_correct_lock(void) {         /* name contains "lock" → suppressed */
    atomic_flag_test_and_set(&g_lock);
}

void acl05_correct_unlock(void) {
    atomic_flag_clear(&g_lock);
}

/* ═══════════════ ACL-07: CAS return value ignored ═════════════════ */
void acl07_demo(void) {
    int expected = 0;
    /* ACL-07: return value of CAS not checked */
    atomic_compare_exchange_strong(&g_counter, &expected, 1);
}

void acl07_correct(void) {
    int expected = 0;
    if (atomic_compare_exchange_strong(&g_counter, &expected, 1)) {
        /* success path */
    }
}

/* ═══════════════ ACL-08: atomic struct copied to stack ════════════ */
void acl08_demo(void) {
    struct SharedStruct local = g_shared;   /* ACL-08: non-atomic copy */
    int v = atomic_load(&local.counter);    /* operates on torn copy   */
    (void)v;
}

void acl08_correct(void) {
    /* Pass pointer to shared struct, don't copy */
    int v = atomic_load(&g_shared.counter);
    (void)v;
}

/* ═══════════════ ACL-09: fence without atomic ops ═════════════════ */
void acl09_demo(void) {
    /* ACL-09: fence in a function with no atomic load/store/RMW */
    atomic_thread_fence(memory_order_seq_cst);
    int x = 42;
    (void)x;
}

void acl09_correct(void) {
    atomic_store(&g_counter, 99);
    atomic_thread_fence(memory_order_seq_cst);  /* ok: atomic op present */
}

/* ═══════════════ ACL-06 declaration (see top) ══════════════════════ */
/* g_got_sig declared without volatile → ACL-06 fires at declaration  */

/* ═══════════════ ACL-10: atomic in signal handler ═════════════════ */
void my_signal_handler(int signo) {
    (void)signo;
    /* ACL-10: non-sig_atomic_t atomic op inside signal handler */
    atomic_store(&g_counter, 0);
    /* Correct usage in a handler: */
    g_got_sig_ok = 1;   /* volatile sig_atomic_t plain write — ok */
}

int main(void) {
    /* Register the signal handler so ACL-10 fires */
    signal(SIGINT, my_signal_handler);

    acl01_demo();
    acl01_correct();
    acl02_demo();
    acl02_correct();
    acl03_writer();
    acl03_reader();
    acl04_demo();
    acl04_correct();
    acl05_demo();
    acl07_demo();
    acl07_correct();
    acl08_demo();
    acl08_correct();
    acl09_demo();
    acl09_correct();
    return 0;
}
