/*
 * cbc_test.c — exercise cases for CompilerBarrierChecker.py
 *
 * Build dump:  cppcheck --dump cbc_test.c
 * Run addon:   python3 CompilerBarrierChecker.py cbc_test.c.dump
 *
 * Lines marked EXPECT_CBC-XX should fire that checker.
 * Lines marked CLEAN should produce no finding.
 */

#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <pthread.h>

/* Shared globals used by multiple tests */
static int        g_shared   = 0;
static int        g_flag     = 0;
volatile uint32_t g_mmio_a;
volatile uint32_t g_mmio_b;

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * CBC-01  missing_compiler_barrier
 * ===================================================================== */
void cbc01_bad(void) {
    volatile int status = 0;
    /* EXPECT_CBC-01: volatile write then non-volatile global load, no barrier */
    status   = 1;
    int snap = g_shared;   /* compiler may hoist this above the write */
    (void)snap;
}

void cbc01_good(void) {
    volatile int status = 0;
    status = 1;
    /* CLEAN: barrier protects the load */
    __asm__ volatile("" ::: "memory");
    int snap = g_shared;
    (void)snap;
}

/* =========================================================================
 * CBC-02  mmio_write_without_barrier
 * ===================================================================== */
void cbc02_bad(void) {
    volatile uint32_t *reg_a = (volatile uint32_t *)0x40020000;
    volatile uint32_t *reg_b = (volatile uint32_t *)0x40020004;

    /* EXPECT_CBC-02: two consecutive MMIO writes, no barrier */
    *reg_a = 0x01;
    *reg_b = 0xFF;
}

void cbc02_good(void) {
    volatile uint32_t *reg_a = (volatile uint32_t *)0x40020000;
    volatile uint32_t *reg_b = (volatile uint32_t *)0x40020004;
    /* CLEAN: barrier between writes */
    *reg_a = 0x01;
    __asm__ volatile("" ::: "memory");
    *reg_b = 0xFF;
}

/* =========================================================================
 * CBC-03  lock_without_barrier_pair
 * ===================================================================== */
void cbc03_bad(void) {
    pthread_mutex_lock(&g_mutex);
    /* EXPECT_CBC-03: store to non-atomic global after lock, no barrier */
    g_shared = 42;
    pthread_mutex_unlock(&g_mutex);
}

void cbc03_good(void) {
    pthread_mutex_lock(&g_mutex);
    /* CLEAN: acquire barrier after lock */
    __asm__ volatile("" ::: "memory");
    g_shared = 42;
    pthread_mutex_unlock(&g_mutex);
}

/* =========================================================================
 * CBC-04  signal_handler_nonvolatile
 * ===================================================================== */
static int non_vol_flag = 0;       /* not volatile, not sig_atomic_t */
static volatile sig_atomic_t safe_flag = 0;

void bad_handler(int sig) {
    (void)sig;
    /* EXPECT_CBC-04: writing non-volatile non-sig_atomic_t from handler */
    non_vol_flag = 1;
}

void good_handler(int sig) {
    (void)sig;
    /* CLEAN */
    safe_flag = 1;
}

void cbc04_setup(void) {
    signal(SIGUSR1, bad_handler);
    signal(SIGUSR2, good_handler);
}

/* =========================================================================
 * CBC-05  barrier_in_wrong_order
 * ===================================================================== */
void cbc05_bad(void) {
    int x = g_shared;            /* load */
    /* EXPECT_CBC-05: barrier AFTER load, BEFORE store — wrong order */
    __asm__ volatile("" ::: "memory");
    g_shared = x + 1;            /* store */
}

void cbc05_good(void) {
    /* CLEAN: barrier before the load */
    __asm__ volatile("" ::: "memory");
    int x = g_shared;
    g_shared = x + 1;
}

/* =========================================================================
 * CBC-06  missing_release_barrier
 * ===================================================================== */
void cbc06_bad(void) {
    pthread_mutex_lock(&g_mutex);
    /* EXPECT_CBC-06: store immediately before unlock, no release barrier */
    g_shared = 99;
    pthread_mutex_unlock(&g_mutex);
}

void cbc06_good(void) {
    pthread_mutex_lock(&g_mutex);
    g_shared = 99;
    /* CLEAN: release barrier before unlock */
    __asm__ volatile("" ::: "memory");
    pthread_mutex_unlock(&g_mutex);
}

/* =========================================================================
 * CBC-07  double_barrier
 * ===================================================================== */
void cbc07_bad(void) {
    __asm__ volatile("" ::: "memory");
    /* EXPECT_CBC-07: second barrier with no intervening memory op */
    __asm__ volatile("" ::: "memory");
    g_shared = 1;
}

void cbc07_good(void) {
    __asm__ volatile("" ::: "memory");
    /* CLEAN: memory operation between barriers */
    g_shared = 1;
    __asm__ volatile("" ::: "memory");
}

/* =========================================================================
 * CBC-08  barrier_after_return
 * ===================================================================== */
int cbc08_bad(void) {
    int v = g_shared;
    return v;
    /* EXPECT_CBC-08: unreachable barrier after return */
    __asm__ volatile("" ::: "memory");
}

int cbc08_good(void) {
    /* CLEAN: barrier before return */
    __asm__ volatile("" ::: "memory");
    return g_shared;
}

/* =========================================================================
 * CBC-09  nonvolatile_mmio_pointer
 * ===================================================================== */
void cbc09_bad(void) {
    /* EXPECT_CBC-09: MMIO pointer not volatile-qualified */
    uint32_t *gpio = (uint32_t *)0x40020000;
    *gpio = 0xFF;
}

void cbc09_good(void) {
    /* CLEAN: correctly volatile-qualified */
    volatile uint32_t *gpio = (volatile uint32_t *)0x40020000;
    *gpio = 0xFF;
}

/* =========================================================================
 * CBC-10  setjmp_barrier_missing
 * ===================================================================== */
static jmp_buf g_jmp;

void cbc10_bad(void) {
    int counter = 0;   /* EXPECT_CBC-10: modified after setjmp, not volatile */
    if (setjmp(g_jmp) == 0) {
        counter++;     /* value indeterminate on longjmp */
    }
    (void)counter;
}

void cbc10_good(void) {
    volatile int counter = 0;   /* CLEAN: volatile-qualified */
    if (setjmp(g_jmp) == 0) {
        counter++;
    }
    (void)counter;
}
