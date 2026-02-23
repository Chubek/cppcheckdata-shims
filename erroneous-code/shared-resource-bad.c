/*
 * concurrency_bad.c
 *
 * PURPOSE: Trigger as many SharedResourceValidator checks as possible.
 *
 * Expected violations:
 *   SRV-01  RaceConditionChecker       — g_counter accessed without lock
 *   SRV-02  TOCTOURaceChecker          — access() then open() on same path
 *   SRV-03  MutexMisuseChecker         — double-lock, unlock without lock,
 *                                         lock-leak
 *   SRV-04  DeadlockChecker            — lock-order inversion (A→B vs B→A)
 *   SRV-05  LockHierarchyChecker       — acquire high-priority while holding
 *                                         low-priority
 *   SRV-06  UnprotectedSharedWriteChecker — write to shared var without lock
 *   SRV-07  NonAtomicRMWChecker        — ++ on shared var without lock/atomic
 *   SRV-08  DataRaceChecker            — concurrent read+write, disjoint locks
 *   SRV-09  SignalHandlerSafetyChecker — unsafe calls inside signal handler
 *
 * Compile (for analysis only — not meant to run correctly):
 *   cppcheck --dump concurrency_bad.c
 *   python SharedResourceValidator.py concurrency_bad.c.dump
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

/* ─────────────────────────────────────────────────────────────────────────
 * Shared (global) variables — heuristically identified by the addon via
 * g_ / s_ / shared_ prefixes and global scope.
 * ───────────────────────────────────────────────────────────────────────── */
static int    g_counter   = 0;          /* SRV-01, SRV-06, SRV-07, SRV-08 */
static double g_balance   = 0.0;        /* SRV-06, SRV-08                  */
static char   shared_buf[256];          /* SRV-06                          */

/* Two mutexes — declared in this order, so:
 *   mutex_A has higher priority (lower line number)
 *   mutex_B has lower  priority
 * Acquiring B then A violates hierarchy  →  SRV-05
 */
static pthread_mutex_t mutex_A = PTHREAD_MUTEX_INITIALIZER;   /* line ~38 */
static pthread_mutex_t mutex_B = PTHREAD_MUTEX_INITIALIZER;   /* line ~39 */


/* ═══════════════════════════════════════════════════════════════════════════
 * SRV-01 / SRV-06 / SRV-07  —  unprotected accesses to g_counter
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * increment_unprotected()
 *
 * Reads and writes g_counter with NO lock held.
 * The ++ operator is a non-atomic read-modify-write → SRV-07.
 * The bare write    is an unprotected shared write  → SRV-06.
 * The bare access   inside a thread               → SRV-01.
 */
void increment_unprotected(void)
{
    g_counter++;                /* SRV-07: non-atomic RMW, no lock          */
    g_counter += 10;            /* SRV-07: compound assignment               */
    g_counter  = g_counter * 2; /* SRV-06: unprotected write                */
}

/*
 * read_balance_unprotected()
 *
 * Reads g_balance from one thread while another thread writes it.
 * No lock — different "lock set" than the writer → SRV-08.
 */
double read_balance_unprotected(void)
{
    return g_balance;           /* SRV-08: read with empty lock set          */
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SRV-03  —  mutex misuse: double-lock, unlock-without-lock, lock-leak
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * double_lock_example()
 *
 * Locks mutex_A twice without unlocking in between on a
 * non-recursive mutex → SRV-03 (double-lock).
 */
void double_lock_example(void)
{
    pthread_mutex_lock(&mutex_A);   /* first acquire — OK                    */
    /* … some work … */
    pthread_mutex_lock(&mutex_A);   /* SRV-03: double-lock (deadlock risk)   */
    g_counter = 1;
    pthread_mutex_unlock(&mutex_A);
    /* Second unlock missing — but at least one is here.                     */
}

/*
 * unlock_without_lock()
 *
 * Calls unlock without a matching prior lock → SRV-03.
 */
void unlock_without_lock(void)
{
    pthread_mutex_unlock(&mutex_B); /* SRV-03: unlock without lock           */
    g_balance = 99.9;
}

/*
 * lock_leak_example()
 *
 * Acquires mutex_B but never releases it → SRV-03 (lock-leak).
 */
void lock_leak_example(void)
{
    pthread_mutex_lock(&mutex_B);   /* acquired …                            */
    strcpy(shared_buf, "hello");    /* SRV-06: write under WRONG lock scope  */
    /* function returns without unlock → SRV-03: lock-leak                  */
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SRV-04  —  lock-order inversion leading to deadlock
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * thread_func_A()
 *
 * Acquires:  mutex_A  →  mutex_B   (order: A before B)
 */
void *thread_func_A(void *arg)
{
    pthread_mutex_lock(&mutex_A);           /* acquire A first               */
    pthread_mutex_lock(&mutex_B);           /* then B   — order: A → B       */

    g_counter++;
    g_balance = (double)g_counter;

    pthread_mutex_unlock(&mutex_B);
    pthread_mutex_unlock(&mutex_A);
    return NULL;
}

/*
 * thread_func_B()
 *
 * Acquires:  mutex_B  →  mutex_A   (order: B before A)
 *
 * This is the INVERSE of thread_func_A → SRV-04 deadlock.
 */
void *thread_func_B(void *arg)
{
    pthread_mutex_lock(&mutex_B);           /* acquire B first               */
    pthread_mutex_lock(&mutex_A);           /* then A   — INVERTED: B → A   */
                                            /* SRV-04: lock-order inversion  */
    g_counter--;
    g_balance = (double)g_counter;

    pthread_mutex_unlock(&mutex_A);
    pthread_mutex_unlock(&mutex_B);
    return NULL;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SRV-05  —  lock-hierarchy violation
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * hierarchy_violation()
 *
 * mutex_A is declared BEFORE mutex_B, so it has higher priority.
 * Acquiring mutex_A while already holding mutex_B violates the
 * declaration-order hierarchy → SRV-05.
 */
void hierarchy_violation(void)
{
    pthread_mutex_lock(&mutex_B);       /* acquire lower-priority lock first */
    /* … */
    pthread_mutex_lock(&mutex_A);       /* SRV-05: acquire higher-priority   */
                                        /* while holding lower-priority       */
    g_counter = 42;
    pthread_mutex_unlock(&mutex_A);
    pthread_mutex_unlock(&mutex_B);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SRV-02  —  TOCTOU race on a file path
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * toctou_file_example()
 *
 * Checks whether a file exists with access(), then opens it with open().
 * Between the two calls, another process could replace the file
 * (classic TOCTOU / symlink race) → SRV-02.
 *
 * No mutex guards the check-then-use sequence.
 */
void toctou_file_example(const char *path)
{
    if (access(path, R_OK) == 0)    /* CHECK  — SRV-02 (time of check)       */
    {
        int fd = open(path, O_RDONLY); /* USE — SRV-02 (time of use)          */
        if (fd >= 0)
        {
            char buf[128];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
    }
}

/*
 * toctou_stat_unlink()
 *
 * Uses stat() to verify existence, then unlink()s — another TOCTOU → SRV-02.
 */
void toctou_stat_unlink(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)       /* CHECK  — SRV-02                       */
    {
        unlink(path);               /* USE    — SRV-02                        */
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SRV-08  —  data race (disjoint lock sets, concurrent read + write)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * write_with_mutex_A()
 *
 * Writes g_balance while holding mutex_A.
 * Lock set = {mutex_A}.
 */
void write_with_mutex_A(double v)
{
    pthread_mutex_lock(&mutex_A);
    g_balance = v;                  /* write: lock set {A}                   */
    pthread_mutex_unlock(&mutex_A);
}

/*
 * read_with_mutex_B()
 *
 * Reads g_balance while holding mutex_B.
 * Lock set = {mutex_B}  ≠  {mutex_A}  → SRV-08: disjoint lock sets.
 */
double read_with_mutex_B(void)
{
    double v;
    pthread_mutex_lock(&mutex_B);
    v = g_balance;                  /* read:  lock set {B} — SRV-08          */
    pthread_mutex_unlock(&mutex_B);
    return v;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SRV-09  —  signal handler calling async-signal-unsafe functions
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * unsafe_signal_handler()
 *
 * Registered as a SIGINT handler via signal() below.
 * Calls printf, malloc, pthread_mutex_lock — all async-signal-unsafe
 * → SRV-09 for each unsafe call.
 */
void unsafe_signal_handler(int signum)
{
    printf("Caught signal %d\n", signum); /* SRV-09: printf is unsafe        */

    void *tmp = malloc(64);               /* SRV-09: malloc is unsafe        */
    if (tmp) free(tmp);                   /* SRV-09: free is unsafe          */

    pthread_mutex_lock(&mutex_A);         /* SRV-09: mutex ops are unsafe    */
    g_counter = 0;
    pthread_mutex_unlock(&mutex_A);       /* SRV-09: mutex ops are unsafe    */
}

/*
 * another_unsafe_handler()
 *
 * Registered via sigaction sa_handler.
 * Calls fprintf and exit — fprintf is unsafe, exit is debatable but
 * many implementations flag it.
 */
void another_unsafe_handler(int signum)
{
    fprintf(stderr, "Fatal signal\n");    /* SRV-09: fprintf is unsafe        */
    exit(1);                              /* SRV-09: exit may be flagged       */
}


/* ═══════════════════════════════════════════════════════════════════════════
 * main() — wire everything together for the analyser to see call-graph edges
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    /* Register signal handlers — addon discovers these as handler functions */
    signal(SIGINT,  unsafe_signal_handler);   /* SRV-09 trigger              */

    struct sigaction sa;
    sa.sa_handler = another_unsafe_handler;   /* SRV-09 trigger (sa_handler) */
    sigaction(SIGTERM, &sa, NULL);

    /* Spawn threads that will race */
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_func_A, NULL);
    pthread_create(&t2, NULL, thread_func_B, NULL);   /* SRV-04 lock inversion */

    /* Demonstrate unprotected accesses */
    increment_unprotected();    /* SRV-01 / SRV-06 / SRV-07                  */
    read_balance_unprotected(); /* SRV-08                                     */

    /* Demonstrate mutex misuse */
    double_lock_example();      /* SRV-03                                     */
    unlock_without_lock();      /* SRV-03                                     */
    lock_leak_example();        /* SRV-03                                     */

    /* Demonstrate hierarchy violation */
    hierarchy_violation();      /* SRV-05                                     */

    /* Demonstrate TOCTOU */
    if (argc > 1)
    {
        toctou_file_example(argv[1]);   /* SRV-02                             */
        toctou_stat_unlink(argv[1]);    /* SRV-02                             */
    }

    /* Demonstrate disjoint-lock-set data race */
    write_with_mutex_A(3.14);   /* SRV-08 (writer)                            */
    read_with_mutex_B();        /* SRV-08 (reader, disjoint lock set)          */

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    return 0;
}
