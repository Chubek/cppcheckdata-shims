/*
 * reg_test_loop_alloc.c
 * ─────────────────────
 * Triggers:
 *   REG-01  resourceExhaustionLoop        (lines 33, 58)
 *   REG-02  unboundedAllocationChain      (line 43)
 *   REG-02  allocationInLoopNoFree        (line 70)
 *   REG-02  reallocInLoop                 (line 82)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── REG-01 + REG-02 : tainted loop bound + alloc inside ─────────────── */
void process_network_data(void)
{
    /*
     * `count` is read from the network — attacker controlled.
     * No upper-bound check is performed before the loop.
     */
    int count;
    read(STDIN_FILENO, &count, sizeof(count));   /* taint source */

    /* REG-01: loop bound is the tainted variable 'count'              */
    /* REG-02: malloc inside a loop whose bound is tainted             */
    for (int i = 0; i < count; i++) {           /* REG-01 here        */
        /*
         * Allocates 256 bytes on every iteration driven by 'count'.
         * If count == INT_MAX the process OOMs.
         */
        char *buf = (char *)malloc(256);         /* REG-02 here        */
        if (!buf)
            break;
        read(STDIN_FILENO, buf, 255);
        /* BUG: buf is never freed — each iteration leaks 256 bytes   */
        (void)buf;
    }
}

/* ── REG-01 : tainted loop bound, no allocation ─────────────────────── */
void spin_on_user_input(int argc, char *argv[])
{
    if (argc < 2)
        return;

    /*
     * `limit` comes from argv — another taint source.
     * The loop performs expensive work proportional to `limit`.
     */
    int limit = atoi(argv[1]);                  /* taint: atoi(argv) */
    long sum  = 0;

    /* REG-01: 'limit' is tainted, no guard before the loop           */
    for (int i = 0; i < limit; i++) {           /* REG-01 here        */
        /* Simulate expensive per-iteration work */
        for (int j = 0; j < 1000; j++)
            sum += j * i;
    }
    printf("sum = %ld\n", sum);
}

/* ── REG-02 : alloc in loop, no matching free ────────────────────────── */
void build_record_list(int n)
{
    /*
     * n is a parameter — could be tainted at the call site.
     * malloc is called on every iteration but the pointer is
     * immediately overwritten by the next iteration.
     */
    char *record = NULL;

    for (int i = 0; i < n; i++) {
        record = (char *)malloc(64);             /* REG-02: no free    */
        if (record) {
            snprintf(record, 64, "record-%d", i);
            /* record is overwritten next iteration — previous leaks  */
        }
    }
    /* Only the very last allocation survives; all others are lost     */
    free(record);
}

/* ── REG-02 : realloc inside loop ────────────────────────────────────── */
void accumulate_buffer(int chunk_count)
{
    char *buf = NULL;
    size_t total = 0;

    for (int i = 0; i < chunk_count; i++) {
        total += 128;
        buf = (char *)realloc(buf, total);       /* REG-02: reallocInLoop */
        if (!buf)
            return;
        memset(buf + total - 128, 0, 128);
    }
    free(buf);
}

int main(int argc, char *argv[])
{
    process_network_data();
    spin_on_user_input(argc, argv);
    build_record_list(100);
    accumulate_buffer(50);
    return 0;
}
