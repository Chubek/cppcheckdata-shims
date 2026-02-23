/*
 * reg_test_fd_recursion.c
 * ───────────────────────
 * Triggers:
 *   REG-03  fileDescriptorExhaustion  (line 38)
 *   REG-03  unclosedFileDescriptor    (line 57)
 *   REG-04  recursionDepthUnbounded   (line 78)
 *   REG-04  mutualRecursionTaintedDepth (lines 94, 105)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* ── REG-03 : open() in loop, close() outside loop ───────────────────── */
void scan_directory_entries(int entry_count)
{
    char path[64];

    /*
     * A new file descriptor is opened on every iteration.
     * close() is called AFTER the loop — meaning at any moment
     * up to entry_count fds are simultaneously open.
     * If entry_count is large (attacker-controlled), fd table overflows.
     */
    int fd = -1;
    for (int i = 0; i < entry_count; i++) {     /* loop starts        */
        snprintf(path, sizeof(path), "/tmp/entry_%d.dat", i);

        fd = open(path, O_RDONLY);               /* REG-03: fd in loop */
        if (fd < 0)
            continue;
        /* Process file contents … (fd not closed here) */
        char tmp[64];
        read(fd, tmp, sizeof(tmp));
        /* BUG: fd is overwritten on next iteration without close()   */
    }
    /* Only last fd is closed — all previous fds are leaked           */
    if (fd >= 0)
        close(fd);
}

/* ── REG-03 : open() result never closed in function ─────────────────── */
int get_config_fd(const char *config_path)
{
    /*
     * The caller is supposed to close() the returned fd, but this
     * function itself opens a log fd that it never closes.
     */
    int log_fd = open("/var/log/app.log", O_WRONLY | O_APPEND); /* REG-03 */
    if (log_fd >= 0) {
        const char *msg = "config opened\n";
        write(log_fd, msg, strlen(msg));
        /* BUG: log_fd is never closed — leaks one fd per call        */
    }

    return open(config_path, O_RDONLY);   /* this fd is returned (ok) */
}

/* ── REG-04 : recursive function with tainted depth ─────────────────── */
int compute_recursive(int depth, int value)
{
    /*
     * `depth` is caller-supplied and potentially tainted.
     * No base-case guard on depth before the recursive call —
     * an attacker passes depth = INT_MAX → stack overflow.
     */
    if (value == 0)
        return 0;

    /*
     * REG-04: recursive call passes `depth - 1` which is derived
     * from the tainted `depth` parameter with no upper-bound check.
     */
    return value + compute_recursive(depth - 1, value - 1); /* REG-04 */
}

/* ── REG-04 : mutual recursion cycle ─────────────────────────────────── */

/* Forward declarations */
int is_even(int n);
int is_odd(int n);

/*
 * is_even / is_odd form a mutual recursion cycle.
 * When called with a tainted `n` (from network/argv) the call
 * depth equals n — unbounded if n is attacker-controlled.
 *
 * REG-04: mutualRecursionTaintedDepth on both functions.
 */
int is_even(int n)                               /* REG-04 here        */
{
    if (n == 0) return 1;
    return is_odd(n - 1);
}

int is_odd(int n)                                /* REG-04 here        */
{
    if (n == 0) return 0;
    return is_even(n - 1);
}

/* ── Driver ───────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    /* REG-03 demo */
    scan_directory_entries(4096);

    int cfg_fd = get_config_fd("/etc/app/config");
    if (cfg_fd >= 0)
        close(cfg_fd);

    /* REG-04 demo — depth from argv (tainted) */
    int depth = (argc > 1) ? atoi(argv[1]) : 10;
    int result = compute_recursive(depth, depth);
    printf("result = %d\n", result);

    /* REG-04 mutual recursion demo — n from argv (tainted) */
    int n = (argc > 2) ? atoi(argv[2]) : 5;
    printf("%d is %s\n", n, is_even(n) ? "even" : "odd");

    return 0;
}
