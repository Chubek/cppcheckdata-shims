/*
 * euc_test.c — exercise all 8 ErrnoUsageChecker rules
 *
 * Compile and dump:
 *   cppcheck --dump euc_test.c
 *   python ErrnoUsageChecker.py euc_test.c.dump
 *
 * Expected findings: EUC-01 through EUC-08, each triggered at least once.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

/* ── EUC-08: extern int errno declaration ──────────────────────────────── */
extern int errno;          /* EUC-08: should #include <errno.h> instead    */

/* ── EUC-01: errno read before checking return value ───────────────────── */
void euc01_demo(void) {
    int fd = open("/tmp/test", O_RDONLY);
    if (errno == ENOENT) {  /* EUC-01: check fd < 0 FIRST                 */
        perror("open");
    }
    if (fd < 0) {
        close(fd);
    }
}

/* ── EUC-02: return value and errno both ignored ────────────────────────── */
void euc02_demo(int fd) {
    write(fd, "hello", 5);  /* EUC-02: neither return value nor errno     */
    close(fd);              /* EUC-02: ditto                               */
}

/* ── EUC-03: strtol without errno=0 before and without errno check after ── */
void euc03_demo(const char *s) {
    long v = strtol(s, NULL, 10);  /* EUC-03: missing errno=0 + no check  */
    printf("value: %ld\n", v);

    /* Partial fix — cleared but not checked */
    errno = 0;
    long v2 = strtol(s, NULL, 10); /* EUC-03: errno not read after        */
    printf("value2: %ld\n", v2);

    /* Partial fix — checked but not cleared first */
    long v3 = strtol(s, NULL, 10); /* EUC-03: errno not cleared before    */
    if (errno != 0) {
        fprintf(stderr, "conversion error\n");
    }
}

/* ── EUC-04: errno overwritten by intervening call ──────────────────────── */
void euc04_demo(int fd) {
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
        printf("read failed\n");  /* EUC-04: printf may clobber errno      */
        fprintf(stderr, "errno: %d\n", errno);
    }
}

/* ── EUC-05: errno compared to negative value ───────────────────────────── */
void euc05_demo(void) {
    int fd = open("/tmp/x", O_RDONLY);
    if (fd < 0) {
        if (errno == -1) {        /* EUC-05: errno is always non-negative  */
            fprintf(stderr, "impossible\n");
        }
        if (errno < 0) {          /* EUC-05: also always false             */
            fprintf(stderr, "also impossible\n");
        }
    }
}

/* ── EUC-06: errno used as boolean ─────────────────────────────────────── */
void euc06_demo(int fd) {
    read(fd, NULL, 0);
    if (errno) {               /* EUC-06: don't use errno as boolean       */
        perror("read");
    }
    return errno;              /* EUC-06: returning errno as status code   */
}

/* ── EUC-07: strerror() not thread-safe ────────────────────────────────── */
void euc07_demo(void) {
    int fd = open("/tmp/nope", O_RDONLY);
    if (fd < 0) {
        /* EUC-07: strerror() not thread-safe                              */
        fprintf(stderr, "error: %s\n", strerror(errno));
    }
}

/* ── EUC-08: &errno (address of errno) ─────────────────────────────────── */
void euc08_demo(void) {
    int *ep = &errno;          /* EUC-08: non-portable address-of errno    */
    *ep = 0;
}

int main(void) {
    euc01_demo();
    euc02_demo(1);
    euc03_demo("123abc");
    euc04_demo(0);
    euc05_demo();
    euc06_demo(0);
    euc07_demo();
    euc08_demo();
    return 0;
}
