/* ssl_test.c — exercise all 7 SSL rules */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

/* SSL-01: tainted buffer passed to xml deserializer */
void test_ssl01(int fd) {
    char buf[256];
    int  n = recv(fd, buf, sizeof(buf), 0);   /* buf is now tainted */
    /* xmlParseMemory(buf, n); */              /* would trigger SSL-01 */
}

/* SSL-02: tainted format string */
void test_ssl02(int fd) {
    char fmt[128];
    recv(fd, fmt, sizeof(fmt), 0);            /* fmt tainted */
    printf(fmt);                              /* SSL-02 */
}

/* SSL-03: tainted size in memcpy */
void test_ssl03(int fd, char *dst) {
    char src[512];
    int  n;
    read(fd, &n, sizeof(n));                  /* n tainted */
    n = ntohl(n);
    memcpy(dst, src, n);                      /* SSL-03 */
}

/* SSL-04: loop over tainted length without guard */
void test_ssl04(int fd) {
    int count;
    recv(fd, &count, sizeof(count), 0);       /* count tainted */
    count = ntohl(count);
    char item[8];
    for (int i = 0; i < count; i++) {         /* SSL-04: no guard before loop */
        recv(fd, item, sizeof(item), 0);
    }
}

/* SSL-05: tainted length in multiplication feeds malloc */
void test_ssl05(int fd) {
    uint32_t n;
    recv(fd, &n, sizeof(n), 0);               /* n tainted */
    n = ntohl(n);
    size_t sz = n * sizeof(int);              /* SSL-05: overflow risk */
    int   *arr = malloc(sz);
    free(arr);
}

/* SSL-06: recv with tainted size into fixed buffer */
void test_ssl06(int fd) {
    char   fixed[64];
    size_t req;
    recv(fd, &req, sizeof(req), 0);           /* req tainted */
    recv(fd, fixed, req, 0);                  /* SSL-06 */
}

/* SSL-07: malloc with tainted size */
void test_ssl07(int fd) {
    uint32_t n;
    recv(fd, &n, sizeof(n), 0);               /* n tainted */
    n = ntohl(n);
    char *buf = malloc(n);                    /* SSL-07 */
    free(buf);
}

int main(void) { return 0; }
