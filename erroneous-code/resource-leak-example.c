/*
 * rll_test.c — Reference test cases for ResourceLeakLint.py
 *
 * Build dump:
 *   cppcheck --dump rll_test.c
 * Run addon:
 *   python3 ResourceLeakLint.py rll_test.c.dump
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>

/* ================================================================== */
/* RLL-01 : unclosed_file_stream                                       */
/* ================================================================== */

void rll01_bad_fopen(void) {
    FILE *f = fopen("/etc/passwd", "r");  /* acquired */
    if (f == NULL) return;
    /* ... processing ... */
}                                          /* RLL-01: f never fclose'd */

void rll01_bad_popen(void) {
    FILE *p = popen("ls -la", "r");       /* acquired */
    char buf[256];
    fgets(buf, sizeof(buf), p);
}                                          /* RLL-01: p never pclose'd */

void rll01_good_fopen(void) {
    FILE *f = fopen("/etc/passwd", "r");
    if (f == NULL) return;
    /* ... processing ... */
    fclose(f);                             /* OK: properly closed */
}

void rll01_good_return(void) {
    FILE *f = fopen("/tmp/x", "w");
    return;                                /* f is returned — ESCAPED, no flag */
    /* (contrived — normally you'd return f, but escape-on-return fires) */
}

/* ================================================================== */
/* RLL-02 : unclosed_posix_fd                                          */
/* ================================================================== */

void rll02_bad_open(const char *path) {
    int fd = open(path, O_RDONLY);         /* acquired */
    if (fd < 0) return;
    char buf[128];
    read(fd, buf, sizeof(buf));
}                                          /* RLL-02: fd never close'd */

void rll02_bad_socket(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0); /* acquired */
    if (sock < 0) return;
    /* ... connect, send, recv ... */
}                                          /* RLL-02: sock never close'd */

void rll02_good_open(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    char buf[128];
    read(fd, buf, sizeof(buf));
    close(fd);                             /* OK */
}

/* ================================================================== */
/* RLL-03 : unmapped_mmap                                              */
/* ================================================================== */

void rll03_bad_mmap(int fd, size_t len) {
    void *map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) return;
    /* ... use map ... */
}                                          /* RLL-03: map never munmap'd */

void rll03_good_mmap(int fd, size_t len) {
    void *map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) return;
    /* ... use map ... */
    munmap(map, len);                      /* OK */
}

/* ================================================================== */
/* RLL-04 : unclosed_dir_handle                                        */
/* ================================================================== */

void rll04_bad_opendir(const char *path) {
    DIR *d = opendir(path);                /* acquired */
    if (d == NULL) return;
    /* ... readdir loop ... */
}                                          /* RLL-04: d never closedir'd */

void rll04_good_opendir(const char *path) {
    DIR *d = opendir(path);
    if (d == NULL) return;
    closedir(d);                           /* OK */
}

/* ================================================================== */
/* RLL-05 : undlclosed_dl_handle                                       */
/* ================================================================== */

void rll05_bad_dlopen(void) {
    void *h = dlopen("libm.so", RTLD_LAZY); /* acquired */
    if (h == NULL) return;
    /* ... dlsym calls ... */
}                                           /* RLL-05: h never dlclose'd */

void rll05_good_dlopen(void) {
    void *h = dlopen("libm.so", RTLD_LAZY);
    if (h == NULL) return;
    dlclose(h);                             /* OK */
}

/* ================================================================== */
/* RLL-06 : double_close                                               */
/* ================================================================== */

void rll06_bad_double_close(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    close(fd);
    close(fd);                             /* RLL-06: second close on same fd */
}

void rll06_bad_double_fclose(void) {
    FILE *f = fopen("/tmp/x", "w");
    if (f == NULL) return;
    fclose(f);
    fclose(f);                             /* RLL-06 */
}

/* ================================================================== */
/* RLL-07 : use_after_close                                            */
/* ================================================================== */

void rll07_bad_use_after_close(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    close(fd);
    char buf[64];
    read(fd, buf, sizeof(buf));            /* RLL-07: fd already closed */
}

void rll07_bad_use_after_fclose(void) {
    FILE *f = fopen("/tmp/x", "r");
    if (f == NULL) return;
    char buf[64];
    fclose(f);
    fgets(buf, sizeof(buf), f);            /* RLL-07: f already closed */
}

/* ================================================================== */
/* RLL-08 : leak_on_reassignment                                       */
/* ================================================================== */

void rll08_bad_reassign(void) {
    FILE *f = fopen("first.txt", "r");    /* acquired */
    f = fopen("second.txt", "r");         /* RLL-08: first handle leaked */
    if (f) fclose(f);
}

void rll08_bad_fd_reassign(const char *a, const char *b) {
    int fd = open(a, O_RDONLY);           /* acquired */
    fd = open(b, O_RDONLY);               /* RLL-08: first fd leaked */
    if (fd >= 0) close(fd);
}

void rll08_good_close_then_reassign(void) {
    FILE *f = fopen("first.txt", "r");
    fclose(f);                             /* released first */
    f = fopen("second.txt", "r");         /* OK: reassign after close */
    if (f) fclose(f);
}
