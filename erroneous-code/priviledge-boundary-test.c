/* pbc_test.c — exercises all 8 PBC rules */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

/* ── PBC-01: dangerous call before privilege drop ──────────────────── */
void test_pbc01(const char *path) {
    /* access() here while still root → PBC-01 */
    if (access(path, R_OK) == 0) {
        open(path, O_RDONLY);        /* also PBC-01 */
    }
    setuid(65534);                   /* privilege drop — comes too late */
}

/* ── PBC-02: unchecked setuid return ──────────────────────────────── */
void test_pbc02(void) {
    setuid(65534);                   /* PBC-02: return value discarded */
    /* correct form:
       if (setuid(65534) != 0) { perror("setuid"); exit(1); } */
}

/* ── PBC-03: reversible privilege drop via seteuid only ───────────── */
void test_pbc03(void) {
    /* only drops effective uid — saved uid remains 0 → PBC-03 */
    if (seteuid(65534) != 0) { perror("seteuid"); exit(1); }
    /* missing: setresuid(65534, 65534, 65534) to clear saved uid */
}

/* ── PBC-04: tainted path passed to exec ──────────────────────────── */
void test_pbc04(int fd) {
    char cmd[256];
    read(fd, cmd, sizeof(cmd));      /* cmd is wire-tainted */
    system(cmd);                     /* PBC-04: tainted exec argument */
}

/* ── PBC-05: unsafe tmpfile before privilege drop ─────────────────── */
void test_pbc05(void) {
    char *name = tmpnam(NULL);       /* PBC-05: inherently unsafe */
    int   fd   = open("/tmp/work.tmp", O_CREAT | O_WRONLY, 0600);
    /* ↑ PBC-05: O_EXCL missing — TOCTOU race */
    (void)fd;
    setuid(65534);
}

/* ── PBC-06: privilege drop without signal-mask bracket ───────────── */
void test_pbc06(void) {
    /* no sigprocmask before → PBC-06 */
    if (setuid(65534) != 0) { perror("setuid"); exit(1); }
    /* no sigprocmask after */
}

/* ── PBC-07: seteuid(0) re-raises capability ──────────────────────── */
void test_pbc07(void) {
    if (seteuid(65534) != 0) { perror("seteuid"); exit(1); }
    /* do unprivileged work */
    seteuid(0);                      /* PBC-07: re-raise to root */
}

/* ── PBC-08: drop then immediate re-raise ─────────────────────────── */
void test_pbc08(void) {
    seteuid(65534);                  /* drop */
    seteuid(0);                      /* PBC-08: re-acquisition 1 line later */
}

int main(void) { return 0; }
