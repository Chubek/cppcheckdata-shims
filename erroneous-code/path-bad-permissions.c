/*
 * bad_paths_permissions.c  —  triggers PLT-04, PLT-05
 *
 * Compile + dump:
 *   cppcheck --dump bad_paths_permissions.c
 *   python3 PathLint.py bad_paths_permissions.c.dump
 */
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/* ── PLT-04 : world-writable permission bits ─────────────────────────── */
void bad_permissions(const char *path)
{
    /* 0777 → world-writable + world-executable */
    chmod(path, 0777);                          /* PLT-04 */

    /* 0666 → world-writable */
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0666);  /* PLT-04 */
    if (fd >= 0) close(fd);

    /* setuid bit */
    chmod(path, 04755);                         /* PLT-04 */

    /* mkdir world-writable */
    mkdir("/tmp/mydir", 0777);                  /* PLT-04 */
}

/* ── PLT-05 : TOCTOU / symlink attack ───────────────────────────────── */
void toctou_open(const char *path)
{
    struct stat st;

    /* Check existence … */
    if (access(path, F_OK) == 0) {             /* sets up TOCTOU */
        /* … then open without O_NOFOLLOW — race window */
        int fd = open(path, O_RDONLY);          /* PLT-05 */
        if (fd >= 0) close(fd);
    }
}

void toctou_fopen(const char *filename)
{
    struct stat st;

    /* stat check … */
    if (stat(filename, &st) == 0) {            /* sets up TOCTOU */
        /* fopen cannot pass O_NOFOLLOW → always flagged */
        FILE *f = fopen(filename, "r");         /* PLT-05 */
        if (f) fclose(f);
    }
}

/* ── PLT-04 : hex mode literal ───────────────────────────────────────── */
void hex_bad_mode(const char *path)
{
    /* 0x1FF == 0777 octal — same dangerous bits */
    chmod(path, 0x1FF);                         /* PLT-04 */
}
