/*
 * bad_paths_traversal.c  —  triggers PLT-01, PLT-02, PLT-03, PLT-06, PLT-07
 *
 * Compile + dump:
 *   cppcheck --dump bad_paths_traversal.c
 *   python3 PathLint.py bad_paths_traversal.c.dump
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* ── PLT-01 / PLT-02 : raw argv passed to file sinks ─────────────────── */
void open_user_file(int argc, char *argv[])
{
    /* argv[1] is tainted; no sanitization */
    FILE *f = fopen(argv[1], "r");      /* PLT-01 + PLT-02 */
    if (!f) return;
    fclose(f);

    /* unlink on externally-controlled path */
    unlink(argv[1]);                    /* PLT-02 */
}

/* ── PLT-01 : hardcoded traversal literal ────────────────────────────── */
void read_passwd(void)
{
    /* literal with '..' → PLT-01 */
    FILE *f = fopen("../../etc/shadow", "r");  /* PLT-01 */
    if (f) fclose(f);
}

/* ── PLT-03 : unsafe temp-file creation ──────────────────────────────── */
void write_temp(const char *data)
{
    char *tmp = tmpnam(NULL);           /* PLT-03: unsafe */
    FILE *f   = fopen(tmp, "w");        /* PLT-03: tainted name to fopen */
    if (f) {
        fputs(data, f);
        fclose(f);
    }
}

/* ── PLT-06 : O_CREAT without O_EXCL ────────────────────────────────── */
void create_config(const char *path)
{
    /* Missing O_EXCL → not atomic */
    int fd = open(path, O_WRONLY | O_CREAT, 0644);   /* PLT-06 */
    if (fd >= 0) close(fd);

    /* creat() is never exclusive */
    int fd2 = creat(path, 0644);                      /* PLT-06 */
    if (fd2 >= 0) close(fd2);

    /* fopen "w" without "x" suffix */
    FILE *f = fopen(path, "w");                        /* PLT-06 */
    if (f) fclose(f);
}

/* ── PLT-07 : path built with snprintf, not sanitized ───────────────── */
void serve_file(const char *user_input)
{
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/var/data/%s", user_input);
    /* filepath is constructed but never passed through realpath() */
    FILE *f = fopen(filepath, "r");   /* PLT-07 */
    if (f) fclose(f);
}
