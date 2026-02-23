/*
 * bad_memory_c.c  —  triggers PLT-01, PLT-02, PLT-03
 *
 * Build & dump:
 *   cppcheck --dump bad_memory_c.c
 *   python3 PointerLifetimeTracker.py bad_memory_c.dump
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Fake GLib-style ref-count API for PLT-03 test */
typedef struct { int ref; } GObject;
void g_object_ref(GObject *o)   { o->ref++; }
void g_object_unref(GObject *o) { o->ref--; }

/* ── PLT-01 : malloc never freed ──────────────────────────────────── */
void leak_simple(void)
{
    /* 'buffer' is allocated but there is no free(buffer) anywhere */
    char *buffer = malloc(256);
    if (!buffer) return;
    memset(buffer, 0, 256);
    /* BUG: no free(buffer) */
}

/* ── PLT-01 : strdup result leaked ───────────────────────────────── */
char *leak_strdup(const char *src)
{
    char *copy = strdup(src);
    /* copy returned — ownership transferred; NOT a leak.
       But the second allocation below IS leaked. */
    char *tmp = strdup("scratch");      /* PLT-01: tmp never freed */
    return copy;
}

/* ── PLT-02 : new allocated, free() called ───────────────────────── */
/* NOTE: This file is .c so 'new' would be a syntax error.
   This function is intentionally omitted here; see bad_memory_cpp.cpp */

/* ── PLT-02 : mmap / free mismatch ──────────────────────────────── */
#include <sys/mman.h>
void mismatch_mmap(size_t sz)
{
    void *region = mmap(NULL, sz,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
    if (region == MAP_FAILED) return;
    /* BUG: should be munmap(region, sz), not free */
    free(region);                       /* PLT-02 */
}

/* ── PLT-03 : ref count incremented, never decremented ───────────── */
void ref_leak(GObject *obj)
{
    g_object_ref(obj);      /* PLT-03: no g_object_unref anywhere */
    printf("using obj\n");
    /* BUG: g_object_unref(obj) missing */
}

/* ── PLT-03 : increment balanced by decrement (no warning) ──────── */
void ref_ok(GObject *obj)
{
    g_object_ref(obj);
    printf("using obj\n");
    g_object_unref(obj);   /* balanced — no warning */
}

/* ── PLT-01 : calloc leaked on early return ──────────────────────── */
int process_data(size_t n)
{
    int *data = calloc(n, sizeof(int));
    if (!data) return -1;

    if (n == 0) {
        return 0;           /* PLT-01: data leaked on this path */
    }

    data[0] = 42;
    free(data);
    return 0;
}
