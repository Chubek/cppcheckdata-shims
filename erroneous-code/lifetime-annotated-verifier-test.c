/*
 * lav_test.c — exercise all 8 LifetimeAnnotationVerifier rules
 *
 * Compile and dump:
 *   cppcheck --dump lav_test.c
 *   python LifetimeAnnotationVerifier.py lav_test.c.dump
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* global pointer — used for LAV-02 stack escape test */
static int *g_ptr = NULL;

/* ── LAV-01: use-after-free ────────────────────────────────────────── */
void lav01_demo(void) {
    char *buf = malloc(64);
    if (!buf) return;
    buf[0] = 'A';
    free(buf);
    buf[1] = 'B';           /* LAV-01: use after free                   */
}

/* ── LAV-02: stack address escape — return ─────────────────────────── */
int *lav02a_return_local(void) {
    int x = 42;
    return &x;              /* LAV-02: address of local returned         */
}

/* ── LAV-02: stack address escape — stored in global ───────────────── */
void lav02b_store_global(void) {
    int local = 7;
    g_ptr = &local;         /* LAV-02: local address stored in global    */
}

/* ── LAV-03: double free ────────────────────────────────────────────── */
void lav03_demo(void) {
    char *p = malloc(32);
    if (!p) return;
    free(p);
    free(p);                /* LAV-03: double free                       */
}

/* ── LAV-04: use after close ────────────────────────────────────────── */
void lav04_demo(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    fclose(f);
    char buf[128];
    fread(buf, 1, sizeof(buf), f);  /* LAV-04: use after fclose         */
}

/* ── LAV-05: null deref after alloc ────────────────────────────────── */
void lav05_demo(size_t n) {
    int *arr = malloc(n * sizeof(int));
    arr[0] = 1;             /* LAV-05: no NULL check before dereference  */
    free(arr);
}

/* ── LAV-06: dangling temp address ─────────────────────────────────── */
void lav06_demo(void) {
    char *outer;
    {
        char inner[64];
        outer = inner;      /* LAV-06: inner's address outlives its scope */
    }
    outer[0] = 'x';        /* use of dangling pointer                   */
}

/* ── LAV-07: free inside loop without reassignment guard ───────────── */
typedef struct Node { struct Node *next; int val; } Node;

void lav07_demo(Node *head) {
    Node *p = head;
    while (p) {
        free(p);            /* LAV-07: p used again via p->next below    */
        p = p->next;        /* UAF: p already freed above                */
    }
}

/* ── LAV-08: pointer arithmetic overflow ───────────────────────────── */
void lav08_demo(void) {
    char *buf = malloc(8);
    if (!buf) return;
    char *end = buf + 10;   /* LAV-08: offset 10 >= allocation 8         */
    *end = 0;
    free(buf);
}

int main(void) {
    lav01_demo();
    lav02a_return_local();
    lav02b_store_global();
    lav03_demo();
    lav04_demo("/tmp/test");
    lav05_demo(16);
    lav06_demo();
    Node n = {NULL, 1};
    lav07_demo(&n);
    lav08_demo();
    return 0;
}
