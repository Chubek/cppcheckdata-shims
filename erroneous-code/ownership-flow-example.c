/*
 * oft_test.c — Reference test cases for OwnershipFlowTracker.py
 *
 * Compile + generate dump:
 *   cppcheck --dump oft_test.c
 * Run addon:
 *   python3 OwnershipFlowTracker.py oft_test.c.dump
 */

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* OFT-01 : double_free_on_same_path                                  */
/* ------------------------------------------------------------------ */
void oft01_bad(void) {
    char *p = malloc(64);
    free(p);
    free(p);   /* OFT-01: double free */
}

void oft01_good(void) {
    char *p = malloc(64);
    free(p);
    p = malloc(64);   /* reassigned — next free is valid */
    free(p);
}

/* ------------------------------------------------------------------ */
/* OFT-02 : use_after_free_deref                                      */
/* ------------------------------------------------------------------ */
void oft02_bad(void) {
    int *p = malloc(sizeof(int));
    free(p);
    *p = 42;   /* OFT-02: use after free */
}

void oft02_good(void) {
    int *p = malloc(sizeof(int));
    *p = 42;
    free(p);
}

/* ------------------------------------------------------------------ */
/* OFT-03 : mismatched_alloc_free                                     */
/* ------------------------------------------------------------------ */
void oft03_bad(void) {
    int *p = (int *)malloc(sizeof(int));
    /* delete p; */           /* would be flagged in C++ */
    free(p);                  /* correct in C — no mismatch expected here */
}

/* ------------------------------------------------------------------ */
/* OFT-04 : free_of_stack_address                                     */
/* ------------------------------------------------------------------ */
void oft04_bad(void) {
    int x = 5;
    free(&x);     /* OFT-04: stack address passed to free */
}

void oft04_bad_array(void) {
    char buf[64];
    free(buf);    /* OFT-04: stack array passed to free */
}

void oft04_good(void) {
    char *p = malloc(64);
    free(p);
}

/* ------------------------------------------------------------------ */
/* OFT-05 : ownership_escaped_without_nulling                         */
/* ------------------------------------------------------------------ */
void take_buffer(char *buf);  /* transfer-semantic callee */

void oft05_bad(void) {
    char *p = malloc(64);
    take_buffer(p);    /* ownership transferred */
    p[0] = 'x';       /* OFT-05: use after transfer */
}

void oft05_good(void) {
    char *p = malloc(64);
    take_buffer(p);
    p = NULL;          /* nulled — safe */
}

/* ------------------------------------------------------------------ */
/* OFT-06 : conditional_free_then_use                                 */
/* ------------------------------------------------------------------ */
void oft06_bad(int cond) {
    char *p = malloc(64);
    if (cond) {
        free(p);
    }
    p[0] = 'x';    /* OFT-06: use without NULL check after conditional free */
}

void oft06_good(int cond) {
    char *p = malloc(64);
    if (cond) {
        free(p);
        p = NULL;
    }
    if (p != NULL) {
        p[0] = 'x';
    }
}

/* ------------------------------------------------------------------ */
/* OFT-07 : realloc_original_lost                                     */
/* ------------------------------------------------------------------ */
void oft07_bad(void) {
    char *p = malloc(64);
    p = realloc(p, 128);  /* OFT-07: original lost if realloc returns NULL */
}

void oft07_good(void) {
    char *p = malloc(64);
    char *tmp = realloc(p, 128);
    if (tmp) {
        p = tmp;
    }
    free(p);
}

/* ------------------------------------------------------------------ */
/* OFT-08 : alloc_in_loop_no_free                                     */
/* ------------------------------------------------------------------ */
void oft08_bad(int n) {
    char *p = NULL;
    for (int i = 0; i < n; i++) {
        p = malloc(64);   /* OFT-08: previous p leaked on next iteration */
        p[0] = (char)i;
    }
    free(p);
}

void oft08_good(int n) {
    for (int i = 0; i < n; i++) {
        char *p = malloc(64);
        p[0] = (char)i;
        free(p);           /* freed in same loop body — clean */
    }
}
