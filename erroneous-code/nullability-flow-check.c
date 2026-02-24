/* nfc_test.c  –  Reference test cases for NullabilityFlowChecker.py
 *
 * Compile (for syntax check only):
 *   gcc -std=c11 -fsyntax-only -Wall -Wextra nfc_test.c
 *
 * Run addon:
 *   cppcheck --addon=NullabilityFlowChecker.py --enable=all nfc_test.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* ===== NFC-01: unchecked dereference ===================================== */

int nfc01_bad(void)
{
    int *p = malloc(sizeof(int));   /* p is MAYBE_NULL */
    *p = 42;                        /* NFC-01: deref without null check */
    return *p;
}

int nfc01_good(void)
{
    int *p = malloc(sizeof(int));
    if (p == NULL) return -1;       /* null guard clears MAYBE_NULL */
    *p = 42;                        /* safe */
    return *p;
}

/* ===== NFC-02: null dereference inside null branch ======================= */

void nfc02_bad(int *p)
{
    if (p == NULL) {
        *p = 0;                     /* NFC-02: p is known NULL here */
    }
}

void nfc02_good(int *p)
{
    if (p != NULL) {
        *p = 0;                     /* safe: p is NON_NULL here */
    }
}

/* ===== NFC-03: null passed to nonnull parameter ========================== */

extern void requires_ptr(int *__attribute__((nonnull)) p);

void nfc03_bad(void)
{
    requires_ptr(NULL);             /* NFC-03 */
}

void nfc03_good(void)
{
    int x = 5;
    requires_ptr(&x);               /* safe */
}

/* ===== NFC-04: nullable return value not stored / not checked ============ */

void nfc04_bad(void)
{
    malloc(64);                     /* NFC-04: result discarded */
}

/* ===== NFC-05: double null check ========================================= */

void nfc05_bad(int *p)
{
    if (p == NULL) { return; }
    if (p == NULL) { return; }     /* NFC-05: redundant, p is NON_NULL */
}

/* ===== NFC-06: pointer arithmetic on nullable pointer ==================== */

void nfc06_bad(void)
{
    char *buf = malloc(32);         /* MAYBE_NULL */
    char *q   = buf + 4;           /* NFC-06: arithmetic on MAYBE_NULL */
    (void)q;
}

void nfc06_good(void)
{
    char *buf = malloc(32);
    if (!buf) return;
    char *q = buf + 4;             /* safe */
    (void)q;
}

/* ===== NFC-07: getenv unchecked ========================================== */

void nfc07_bad(void)
{
    char *home = getenv("HOME");   /* MAYBE_NULL */
    printf("Home: %s\n", home);   /* NFC-07 and NFC-09 */
}

void nfc07_good(void)
{
    char *home = getenv("HOME");
    if (home == NULL) home = "/tmp";
    printf("Home: %s\n", home);   /* safe */
}

/* ===== NFC-08: realloc null stomp ======================================== */

void nfc08_bad(void)
{
    char *buf = malloc(64);
    if (!buf) return;
    buf = realloc(buf, 128);       /* NFC-08: original buf lost on failure */
    free(buf);
}

void nfc08_good(void)
{
    char *buf = malloc(64);
    if (!buf) return;
    char *tmp = realloc(buf, 128); /* safe: use temporary */
    if (!tmp) { free(buf); return; }
    buf = tmp;
    free(buf);
}

/* ===== NFC-09: null passed as %s to printf =============================== */

void nfc09_bad(void)
{
    char *s = getenv("UNDEFINED_VAR");   /* MAYBE_NULL */
    printf("Value: %s\n", s);           /* NFC-09 */
}

void nfc09_good(void)
{
    char *s = getenv("UNDEFINED_VAR");
    if (!s) s = "(none)";
    printf("Value: %s\n", s);           /* safe */
}

/* ===== NFC-10: deref after free ========================================== */

void nfc10_bad(void)
{
    int *p = malloc(sizeof(int));
    if (!p) return;
    *p = 1;
    free(p);
    *p = 2;                             /* NFC-10: use after free */
}

void nfc10_good(void)
{
    int *p = malloc(sizeof(int));
    if (!p) return;
    *p = 1;
    free(p);
    p = NULL;                           /* safe: nulled after free */
}

/* ===== Compound / real-world patterns ==================================== */

typedef struct { int val; } Node;

Node *create_node(int v)
{
    Node *n = malloc(sizeof(Node));
    if (!n) return NULL;
    n->val = v;                         /* safe */
    return n;
}

void use_node_bad(void)
{
    Node *n = create_node(5);
    /* NFC-01: n could be NULL (malloc inside create_node may fail) */
    printf("val=%d\n", n->val);
}

void use_node_good(void)
{
    Node *n = create_node(5);
    if (!n) return;
    printf("val=%d\n", n->val);        /* safe */
}

/* ===== fopen nullable return ============================================= */

void fopen_bad(const char *path)
{
    FILE *f = fopen(path, "r");        /* MAYBE_NULL */
    fread(NULL, 1, 64, f);             /* NFC-01 */
    fclose(f);
}

void fopen_good(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char buf[64];
    fread(buf, 1, 64, f);              /* safe */
    fclose(f);
}

int main(void) { return 0; }
