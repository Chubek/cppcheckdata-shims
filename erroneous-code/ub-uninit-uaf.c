/* test_ub_uninit_uaf.c
 * Expected findings:
 *   UB-001  line 12  variable 'delta' is used uninitialised
 *   UB-001  line 22  variable 'flag' is used uninitialised
 *   UB-002  line 31  use of pointer 'buf' after it was freed
 *   UB-002  line 40  use of pointer 'p' after it was freed
 */

#include <stdio.h>
#include <stdlib.h>

int compute(int base) {
    int delta;                  /* no initialiser */
    int result = base + delta;  /* UB-001: 'delta' read before any store */
    return result;
}

void branching(int cond) {
    int flag;                   /* no initialiser */
    if (cond > 0) {
        flag = 1;
    }
    /* UB-001: on the else path 'flag' is never assigned */
    printf("flag = %d\n", flag);
}

void after_free_simple(void) {
    char *buf = malloc(64);
    if (!buf) return;
    buf[0] = 'A';
    free(buf);
    printf("first char: %c\n", buf[0]);  /* UB-002: use after free */
}

void after_free_deref(int n) {
    int *p = malloc(n * sizeof *p);
    if (!p) return;
    p[0] = 42;
    free(p);
    int val = *p;               /* UB-002: dereference after free */
    printf("val = %d\n", val);
}

int main(void) {
    printf("compute = %d\n", compute(10));
    branching(0);
    after_free_simple();
    after_free_deref(4);
    return 0;
}
