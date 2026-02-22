/* test_ub_lifetime_const.c
 * Expected findings:
 *   UB-006  line 10  returning address of local variable 'buf'
 *   UB-006  line 19  returning address of local array 'arr'
 *   UB-006  line 28  address of local variable 'tmp' stored in 'g_ptr'
 *   UB-007  line 36  modification of const-qualified variable 'LIMIT'
 *   UB-007  line 43  casting away const and writing through the pointer
 */

#include <stdio.h>

/* UB-006: return address of local */
int *return_local_addr(void) {
    int buf = 42;
    return &buf;                    /* UB-006 */
}

/* UB-006: return local array (decays to pointer) */
char *return_local_array(void) {
    char arr[64];
    arr[0] = 'X';
    return arr;                     /* UB-006 */
}

/* UB-006: local address escapes via global pointer */
static int *g_ptr = NULL;
void escape_via_global(void) {
    int tmp = 99;
    g_ptr = &tmp;                   /* UB-006 */
}

/* UB-007: modifying a const variable */
void modify_const(void) {
    const int LIMIT = 100;
    *((int *)&LIMIT) = 200;        /* UB-007 */
    printf("LIMIT = %d\n", LIMIT);
}

/* UB-007: casting away const and writing */
void cast_away_const(const int *src) {
    int *writable = (int *)src;     /* UB-007: cast away const */
    *writable = 0;                  /* and write through it */
}

int main(void) {
    int *p = return_local_addr();
    printf("dangling: %d\n", *p);

    char *s = return_local_array();
    printf("dangling: %s\n", s);

    escape_via_global();
    printf("escaped: %d\n", *g_ptr);

    int x = 42;
    modify_const();
    cast_away_const(&x);
    return 0;
}
