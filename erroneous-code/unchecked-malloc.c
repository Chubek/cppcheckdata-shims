/* test_04_unchecked_malloc.c
 *
 * EXPECTED: uncheckedReturnAssign_malloc (CWE-690)
 *           — malloc return used without NULL check
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* BUG: no NULL check */
    char *buf = malloc(64);        /* CWE-690 line 11 */

    /* If malloc returned NULL this is UB (CWE-476) */
    strcpy(buf, "oops");

    free(buf);
    return 0;
}
