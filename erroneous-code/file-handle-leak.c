/* test_08_file_leak.c
 *
 * EXPECTED: resourceLeak (CWE-401) — fp never closed
 *           uncheckedReturnAssign_fopen (CWE-252) — no NULL check
 */
#include <stdio.h>

int main(void) {
    FILE *fp = fopen("/tmp/test.txt", "w");  /* ACQUIRE line 9 */

    /* BUG 1: no NULL check on fopen (CWE-252) */
    fprintf(fp, "Hello, world!\n");

    /* BUG 2: file handle never closed (CWE-401) */
    return 0;
}
