/* test_02_use_after_free.c
 *
 * EXPECTED: useAfterFree (CWE-416) on printf using buf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = malloc(256);       /* ACQUIRE */
    if (!buf) return 1;

    strcpy(buf, "sensitive data");
    free(buf);                     /* RELEASE line 14 */

    /* BUG: read after free */
    printf("Data: %s\n", buf);    /* USE line 17 — CWE-416 */

    return 0;
}
