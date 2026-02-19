/* test_double_free.c — CWE-415
 * Expected: doubleFree
 * Memory freed twice.
 */
#include <stdlib.h>

int main(void) {
    int *p = malloc(10 * sizeof(int));
    free(p);
    free(p);  /* BUG: double free */
    return 0;
}
