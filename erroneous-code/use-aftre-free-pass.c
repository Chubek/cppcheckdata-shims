/* test_use_after_free_pass.c — CWE-416
 * Expected: useAfterFree
 * Passing freed pointer to function.
 */
#include <stdlib.h>

void sink(int *p);

int main(void) {
    int *p = malloc(sizeof(int));
    free(p);
    sink(p);  /* BUG: passing freed pointer to function */
    return 0;
}
