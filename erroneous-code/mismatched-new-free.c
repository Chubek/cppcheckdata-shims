/* test_mismatched_new_free.cpp — CWE-762
 * Expected: mismatchedDealloc
 * new/free mismatch.
 */
#include <cstdlib>

int main() {
    int *p = new int(42);
    free(p);  /* BUG: new + free mismatch */
    return 0;
}
