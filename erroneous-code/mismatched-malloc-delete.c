/* test_mismatched_malloc_delete.cpp — CWE-762
 * Expected: mismatchedDealloc
 * malloc/delete mismatch.
 */
#include <cstdlib>

int main() {
    int *p = (int *)malloc(sizeof(int));
    delete p;  /* BUG: malloc + delete mismatch */
    return 0;
}
