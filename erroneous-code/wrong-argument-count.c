/* test_07_wrong_arg_count.c
 *
 * EXPECTED: wrongArgCount_memcpy (CWE-628)
 * NOTE: This would be a compile error in strict mode, but some
 *       compilers with disabled warnings or macros may allow it.
 *       The checker flags it at the semantic level.
 */
#include <string.h>

/* Simulate a macro that expands incorrectly */
#define BROKEN_COPY(d, s) memcpy(d, s)

int main(void) {
    char dst[32];
    char src[] = "test";

    /* BUG: memcpy needs 3 args, macro supplies only 2 */
    BROKEN_COPY(dst, src);         /* CWE-628 line 17 */

    return 0;
}
