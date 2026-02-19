/* test_cast_downcast.c
 * Triggers: castDowncastUnsafe (CWE-843)
 * Casting between unrelated struct pointers.
 */
#include <stdio.h>

struct Animal { int legs; };
struct Engine { int horsepower; };

int main(void) {
    struct Animal cat = {4};
    struct Engine *ep = (struct Engine *)&cat;  /* castDowncastUnsafe */
    printf("horsepower = %d\n", ep->horsepower);
    return 0;
}
