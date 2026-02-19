/* test_cast_volatile_away.c
 * Triggers: castVolatileAway (CWE-704)
 * Removing volatile allows the compiler to optimise away reads.
 */
#include <stdio.h>

volatile int hw_register = 0xFF;

void read_hw(void) {
    int *p = (int *)&hw_register;    /* castVolatileAway */
    int val = *p;                     /* compiler may cache this */
    printf("register = %d\n", val);
}

int main(void) {
    read_hw();
    return 0;
}
