/* test_ub_shift_overflow.c
 * Expected findings:
 *   UB-008  line 12  shifting 'int' (32 bits) by 32 is undefined behaviour
 *   UB-008  line 16  shifting by negative amount (-1) is undefined behaviour
 *   UB-008  line 20  left-shifting negative value (-1) is undefined behaviour
 *   UB-009  line 27  signed integer overflow: 2147483647 + 1 = 2147483648
 *   UB-009  line 32  negating the minimum value of 'int' is signed overflow
 *   UB-009  line 37  dividing minimum value (-2147483648) by -1 overflows 'int'
 */

#include <stdio.h>
#include <limits.h>

void shift_too_far(void) {
    int x = 1;
    int y = x << 32;               /* UB-008: shift >= width */
    printf("%d\n", y);

    int a = 10;
    int b = a >> (-1);             /* UB-008: negative shift */
    printf("%d\n", b);

    int c = -1;
    int d = c << 2;                /* UB-008: left-shift of negative */
    printf("%d\n", d);
}

void overflow_add(void) {
    int max = INT_MAX;
    /* UB-009: INT_MAX + 1 wraps — undefined for signed int */
    int boom = max + 1;
    printf("%d\n", boom);
}

void overflow_negate(void) {
    int min = INT_MIN;
    int neg = -min;                /* UB-009: -INT_MIN overflows */
    printf("%d\n", neg);
}

void overflow_div(void) {
    int min = INT_MIN;
    int result = min / (-1);       /* UB-009: INT_MIN / -1 overflows */
    printf("%d\n", result);
}

int main(void) {
    shift_too_far();
    overflow_add();
    overflow_negate();
    overflow_div();
    return 0;
}
