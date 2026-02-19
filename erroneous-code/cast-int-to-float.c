/* test_cast_int_to_float.c
 * Triggers: castIntToFloat (CWE-681)
 * 64-bit integer → float (24-bit mantissa) loses precision.
 */
#include <stdio.h>
#include <stdint.h>

int main(void) {
    int64_t precise = (1LL << 53) + 1;   /* 2^53 + 1 */
    float  approx  = (float)precise;      /* castIntToFloat: 64→24 bit mantissa */
    printf("precise = %ld, approx = %.0f\n", precise, (double)approx);

    long big = 9999999999999L;
    float fbig = (float)big;              /* castIntToFloat */
    printf("big = %ld, fbig = %.0f\n", big, (double)fbig);

    return 0;
}
