/* test_ub_aliasing_align_cast.c
 * Expected findings:
 *   UB-003  line 14  casting 'int *' to 'float *' violates strict-aliasing
 *   UB-003  line 22  casting 'double *' to 'long *' violates strict-aliasing
 *   UB-004  line 30  casting 'char *' to 'int *' may cause misaligned access
 *   UB-004  line 37  casting 'unsigned char *' to 'double *' may cause misaligned access
 *   UB-005  line 44  casting pointer to 'int' truncates the pointer value
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* UB-003: strict-aliasing violation — int and float are not compatible */
void alias_int_float(void) {
    int x = 0x3F800000;
    float *fp = (float *)&x;       /* UB-003 */
    printf("reinterpreted: %f\n", *fp);
}

/* UB-003: strict-aliasing violation — double and long */
void alias_double_long(void) {
    double d = 3.14;
    long *lp = (long *)&d;         /* UB-003 */
    printf("bits: %lx\n", *lp);
}

/* UB-004: misaligned access — char* → int* */
void misaligned_int(void) {
    char buffer[32];
    buffer[1] = 0;
    int *ip = (int *)(buffer + 1);  /* UB-004: offset 1 is not 4-aligned */
    printf("value: %d\n", *ip);
}

/* UB-004: misaligned access — uint8_t* → double* */
void misaligned_double(void) {
    unsigned char raw[64];
    double *dp = (double *)(raw + 3); /* UB-004 */
    *dp = 1.0;
    printf("value: %f\n", *dp);
}

/* UB-005: pointer to narrower integer — truncation on 64-bit */
void ptr_to_int(void) {
    int x = 42;
    int addr = (int)&x;            /* UB-005: pointer truncated to 32-bit int */
    printf("addr: %d\n", addr);
}

int main(void) {
    alias_int_float();
    alias_double_long();
    misaligned_int();
    misaligned_double();
    ptr_to_int();
    return 0;
}
