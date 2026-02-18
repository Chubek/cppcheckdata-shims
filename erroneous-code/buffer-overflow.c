/*
 * test_heap_overflow.c
 * ====================
 * Exercises CWE-122, CWE-124, CWE-125, CWE-131, CWE-805, CWE-806.
 *
 * EXPECTED FINDINGS:
 *   Line 17:  CWE-131  — malloc(count) without * sizeof(int)
 *   Line 20:  CWE-122  — heap buffer overflow: memcpy copies more than
 *                         allocated
 *   Line 30:  CWE-806  — sizeof(src) used as length instead of sizeof(dst)
 *   Line 38:  CWE-125  — out-of-bounds read via memcmp
 *   Line 47:  CWE-124  — negative index causes buffer underwrite
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void vuln_heap_overflow(int count) {
    /* CWE-131: allocates 'count' bytes but should be count*sizeof(int) */
    int *buf = (int *)malloc(count);
    /* CWE-122: copies count*sizeof(int) bytes into 'count'-byte buffer */
    int src[256];
    memcpy(buf, src, count * sizeof(int));
    free(buf);
}

void vuln_sizeof_src(void) {
    char dst[8];
    char src[128];
    /* CWE-806: uses sizeof(src) == 128, but dst is only 8 bytes */
    memcpy(dst, src, sizeof(src));
    printf("%.8s\n", dst);
}

void vuln_overread(const char *data, size_t data_len) {
    char local[16];
    memcpy(local, data, 16);
    /* CWE-125: memcmp may read past end of local if data_len > 16 */
    if (memcmp(local, data, data_len) == 0) {
        puts("match");
    }
}

void vuln_underwrite(int *arr, int idx) {
    /* CWE-124: if idx < 0, this is a buffer underwrite */
    arr[idx] = 42;
}

int main(void) {
    vuln_heap_overflow(10);

    vuln_sizeof_src();

    char blob[64];
    vuln_overread(blob, 64);

    int stack_arr[10];
    vuln_underwrite(stack_arr, -3);    /* concrete negative index */
    return 0;
}
