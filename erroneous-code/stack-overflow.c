/*
 * test_stack_overflow.c
 * =====================
 * Exercises CWE-120, CWE-121, CWE-170, CWE-787 detections.
 *
 * EXPECTED FINDINGS:
 *   Line 15:  CWE-120  — strcpy with unchecked source length
 *   Line 22:  CWE-787  — out-of-bounds write via index from argv
 *   Line 29:  CWE-121  — stack-based overflow via strncpy with wrong size
 *   Line 31:  CWE-170  — strncpy without null termination
 *   Line 38:  CWE-120  — gets() is always exploitable
 */
#include <stdio.h>
#include <string.h>

void vuln_strcpy(const char *input) {
    char buf[16];
    strcpy(buf, input);               /* CWE-120: unbounded copy */
    printf("%s\n", buf);
}

void vuln_index(int idx) {
    int arr[10];
    arr[idx] = 0xDEADBEEF;            /* CWE-787: idx can be >= 10 */
}

void vuln_strncpy(const char *src) {
    char dest[8];
    /* Bug 1 (CWE-121): copies 64 bytes into 8-byte buffer */
    strncpy(dest, src, 64);            /* CWE-121 */
    /* Bug 2 (CWE-170): no null termination added afterwards */
    /*  dest[7] = '\0';  ← missing!  */
    printf("%s\n", dest);
}

void vuln_gets(void) {
    char line[32];
    gets(line);                        /* CWE-120: always exploitable */
    puts(line);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vuln_strcpy(argv[1]);
        vuln_index(argc);
        vuln_strncpy(argv[1]);
    }
    vuln_gets();
    return 0;
}
