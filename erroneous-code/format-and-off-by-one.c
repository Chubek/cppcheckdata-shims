/*
 * test_format_and_off_by_one.c
 * ============================
 * Exercises CWE-126 (over-read), CWE-127 (under-read), CWE-787
 * (off-by-one write), and CWE-805 (incorrect length value).
 *
 * EXPECTED FINDINGS:
 *   Line 18:  CWE-787  — off-by-one write: loop writes arr[10]
 *   Line 28:  CWE-787  — sprintf into too-small buffer
 *   Line 37:  CWE-805  — recv into buffer with wrong length
 *   Line 46:  CWE-126  — over-read: strlen on non-terminated buffer
 *   Line 55:  CWE-127  — under-read: negative offset dereference
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vuln_off_by_one(void) {
    int arr[10];
    /* CWE-787: loop bound should be < 10, not <= 10 */
    for (int i = 0; i <= 10; i++) {
        arr[i] = i;                    /* writes arr[10] on last iter */
    }
}

void vuln_sprintf(const char *user_input) {
    char msg[16];
    /* CWE-787: if user_input is long, this overflows msg */
    sprintf(msg, "Hello, %s!", user_input);
    puts(msg);
}

void vuln_recv_len(int sockfd) {
    char buf[64];
    /* CWE-805: hardcoded 1024 > sizeof(buf) */
    /* Simulating recv: we just model the size mismatch here */
    char temp[1024];
    memcpy(buf, temp, 1024);           /* CWE-805 */
}

void vuln_overread_strlen(void) {
    char data[8];
    memset(data, 'A', 8);             /* no null terminator! */
    /* CWE-126: strlen will read past end of data */
    size_t len = strlen(data);
    printf("len = %zu\n", len);
}

void vuln_underread(const char *ptr, int offset) {
    /* CWE-127: if offset is negative, reads before buffer start */
    char c = ptr[offset];
    printf("c = %c\n", c);
}

int main(int argc, char *argv[]) {
    vuln_off_by_one();

    if (argc > 1)
        vuln_sprintf(argv[1]);

    vuln_recv_len(0);
    vuln_overread_strlen();

    char buf[32];
    vuln_underread(buf, -5);           /* concrete negative */
    return 0;
}
