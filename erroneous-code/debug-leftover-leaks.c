/*
 * bad_debug_leaks.c
 * Expected findings: DLF-01, DLF-02, DLF-03, DLF-04, DLF-05
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>

int  DEBUG      = 1;          /* DLF-03: global debug flag = 1          */
char password[] = "s3cr3t!";  /* later logged → DLF-01                  */

void send_error(int sock, const char *msg) {
    /* DLF-02: strerror leaks into user-facing output */
    fprintf(sock, "Error: %s — detail: %s", msg, strerror(errno));

    /* DLF-02: internal path literal forwarded to caller */
    send(sock, "/etc/shadow lookup failed", 25, 0);
}

void login(const char *user, const char *pass) {
    /* DLF-01: sensitive arg to log sink */
    printf("DEBUG: user=%s pass=%s\n", user, pass);

    /* DLF-04: pointer address printed to stdout */
    printf("buffer at %p, hex=%08x\n", pass, (unsigned)pass);

    /* DLF-05: leftover debug print with marker */
    printf("[DEBUG] entering login routine\n");
}

void dump_key(const unsigned char *key, int len) {
    /* DLF-04: raw write of sensitive buffer */
    write(1, key, len);
}

int main(void) {
    /* DLF-03: enable_debug() call */
    enable_debug();

    login("alice", password);
    return 0;
}
