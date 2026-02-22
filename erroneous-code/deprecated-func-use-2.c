#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* CWE-338: rand used as if it were a secure token */
unsigned int generate_token(void) {
    srand(12345);
    return (unsigned int)rand();
}

/* CWE-120: vsprintf — no output size limit */
void log_message(char *out, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsprintf(out, fmt, ap);
    va_end(ap);
}

/* CWE-120: memcpy with dynamic (unvalidated) size */
void copy_payload(void *dst, const void *src, size_t n) {
    memcpy(dst, src, n);   /* n comes from caller — not validated */
}

/* CWE-78: system() with attacker-influenced string */
void run_report(const char *username) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "report_tool --user %s", username);
    system(cmd);
}

int main(int argc, char *argv[]) {
    unsigned int tok = generate_token();
    printf("Token: %u\n", tok);

    char logbuf[128];
    log_message(logbuf, "User %s logged in with token %u",
                argv[1], tok);
    puts(logbuf);

    char payload[64];
    size_t sz = (size_t)atoi(argv[2]);   /* also hits atoiUsed */
    copy_payload(payload, argv[1], sz);

    run_report(argv[1]);
    return 0;
}
