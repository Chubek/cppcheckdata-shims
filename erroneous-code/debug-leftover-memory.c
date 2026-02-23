/*
 * bad_debug_memory.c
 * Expected findings: DLF-06, DLF-07
 */
#include <stdlib.h>
#include <string.h>

/*
 * No prctl(PR_SET_DUMPABLE, 0) anywhere → DLF-06
 * No setrlimit(RLIMIT_CORE, ...) anywhere → DLF-06
 */

int authenticate(const char *input) {
    char password[64];          /* DLF-07: never memset'd before return  */
    char api_key[32];           /* DLF-07: never memset'd before return  */

    strncpy(password, input, sizeof(password) - 1);
    /* ... authentication logic ... */

    /* password and api_key leave scope without zeroing */
    return 1;
}

void process_session(void) {
    char session_token[128];    /* DLF-07 */
    char secret[64];            /* DLF-07 */

    /* use them */
    memset(session_token, 0, sizeof(session_token)); /* this one IS cleared */
    /* secret is NOT cleared → DLF-07 */
}

int main(void) {
    authenticate("hunter2");
    process_session();
    return 0;
}
