/*
 * test_command_injection.c
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command
 *
 * Expected TaintLint findings:
 *   - Line 20: Command injection via system()
 *   - Line 29: Command injection via popen()
 *   - Line 38: Command injection via execl()
 *   - Line 47: Command injection via system() from getenv()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* VULNERABLE: Direct use of user input in system() */
void vulnerable_system_direct(const char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls -la %s", user_input);
    system(cmd);  /* CWE-78: Tainted data reaches system() */
}

