/* test_command_injection.c
 * Expected: Taint from fgets() reaches system() without sanitization.
 * CWE-78: OS Command Injection
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char user_input[256];
    char command[512];

    printf("Enter filename to display: ");
    fgets(user_input, sizeof(user_input), stdin);          /* SOURCE */

    /* Strip newline (but this is NOT a sanitizer) */
    user_input[strcspn(user_input, "\n")] = '\0';

    /* BUG: tainted data concatenated directly into shell command */
    sprintf(command, "cat /var/data/%s", user_input);      /* propagator */
    system(command);                                        /* SINK: CWE-78 */

    return 0;
}
