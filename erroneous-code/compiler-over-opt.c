/* CWE-14: Compiler Removal of Code to Clear Buffers
 * The compiler may optimize away the memset, leaving sensitive data in memory.
 */
#include <stdio.h>
#include <string.h>

void authenticate(void) {
    char password[64] = "SuperSecret123!";
    
    // Use password for authentication...
    printf("Password used for auth\n");
    
    // BUG: Compiler may remove this memset as dead store optimization
    memset(password, 0, sizeof(password));
    // Password may still remain in memory!
}

int main(void) {
    authenticate();
    return 0;
}