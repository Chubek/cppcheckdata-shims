/* CWE-15: External Control of System or Configuration Setting
 * User input directly controls system configuration.
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    
    // BUG: User controls environment variable value
    setenv("LD_LIBRARY_PATH", argv[1], 1);  // Attacker can inject malicious library path
    
    printf("Library path set to: %s\n", argv[1]);
    return 0;
}