/* CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 * User can escape intended directory using "../"
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    
    char filepath[256];
    // BUG: User can supply "../../etc/passwd" to escape /var/data/
    snprintf(filepath, sizeof(filepath), "/var/data/%s", argv[1]);
    
    FILE *f = fopen(filepath, "r");
    if (f) {
        char buf[256];
        while (fgets(buf, sizeof(buf), f))
            printf("%s", buf);
        fclose(f);
    }
    return 0;
}