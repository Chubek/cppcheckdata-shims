/* test_ds_general.c
 * Expected findings:
 *   DS-002  line 8   Unused initialisation: 'total' initialized but never read
 *   DS-001  line 12  Dead store: 'result' assigned but overridden before use
 *   DS-007  line 9   Unused variable: 'scratch' defined but never used
 *   DS-001  line 18  Dead store: 'flags' assigned but never read
 */

#include <stdio.h>
#include <stdlib.h>

int process_data(int *data, int len) {
    int total = 0;            /* DS-002: initialized but never read — 
                                 overwritten unconditionally below */
    int scratch = 42;         /* DS-007: defined, never used anywhere */
    int result;
    int flags;

    result = len * 2;         /* DS-001: dead store — overwritten at line 16
                                 without 'result' being read in between */

    total = 0;                /* overwrites the init on line 8 */
    for (int i = 0; i < len; i++) {
        total += data[i];
    }

    result = total + 1;       /* this is the value actually returned */

    flags = 0xFF;             /* DS-001: dead store — 'flags' never read
                                 after this point */

    return result;
}

int main(void) {
    int arr[] = {10, 20, 30};
    printf("result = %d\n", process_data(arr, 3));
    return 0;
}
