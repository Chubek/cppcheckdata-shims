/*
 * test_unreachable_basic.c
 * ========================
 * Exercises: structural unreachability, post-return dead code,
 * always-true/false branches, dead stores.
 *
 * EXPECTED FINDINGS:
 *   Line 16:  CWE-561   — code after return is unreachable
 *   Line 23:  CWE-571   — condition 1==1 is always true,
 *                          else branch (line 26) is dead
 *   Line 33:  CWE-570   — condition 0 is always false,
 *                          true branch (line 34) is dead
 *   Line 41:  CWE-561   — dead store: x = 10 overwritten by x = 20
 *   Line 50:  CWE-561   — structurally unreachable (after goto skip)
 *   Line 58:  CWE-1164  — code after exit() is irrelevant
 */
#include <stdio.h>
#include <stdlib.h>

int post_return_dead(int a) {
    if (a > 0)
        return a;
    return -a;
    printf("This is unreachable\n");   /* CWE-561: post-return */
    return 0;                           /* CWE-561: post-return */
}

void always_true_branch(int x) {
    if (1 == 1) {                       /* CWE-571: always true */
        printf("always reached\n");
    } else {
        printf("never reached\n");      /* dead branch */
    }
}

void always_false_branch(void) {
    if (0) {                            /* CWE-570: always false */
        printf("dead code\n");          /* dead branch */
    }
    printf("alive\n");
}

void dead_store_example(void) {
    int x;
    x = 10;                            /* CWE-561: dead store */
    x = 20;                            /* overwrites without reading */
    printf("%d\n", x);
}

void goto_unreachable(void) {
    goto skip;
    printf("structurally unreachable\n"); /* CWE-561 */
skip:
    printf("reached via goto\n");
}

void after_exit_dead(int code) {
    exit(code);
    printf("after exit — dead\n");       /* CWE-1164 */
}

int main(void) {
    post_return_dead(5);
    always_true_branch(42);
    always_false_branch();
    dead_store_example();
    goto_unreachable();
    after_exit_dead(1);
    return 0;
}
