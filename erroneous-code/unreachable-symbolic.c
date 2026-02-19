/*
 * test_unreachable_symbolic.c
 * ===========================
 * Exercises: symbolic-execution proven unreachability,
 * path-infeasible dead code, vacuous loops, abstract-interpretation
 * dead branches.
 *
 * EXPECTED FINDINGS:
 *   Line 18:  CWE-561  — branch x > 100 && x < 50 is infeasible
 *   Line 27:  CWE-561  — inner branch dead: if (y < 0) after y = abs(x)
 *   Line 35:  CWE-561  — vacuous loop: while (n < 0) when n is unsigned
 *   Line 43:  CWE-570  — condition (a > 10 && a < 5) always false
 *   Line 52:  CWE-561  — path-infeasible: contradictory conditions on x
 *   Line 64:  CWE-561  — dead store: result computed but overwritten
 */
#include <stdio.h>
#include <stdlib.h>

/* Symbolic: impossible conjunction */
void impossible_conjunction(int x) {
    if (x > 100 && x < 50) {
        /* Symbolic execution proves: no x satisfies both */
        printf("impossible\n");          /* CWE-561 */
    }
    printf("ok\n");
}

/* Path-infeasible after abs */
void abs_unreachable(int x) {
    int y = abs(x);                      /* y >= 0 always */
    if (y < 0) {
        printf("y is negative?!\n");     /* CWE-561 */
    }
}

/* Vacuous loop: unsigned n can never be < 0 */
void vacuous_unsigned_loop(unsigned int n) {
    while (n < 0) {                      /* always false for unsigned */
        printf("never\n");               /* CWE-561: vacuous loop */
        n--;
    }
}

/* Abstract interpretation: interval proves impossible */
void interval_impossible(int a) {
    if (a > 10) {
        if (a < 5) {
            printf("impossible\n");      /* CWE-570 / CWE-561 */
        }
    }
}

/* Path-sensitive: contradictory branches on same variable */
void contradictory_paths(int x) {
    if (x > 0) {
        if (x < 0) {
            /* Both conditions on x cannot hold simultaneously */
            printf("dead\n");            /* CWE-561 */
        }
    }
}

/* Dead store */
int dead_computation(int a, int b) {
    int result = a * b + 17;            /* CWE-561: dead store */
    result = a + b;                      /* overwrites previous */
    return result;
}

int main(void) {
    impossible_conjunction(42);
    abs_unreachable(-7);
    vacuous_unsigned_loop(10u);
    interval_impossible(3);
    contradictory_paths(1);
    return dead_computation(3, 4);
}
