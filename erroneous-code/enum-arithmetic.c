/*
 * test_enum_arithmetic.c
 *
 * Expected findings from EnumCheck.py:
 *
 *   Line 28  : arithmeticOnEnum (CWE-704)  — compound assignment day += 1
 *   Line 33  : arithmeticOnEnum (CWE-704)  — arithmetic expression
 *              (day + 1) assigned back to enum variable
 *   Line 39  : arithmeticOnEnum (CWE-704)  — day = day * 2 assigned
 *              back to enum
 *   Line 46  : arithmeticOnEnum (CWE-704)  — day -= 1 compound assign
 *   Line 56  : enumTypeMismatch (CWE-704)  — assigning Season to Day
 *              (cross-enum assignment detected via UnionFind)
 *   Line 62  : mixedEnumOp (CWE-704)       — arithmetic between Day and
 *              Season
 *   Line 71  : enumOutOfRange (CWE-704)    — variable 'today' may hold
 *              value 8 which is not valid (dataflow-detected)
 *   Line 78  : switchEnumNotCovered (CWE-478) — switch on Season missing
 *              AUTUMN and WINTER, no default
 *   Line 93  : implicitIntToEnum (CWE-704) — function return int assigned
 *              to enum
 *
 * Compile:  gcc -o test_enum_arith test_enum_arithmetic.c
 */

#include <stdio.h>

/* ===== Enum definitions ===== */

typedef enum {
    MON = 1,
    TUE = 2,
    WED = 3,
    THU = 4,
    FRI = 5,
    SAT = 6,
    SUN = 7
} Day;

typedef enum {
    SPRING = 0,
    SUMMER = 1,
    AUTUMN = 2,
    WINTER = 3
} Season;


/* ===== Arithmetic on enums ===== */

void test_compound_assign(void) {
    Day day = MON;

    day += 1;             /* BUG (line ~28): arithmeticOnEnum
                            compound += on enum type */

    /* Simple arithmetic assigned back */
    Day next_day;
    next_day = day + 1;   /* BUG (line ~33): arithmeticOnEnum
                            arithmetic expression assigned to enum */

    (void)next_day;

    /* Multiplication — obviously wrong for a day-of-week */
    day = day * 2;        /* BUG (line ~39): arithmeticOnEnum
                            multiplication on enum */

    (void)day;
}

void test_decrement(void) {
    Day day = SUN;

    day -= 1;             /* BUG (line ~46): arithmeticOnEnum
                            compound -= on enum */

    (void)day;
}

/* ===== Cross-enum assignment (type unification error) ===== */

void test_cross_enum_assign(void) {
    Day day;
    Season s = SUMMER;

    day = s;              /* BUG (line ~56): enumTypeMismatch
                            assigning Season to Day (incompatible enums) */

    (void)day;

    /* Mixed arithmetic */
    int result = day + s; /* BUG (line ~62): mixedEnumOp
                            adding Day + Season */
    (void)result;
}

/* ===== Dataflow out-of-range detection ===== */

void test_out_of_range_value(void) {
    Day today = MON;      /* value = 1, valid */
    today = today + 7;    /* BUG (line ~71): after dataflow, today may
                            hold 8 which is not in {1..7}.
                            Also arithmeticOnEnum. */

    printf("day = %d\n", today);
}

/* ===== Switch missing cases ===== */

void test_switch_season(Season s) {
    switch (s) {          /* BUG (line ~78): switchEnumNotCovered
                            missing AUTUMN and WINTER, no default */
        case SPRING:
            printf("spring\n");
            break;
        case SUMMER:
            printf("summer\n");
            break;
        /* Missing: AUTUMN, WINTER — and no default! */
    }
}

/* ===== Function returning int assigned to enum ===== */

int get_day_number(void) {
    return 42;  /* returns int, not Day */
}

void test_int_return_to_enum(void) {
    Day d;
    d = get_day_number(); /* BUG (line ~93): implicitIntToEnum
                            integer return value assigned to Day */
    (void)d;
}

/* ===== Driver ===== */

int main(void) {
    test_compound_assign();
    test_decrement();
    test_cross_enum_assign();
    test_out_of_range_value();
    test_switch_season(SPRING);
    test_int_return_to_enum();
    return 0;
}
