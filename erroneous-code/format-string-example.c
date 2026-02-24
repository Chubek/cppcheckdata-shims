/*
 * fsg_test.c — Reference test cases for FormatStringGuard.py
 *
 * Build dump:
 *   cppcheck --dump fsg_test.c
 * Run addon:
 *   python3 FormatStringGuard.py fsg_test.c.dump
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <err.h>

/* ================================================================== */
/* FSG-01 : format_string_injection                                    */
/* ================================================================== */

void fsg01_bad_printf(const char *user_input) {
    printf(user_input);            /* FSG-01: non-literal format */
}

void fsg01_bad_fprintf(FILE *fp, const char *msg) {
    fprintf(fp, msg);              /* FSG-01: non-literal format */
}

void fsg01_good_printf(const char *user_input) {
    printf("%s\n", user_input);   /* OK: literal format, var as argument */
}

void fsg01_good_const_fmt(void) {
    printf("Hello, world!\n");    /* OK: plain literal */
}

/* ================================================================== */
/* FSG-02 : percent_n_in_format                                        */
/* ================================================================== */

void fsg02_bad_percent_n(void) {
    int written;
    printf("hello%n", &written);  /* FSG-02: %n present */
}

void fsg02_bad_percent_n_fprintf(FILE *fp) {
    int w;
    fprintf(fp, "data%n", &w);    /* FSG-02 */
}

void fsg02_good_no_n(void) {
    printf("value: %d\n", 42);    /* OK */
}

/* ================================================================== */
/* FSG-03 : argument_count_mismatch                                    */
/* ================================================================== */

void fsg03_bad_too_few(void) {
    printf("%d %d %d\n", 1, 2);   /* FSG-03: 3 needed, 2 supplied */
}

void fsg03_bad_too_many(void) {
    printf("%d\n", 1, 2, 3);      /* FSG-03: 1 needed, 3 supplied */
}

void fsg03_good_exact(void) {
    printf("%d %s %f\n", 42, "hello", 3.14);  /* OK: 3 == 3 */
}

void fsg03_good_percent_percent(void) {
    printf("100%% complete: %d items\n", 5);  /* OK: %% is literal % */
}

void fsg03_bad_star_width(void) {
    printf("%*d\n", 42);           /* FSG-03: %*d needs 2 args (width + val) */
}

/* ================================================================== */
/* FSG-04 : format_type_mismatch                                       */
/* ================================================================== */

void fsg04_bad_string_as_int(void) {
    printf("%d\n", "hello");       /* FSG-04: %d with char* */
}

void fsg04_bad_int_as_string(void) {
    int x = 42;
    printf("%s\n", x);             /* FSG-04: %s with int */
}

void fsg04_bad_float_as_int(void) {
    printf("%d\n", 3.14);          /* FSG-04: %d with double */
}

void fsg04_good_types(void) {
    int   i = 1;
    char *s = "hi";
    double d = 3.14;
    printf("%d %s %f\n", i, s, d); /* OK */
}

/* ================================================================== */
/* FSG-05 : null_format_string                                         */
/* ================================================================== */

void fsg05_bad_null_fmt(void) {
    printf(NULL);                  /* FSG-05: NULL format */
}

void fsg05_bad_zero_fmt(FILE *fp) {
    fprintf(fp, 0);                /* FSG-05: 0 (null pointer) as format */
}

void fsg05_good_empty_string(void) {
    printf("");                    /* OK: empty but not NULL */
}

/* ================================================================== */
/* FSG-06 : snprintf_truncation_ignored                                */
/* ================================================================== */

void fsg06_bad_snprintf_no_check(char *buf, size_t len, int val) {
    snprintf(buf, len, "%d", val); /* FSG-06: return value discarded */
}

void fsg06_good_snprintf_checked(char *buf, size_t len, int val) {
    int r = snprintf(buf, len, "%d", val);
    if (r >= (int)len) {
        /* handle truncation */
    }
}

/* ================================================================== */
/* FSG-07 : sprintf_no_length_limit                                    */
/* ================================================================== */

void fsg07_bad_sprintf(char *dst, const char *src) {
    sprintf(dst, "%s", src);       /* FSG-07: no size limit */
}

void fsg07_bad_sprintf_int(char *buf) {
    sprintf(buf, "value=%d", 42);  /* FSG-07: no size limit */
}

void fsg07_good_snprintf(char *buf, size_t n, const char *src) {
    snprintf(buf, n, "%s", src);   /* OK */
}

/* ================================================================== */
/* FSG-08 : format_string_from_getenv                                  */
/* ================================================================== */

void fsg08_bad_getenv_fmt(void) {
    printf(getenv("FORMAT"));      /* FSG-08: getenv result as format */
}

void fsg08_bad_getenv_fprintf(FILE *fp) {
    fprintf(fp, getenv("MSG"));    /* FSG-08 */
}

void fsg08_good_getenv_as_arg(void) {
    printf("%s\n", getenv("NAME")); /* OK: getenv is argument, not format */
}

/* ================================================================== */
/* Combined / edge cases                                               */
/* ================================================================== */

void combined_bad(const char *user_msg) {
    /* FSG-01 + would-be FSG-03 if literal */
    fprintf(stderr, user_msg);
}

void combined_sprintf_getenv(char *buf, size_t n) {
    /* FSG-07 */
    sprintf(buf, getenv("TEMPLATE")); /* FSG-07 + FSG-08 */
}
