/*
 * bos_test_strings.c
 * ──────────────────
 * Triggers:
 *   BOS-04  unsafeGetsFunction          (line 28)
 *   BOS-04  unsafeStringFunction        (line 35, 41, 47)
 *   BOS-04  unsafeSprintfFunction       (line 54)
 *   BOS-03  offByOne                    (line 63)
 *   BOS-03  offByOneLoop                (line 72)
 *   BOS-03  offByOneStrlen              (line 80)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUF_SIZE 64

/* ── BOS-04: gets() ────────────────────────────────────────────────────── */
void gets_demo(void)
{
    char input[BUF_SIZE];

    /*
     * gets() provides no size limit whatsoever.
     * Any input longer than 63 chars overflows `input`.
     */
    gets(input);               /* BOS-04: unsafeGetsFunction         */
    printf("You entered: %s\n", input);
}

/* ── BOS-04: strcpy / strcat ───────────────────────────────────────────── */
void strcpy_demo(const char *src)
{
    char dest[BUF_SIZE];

    strcpy(dest, src);         /* BOS-04: unsafeStringFunction       */

    char result[BUF_SIZE];
    strcpy(result, dest);      /* BOS-04: unsafeStringFunction       */
    strcat(result, " suffix"); /* BOS-04: unsafeStringFunction       */

    printf("%s\n", result);
}

/* ── BOS-04: sprintf with %s ───────────────────────────────────────────── */
void sprintf_demo(const char *user_name)
{
    char out[32];

    /*
     * If user_name is longer than ~24 chars, out overflows.
     * The %s specifier has no width limit.
     */
    sprintf(out, "Hello, %s!", user_name); /* BOS-04: unsafeSprintfFunction */

    puts(out);
}

/* ── BOS-03: off-by-one — direct index == size ─────────────────────────── */
void off_by_one_direct(void)
{
    int scores[10];

    /* Valid indices are 0..9; writing to scores[10] is one past the end */
    scores[10] = 0;            /* BOS-03: offByOne                   */

    (void)scores;
}

/* ── BOS-03: off-by-one — <= in loop ───────────────────────────────────── */
void off_by_one_loop(void)
{
    char msg[16];

    /*
     * Loop runs i = 0, 1, …, 16.
     * When i == 16, msg[16] is one past the end.
     */
    for (int i = 0; i <= 16; i++) {
        msg[i] = 'A';          /* BOS-03: offByOneLoop               */
    }

    (void)msg;
}

/* ── BOS-03: off-by-one — strlen used as index ─────────────────────────── */
void off_by_one_strlen(void)
{
    char greeting[32] = "Hello";

    /*
     * strlen("Hello") == 5; greeting[5] IS the NUL terminator.
     * Writing here overwrites the NUL — legal but suspicious.
     * Any index > 5 is a definite overflow.
     */
    greeting[strlen(greeting)] = '!'; /* BOS-03: offByOneStrlen      */

    puts(greeting);
}

int main(void)
{
    gets_demo();
    strcpy_demo("world");
    sprintf_demo("Alice");
    off_by_one_direct();
    off_by_one_loop();
    off_by_one_strlen();
    return 0;
}
