/*
 * bos_test_stack_heap.c
 * ─────────────────────
 * Triggers:
 *   BOS-01  stackBufferOverflow         (line 22, 23)
 *   BOS-01  stackBufferOverflowPossible (line 27)
 *   BOS-02  heapBufferOverflow          (line 43)
 *   BOS-06  bufferUnderflow             (line 51)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── BOS-01: Stack Buffer Overflow ─────────────────────────────────────── */
void stack_overflow_demo(void)
{
    char buf[8];

    /* Index == size: classic off-by-one leading to overflow */
    buf[8] = 'X';              /* BOS-01: index 8 >= size 8          */

    /* Index clearly past the end */
    buf[9] = 'Y';              /* BOS-01: index 9 >= size 8          */

    int arr[4];
    /* ValueFlow may resolve loop variable to 4 at final iteration */
    for (int i = 0; i <= 4; i++) {
        arr[i] = i * 2;        /* BOS-01 (possible): i may reach 4   */
    }

    (void)buf;
    (void)arr;
}

/* ── BOS-02: Heap Buffer Overflow ──────────────────────────────────────── */
void heap_overflow_demo(void)
{
    /*
     * Allocate exactly 5 ints (20 bytes on 32-bit, 20 on 64-bit).
     * Valid indices: 0..4
     */
    int *p = (int *)malloc(5 * sizeof(int));
    if (!p)
        return;

    for (int i = 0; i <= 5; i++) {
        p[i] = i;              /* BOS-02: index 5 >= 5 elements      */
    }

    free(p);
}

/* ── BOS-06: Buffer Underflow ───────────────────────────────────────────── */
void underflow_demo(void)
{
    int data[10];
    int *ptr = data;

    /* Negative literal index — always undefined behaviour */
    ptr[-1] = 42;              /* BOS-06: bufferUnderflow            */
    data[-2] = 99;             /* BOS-06: bufferUnderflow            */

    (void)ptr;
}

int main(void)
{
    stack_overflow_demo();
    heap_overflow_demo();
    underflow_demo();
    return 0;
}
