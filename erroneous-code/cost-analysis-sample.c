/*
 * test_cost_analysis.c
 * ====================
 * Test program for the StaticCostAnalysis Cppcheck addon.
 *
 * Compile dump:
 *   cppcheck --dump test_cost_analysis.c
 *
 * Run addon:
 *   python StaticCostAnalysis.py --verbose test_cost_analysis.c.dump
 *
 * Expected findings:
 *   - constant_work():           O(1)
 *   - linear_search():           O(n)
 *   - bubble_sort():             O(n²)
 *   - merge_sort_helper():       O(n log n)  [recursive, hard to infer]
 *   - matrix_multiply():         O(n³)
 *   - io_heavy():                O(n) with high per-iteration cost
 *   - unbounded_loop():          O(∞)
 *   - nested_with_break():       O(n) or O(n²) [depends on analysis precision]
 *   - alloc_in_loop():           O(n) with allocation cost
 *   - recursive_fibonacci():     O(∞) [recursive, exponential]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  1. O(1) — Constant work                                          */
/* ------------------------------------------------------------------ */
int constant_work(int a, int b) {
    int x = a + b;
    int y = x * 2;
    int z = y - a;
    return z / (b ? b : 1);
}

/* ------------------------------------------------------------------ */
/*  2. O(n) — Linear search                                          */
/* ------------------------------------------------------------------ */
int linear_search(const int *arr, int n, int target) {
    for (int i = 0; i < n; i++) {
        if (arr[i] == target) {
            return i;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  3. O(n²) — Bubble sort                                           */
/* ------------------------------------------------------------------ */
void bubble_sort(int *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  4. O(n log n) — Merge sort (recursive)                           */
/* ------------------------------------------------------------------ */
void merge(int *arr, int left, int mid, int right) {
    int n1 = mid - left + 1;
    int n2 = right - mid;
    int *L = (int *)malloc(n1 * sizeof(int));
    int *R = (int *)malloc(n2 * sizeof(int));

    for (int i = 0; i < n1; i++)
        L[i] = arr[left + i];
    for (int j = 0; j < n2; j++)
        R[j] = arr[mid + 1 + j];

    int i = 0, j = 0, k = left;
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            arr[k++] = L[i++];
        } else {
            arr[k++] = R[j++];
        }
    }
    while (i < n1)
        arr[k++] = L[i++];
    while (j < n2)
        arr[k++] = R[j++];

    free(L);
    free(R);
}

void merge_sort_helper(int *arr, int left, int right) {
    if (left < right) {
        int mid = left + (right - left) / 2;
        merge_sort_helper(arr, left, mid);
        merge_sort_helper(arr, mid + 1, right);
        merge(arr, left, mid, right);
    }
}

void merge_sort(int *arr, int n) {
    merge_sort_helper(arr, 0, n - 1);
}

/* ------------------------------------------------------------------ */
/*  5. O(n³) — Matrix multiplication                                  */
/* ------------------------------------------------------------------ */
void matrix_multiply(
    const double *A, const double *B, double *C,
    int n
) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            C[i * n + j] = 0.0;
            for (int k = 0; k < n; k++) {
                C[i * n + j] += A[i * n + k] * B[k * n + j];
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  6. O(n) with high per-iteration cost — I/O in a loop             */
/* ------------------------------------------------------------------ */
void io_heavy(const char **filenames, int n) {
    for (int i = 0; i < n; i++) {
        FILE *f = fopen(filenames[i], "r");
        if (f) {
            char buf[1024];
            while (fgets(buf, sizeof(buf), f)) {
                printf("%s", buf);
            }
            fclose(f);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  7. O(∞) — Unbounded loop (event loop / server)                   */
/* ------------------------------------------------------------------ */
void unbounded_loop(int socket_fd) {
    char buffer[4096];
    while (1) {
        int n = read(socket_fd, buffer, sizeof(buffer));
        if (n <= 0) break;
        write(1, buffer, n);
    }
}

/* ------------------------------------------------------------------ */
/*  8. Nested with early exit — hard to bound precisely              */
/* ------------------------------------------------------------------ */
int nested_with_break(const int *matrix, int rows, int cols, int target) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            if (matrix[r * cols + c] == target) {
                return r * cols + c;  /* early exit */
            }
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  9. Allocation in a loop — cost includes malloc/free              */
/* ------------------------------------------------------------------ */
void alloc_in_loop(int n) {
    for (int i = 0; i < n; i++) {
        int *p = (int *)malloc(100 * sizeof(int));
        if (!p) return;
        memset(p, 0, 100 * sizeof(int));
        p[i % 100] = i;
        printf("Value: %d\n", p[i % 100]);
        free(p);
    }
}

/* ------------------------------------------------------------------ */
/* 10. O(2^n) — Recursive Fibonacci (exponential, reported as O(∞))  */
/* ------------------------------------------------------------------ */
int recursive_fibonacci(int n) {
    if (n <= 1) return n;
    return recursive_fibonacci(n - 1) + recursive_fibonacci(n - 2);
}

/* ------------------------------------------------------------------ */
/*  Main — exercise all functions                                     */
/* ------------------------------------------------------------------ */
int main(void) {
    /* 1. Constant */
    int r1 = constant_work(10, 20);
    printf("constant_work: %d\n", r1);

    /* 2. Linear */
    int arr[] = {5, 3, 8, 1, 9, 2, 7, 4, 6, 0};
    int idx = linear_search(arr, 10, 7);
    printf("linear_search: found at %d\n", idx);

    /* 3. Quadratic */
    bubble_sort(arr, 10);
    printf("bubble_sort: arr[0]=%d\n", arr[0]);

    /* 4. N log N */
    int arr2[] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    merge_sort(arr2, 10);
    printf("merge_sort: arr2[0]=%d\n", arr2[0]);

    /* 5. Cubic */
    double A[4] = {1, 2, 3, 4};
    double B[4] = {5, 6, 7, 8};
    double C[4];
    matrix_multiply(A, B, C, 2);
    printf("matrix_multiply: C[0]=%f\n", C[0]);

    /* 8. Nested with break */
    int mat[6] = {1, 2, 3, 4, 5, 6};
    int pos = nested_with_break(mat, 2, 3, 5);
    printf("nested_with_break: pos=%d\n", pos);

    /* 9. Alloc in loop */
    alloc_in_loop(5);

    /* 10. Fibonacci */
    int fib = recursive_fibonacci(10);
    printf("fibonacci(10): %d\n", fib);

    return 0;
}
