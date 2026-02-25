/*
 * test_stack_depth.c
 * ==================
 * Test program for the StackDepthAnalyzer Cppcheck addon.
 *
 * Compile dump:
 *   cppcheck --dump test_stack_depth.c
 *
 * Run addon:
 *   python StackDepthAnalyzer.py --verbose --threshold 65536 test_stack_depth.c.dump
 *
 * Expected findings:
 *
 *   Function                   | Frame     | Max Depth     | Flags
 *   ---------------------------+-----------+---------------+------------------
 *   tiny_leaf                  |   ~32 B   |    ~48 B      | (none)
 *   moderate_locals            |  ~320 B   |   ~336 B      | (none)
 *   large_local_array          | ~40016 B  | ~40032 B      | largeStackFrame
 *   vla_function               | ∞         | ∞             | unboundedStack (VLA)
 *   alloca_function            | ∞         | ∞             | unboundedStack (alloca)
 *   deep_chain_a → b → c → d  |   ~64 B   |   ~256 B      | (none; sum of chain)
 *   direct_recursion           |   ~48 B   | ∞             | recursiveStack
 *   mutual_a ↔ mutual_b       |   ~48 B   | ∞             | recursiveStack (SCC)
 *   entry_with_deep_call       |   ~32 B   |  ~40320 B     | highStackDepth
 *   main                       |   ~32 B   |  ~40320 B+    | (entry point report)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

/* ------------------------------------------------------------------ */
/*  1. Tiny leaf — minimal frame                                      */
/* ------------------------------------------------------------------ */
int tiny_leaf(int x) {
    int y = x + 1;
    return y * 2;
}

/* ------------------------------------------------------------------ */
/*  2. Moderate locals                                                */
/* ------------------------------------------------------------------ */
double moderate_locals(double a, double b) {
    double arr[32];     /* 32 * 8 = 256 bytes */
    int i;
    double sum = 0.0;
    for (i = 0; i < 32; i++) {
        arr[i] = a * i + b;
        sum += arr[i];
    }
    return sum;
}

/* ------------------------------------------------------------------ */
/*  3. Large local array — should trigger largeStackFrame             */
/* ------------------------------------------------------------------ */
void large_local_array(void) {
    char buffer[40000];     /* 40000 bytes — well above 64 KiB? No, below. */
                            /* Adjust: use 80000 to exceed SINGLE_FRAME_WARN */
    memset(buffer, 0, sizeof(buffer));
    printf("buffer[0] = %d\n", buffer[0]);
}

/* ------------------------------------------------------------------ */
/*  4. VLA — unbounded frame                                          */
/* ------------------------------------------------------------------ */
void vla_function(int n) {
    int arr[n];     /* VLA: size depends on runtime argument */
    for (int i = 0; i < n; i++) {
        arr[i] = i * i;
    }
    printf("arr[0] = %d\n", arr[0]);
}

/* ------------------------------------------------------------------ */
/*  5. alloca — unbounded frame                                       */
/* ------------------------------------------------------------------ */
void alloca_function(int size) {
    char *buf = (char *)alloca(size);
    memset(buf, 'A', size);
    buf[size - 1] = '\0';
    printf("buf = %s\n", buf);
}

/* ------------------------------------------------------------------ */
/*  6. Deep call chain (non-recursive, DAG)                           */
/*     a → b → c → d                                                  */
/*     depth(a) = frame(a) + frame(b) + frame(c) + frame(d)          */
/* ------------------------------------------------------------------ */
int deep_chain_d(int x) {
    int local_d = x + 4;
    return local_d;
}

int deep_chain_c(int x) {
    int local_c = x + 3;
    return deep_chain_d(local_c);
}

int deep_chain_b(int x) {
    int local_b = x + 2;
    return deep_chain_c(local_b);
}

int deep_chain_a(int x) {
    int local_a = x + 1;
    return deep_chain_b(local_a);
}

/* ------------------------------------------------------------------ */
/*  7. Direct recursion — unbounded stack depth                       */
/* ------------------------------------------------------------------ */
int direct_recursion(int n) {
    if (n <= 0) return 0;
    int local = n;
    return local + direct_recursion(n - 1);
}

/* ------------------------------------------------------------------ */
/*  8. Mutual recursion — SCC {mutual_a, mutual_b}                   */
/* ------------------------------------------------------------------ */
int mutual_b(int n);

int mutual_a(int n) {
    if (n <= 0) return 1;
    int val = n * 2;
    return mutual_b(n - 1) + val;
}

int mutual_b(int n) {
    if (n <= 0) return 1;
    int val = n + 1;
    return mutual_a(n - 1) + val;
}

/* ------------------------------------------------------------------ */
/*  9. Entry with deep call — reaches large_local_array               */
/*     Reported as high stack depth if threshold is low enough.       */
/* ------------------------------------------------------------------ */
void entry_with_deep_call(int mode) {
    int x = mode;
    if (mode == 1) {
        large_local_array();
    } else if (mode == 2) {
        x = deep_chain_a(mode);
    } else {
        x = direct_recursion(mode);
    }
    printf("result: %d\n", x);
}

/* ------------------------------------------------------------------ */
/*  10. Main — program entry point                                    */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    int result = 0;

    result += tiny_leaf(10);
    result += (int)moderate_locals(1.0, 2.0);

    entry_with_deep_call(1);
    entry_with_deep_call(2);

    vla_function(100);
    alloca_function(256);

    printf("Total: %d\n", result);
    return 0;
}
