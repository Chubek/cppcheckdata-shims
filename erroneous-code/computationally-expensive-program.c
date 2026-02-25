/* test_energy.c — Calibration program for EnergyConsumptionEstimator */
#include <stdio.h>
#include <math.h>
#include <stdlib.h>

/* Pure integer arithmetic — should match INT_ADD/INT_MUL profile */
int integer_workload(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {          /* bound: n */
        for (int j = 0; j < n; j++) {      /* bound: n */
            sum += i * j + (i ^ j);        /* INT_MUL + INT_ADD + INT_BITWISE */
        }
    }
    return sum;
}

/* Floating-point workload — should match FP_ADD/FP_MUL/FP_DIV profile */
double fp_workload(int n) {
    double acc = 0.0;
    for (int i = 1; i <= n; i++) {         /* bound: n */
        acc += 1.0 / (double)i;           /* FP_DIV + FP_ADD + FP_CONV */
        acc *= 1.0000001;                 /* FP_MUL */
    }
    return acc;
}

/* Memory-intensive workload — should match MEM_LOAD/MEM_STORE profile */
void memory_workload(int *buf, int n) {
    for (int i = 0; i < n; i++) {          /* bound: n */
        buf[i] = buf[i] * 2 + 1;          /* MEM_LOAD + INT_MUL + INT_ADD + MEM_STORE */
    }
}

/* I/O workload */
void io_workload(int n) {
    for (int i = 0; i < n; i++) {          /* bound: n */
        printf("%d\n", i);                 /* IO_WRITE */
    }
}

/* Mixed workload with function calls */
double mixed_workload(int n) {
    int buf[4096];
    for (int i = 0; i < 4096; i++) buf[i] = i;

    int r1 = integer_workload(n);          /* CALL */
    double r2 = fp_workload(n);            /* CALL */
    memory_workload(buf, 4096);            /* CALL */

    return r1 + r2 + buf[0];
}

int main(int argc, char *argv[]) {
    int n = 1000;
    if (argc > 1) n = atoi(argv[1]);

    volatile double result = mixed_workload(n);

    printf("Result: %f\n", result);
    return 0;
}
