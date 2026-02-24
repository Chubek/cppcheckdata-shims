/*
 * tcd_test.c — test cases for TypeConfusionDetector.py
 *
 * Compile a dump with:
 *   cppcheck --dump tcd_test.c
 * Then run:
 *   python3 TypeConfusionDetector.py tcd_test.c.dump
 *
 * Lines marked EXPECT_TCD-XX should trigger that checker.
 * Lines marked CLEAN should produce no finding.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

/* -----------------------------------------------------------------------
 * TCD-01  pointer_type_pun
 * --------------------------------------------------------------------- */
void tcd01_examples(void) {
    int   arr[4] = {0};
    float f_arr[4];

    /* EXPECT_TCD-01: reinterpreting int* as float* */
    float *fp = (float *)arr;
    (void)fp;

    /* CLEAN: memcpy is a safe reinterpretation context */
    float safe;
    int   raw = 42;
    memcpy(&safe, &raw, sizeof safe);

    /* CLEAN: void* cast is generic */
    void *vp = (void *)arr;
    (void)vp;

    /* CLEAN: char* aliasing of any type is permitted by C standard */
    unsigned char *cp = (unsigned char *)arr;
    (void)cp;
}


/* -----------------------------------------------------------------------
 * TCD-02  signed_unsigned_compare
 * --------------------------------------------------------------------- */
void tcd02_examples(void) {
    int    a = -1;
    size_t b = 10;

    /* EXPECT_TCD-02: comparing int (signed) with size_t (unsigned) */
    if (a < b) { /* hazardous */ }

    /* CLEAN: explicit cast */
    if ((size_t)a < b) { /* ok */ }

    /* CLEAN: both unsigned */
    unsigned x = 1, y = 2;
    if (x < y) { /* fine */ }
}


/* -----------------------------------------------------------------------
 * TCD-03  truncating_cast
 * --------------------------------------------------------------------- */
void tcd03_examples(void) {
    int   big  = 70000;
    long  wide = 1234567890L;

    /* EXPECT_TCD-03: int→short truncation */
    short s = (short)big;
    (void)s;

    /* EXPECT_TCD-03: long→int truncation */
    int   i = (int)wide;
    (void)i;

    /* CLEAN: widening cast */
    long  lv = (long)big;
    (void)lv;

    /* CLEAN: same-width cast */
    unsigned u = (unsigned)big;
    (void)u;
}


/* -----------------------------------------------------------------------
 * TCD-04  sizeof_pointer
 * --------------------------------------------------------------------- */
void tcd04_examples(void) {
    char *buf = NULL;
    int   arr2[10];

    /* EXPECT_TCD-04: sizeof of pointer variable */
    size_t wrong = sizeof(buf);
    (void)wrong;

    /* CLEAN: sizeof of pointed-to type */
    size_t right = sizeof(*buf);
    (void)right;

    /* CLEAN: sizeof of array is correct */
    size_t arr_sz = sizeof(arr2);
    (void)arr_sz;

    /* CLEAN: sizeof of a type expression */
    size_t type_sz = sizeof(char *);
    (void)type_sz;
}


/* -----------------------------------------------------------------------
 * TCD-05  void_ptr_function_cast
 * --------------------------------------------------------------------- */
typedef int (*callback_t)(int, int);

int add(int a, int b) { return a + b; }

void tcd05_examples(void) {
    callback_t fn = add;

    /* EXPECT_TCD-05: storing function pointer in void* */
    void *vfp = fn;
    (void)vfp;

    /* CLEAN: correct function pointer usage */
    callback_t direct = add;
    int result = direct(1, 2);
    (void)result;
}


/* -----------------------------------------------------------------------
 * TCD-06  enum_out_of_range
 * --------------------------------------------------------------------- */
typedef enum { RED = 0, GREEN = 1, BLUE = 2 } Color;

void tcd06_examples(void) {
    Color c;

    /* EXPECT_TCD-06: 99 is not a valid Color enumerator */
    c = 99;
    (void)c;

    /* CLEAN: valid enumerator value */
    c = 1;
    (void)c;

    /* CLEAN: using the symbolic name */
    c = GREEN;
    (void)c;
}


/* -----------------------------------------------------------------------
 * TCD-07  struct_reinterpret_cast
 * --------------------------------------------------------------------- */
typedef struct { int x; int y; }   Point2D;
typedef struct { int x; int y; int z; } Point3D;
typedef struct { float r; float i; } Complex;

void tcd07_examples(void) {
    Point2D p2 = {1, 2};

    /* EXPECT_TCD-07: reinterpreting Point2D* as Point3D* */
    Point3D *p3 = (Point3D *)&p2;
    (void)p3;

    /* EXPECT_TCD-07: reinterpreting Point2D* as Complex* */
    Complex *cp = (Complex *)&p2;
    (void)cp;

    /* CLEAN: cast to void* is generic */
    void *vp = (void *)&p2;
    (void)vp;

    /* CLEAN: same-type cast */
    Point2D *pp = (Point2D *)&p2;
    (void)pp;
}


/* -----------------------------------------------------------------------
 * TCD-08  char_width_confusion
 * --------------------------------------------------------------------- */
void tcd08_examples(void) {
    char    nbuf[64] = "hello";
    wchar_t wbuf[64] = L"world";

    /* EXPECT_TCD-08: narrow char* passed to wcslen which expects wchar_t* */
    size_t n = wcslen(nbuf);   /* wrong */
    (void)n;

    /* EXPECT_TCD-08: wide wchar_t* passed to strlen which expects char* */
    size_t m = strlen(wbuf);   /* wrong */
    (void)m;

    /* CLEAN: correct narrow usage */
    size_t nl = strlen(nbuf);
    (void)nl;

    /* CLEAN: correct wide usage */
    size_t wl = wcslen(wbuf);
    (void)wl;
}


/* -----------------------------------------------------------------------
 * TCD-09  sign_change_return
 * --------------------------------------------------------------------- */

/* EXPECT_TCD-09: function returns unsigned int but we return signed variable */
unsigned int tcd09_bad_return(int x) {
    int neg = x - 100;
    return neg;    /* negative neg becomes huge positive unsigned */
}

/* CLEAN: explicit cast signals intent */
unsigned int tcd09_ok_cast(int x) {
    int neg = x - 100;
    return (unsigned int)neg;
}

/* CLEAN: unsigned return, unsigned variable */
unsigned int tcd09_all_unsigned(unsigned int x) {
    unsigned int y = x + 1u;
    return y;
}


/* -----------------------------------------------------------------------
 * TCD-10  implicit_narrowing_arith
 * --------------------------------------------------------------------- */
void tcd10_examples(void) {
    int   a = 1000, b = 1000;

    /* EXPECT_TCD-10: int arithmetic result stored in short without cast */
    short s = a + b;
    (void)s;

    /* EXPECT_TCD-10: int arithmetic result stored in char without cast */
    char  c = a * 2;
    (void)c;

    /* CLEAN: explicit narrowing cast — programmer acknowledges truncation */
    short s2 = (short)(a + b);
    (void)s2;

    /* CLEAN: wide destination */
    int   wide = a + b;
    (void)wide;
}
