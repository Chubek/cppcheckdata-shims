/*
 * bad_memory_cpp.cpp  —  triggers PLT-01, PLT-02, PLT-04,
 *                         PLT-05, PLT-06, PLT-07
 *
 * Build & dump:
 *   cppcheck --dump bad_memory_cpp.cpp
 *   python3 PointerLifetimeTracker.py bad_memory_cpp.dump
 */
#include <cstdlib>
#include <cstring>
#include <new>

/* ═══════════════════════════════════════════════════════════════════
 * PLT-04 : class has raw-pointer member but no destructor
 * ═══════════════════════════════════════════════════════════════════ */
class NaiveBuffer {
public:
    /* Raw owning pointer — no destructor to free it */
    char *data;          /* PLT-04 trigger: '*data' with ownership name */
    int   size;

    NaiveBuffer(int n) {
        data = new char[n];
        size = n;
    }
    /* BUG: no ~NaiveBuffer() → data is never deleted */
};

/* ═══════════════════════════════════════════════════════════════════
 * PLT-05 : Rule of Three — has destructor, but no copy ctor
 *          or copy assignment operator
 * ═══════════════════════════════════════════════════════════════════ */
class RuleOfThreeBad {
public:
    int *ptr;            /* owning raw pointer */

    RuleOfThreeBad(int n)  { ptr = new int[n]; }
    ~RuleOfThreeBad()      { delete[] ptr; }
    /* BUG: no copy constructor    → shallow copy causes double-free */
    /* BUG: no copy assignment op  → same problem                     */
};

/* ═══════════════════════════════════════════════════════════════════
 * PLT-05 : Rule of Three — has copy ctor and dtor but no copy-assign
 * ═══════════════════════════════════════════════════════════════════ */
class PartialRuleOf3 {
public:
    char *buf;

    PartialRuleOf3(int n)              { buf = new char[n]; }
    ~PartialRuleOf3()                  { delete[] buf; }
    PartialRuleOf3(const PartialRuleOf3 &other) {
        buf = new char[32];
        std::memcpy(buf, other.buf, 32);
    }
    /* BUG: missing operator=(const PartialRuleOf3 &) */
};

/* ═══════════════════════════════════════════════════════════════════
 * PLT-06 : Rule of Five — has Rule-of-Three but no move operations
 * ═══════════════════════════════════════════════════════════════════ */
class RuleOfFiveBad {
public:
    int *mem;

    RuleOfFiveBad(int n)               { mem = new int[n]; }
    ~RuleOfFiveBad()                   { delete[] mem; }
    RuleOfFiveBad(const RuleOfFiveBad &o)            { mem = new int[1]; *mem = *o.mem; }
    RuleOfFiveBad &operator=(const RuleOfFiveBad &o) { *mem = *o.mem; return *this; }
    /* BUG: no move constructor        — inefficient copies in C++11 */
    /* BUG: no move assignment operator — same                        */
};

/* ═══════════════════════════════════════════════════════════════════
 * PLT-01 : new[] allocated, never deleted
 * ═══════════════════════════════════════════════════════════════════ */
void leak_new_array(int n)
{
    int *arr = new int[n];   /* PLT-01: arr never deleted */
    arr[0] = 1;
    /* BUG: delete[] arr missing */
}

/* ═══════════════════════════════════════════════════════════════════
 * PLT-02 : new allocated, free() called instead of delete
 * ═══════════════════════════════════════════════════════════════════ */
void mismatch_new_free()
{
    int *p = new int(42);
    /* BUG: should be delete p, not free */
    free(p);                 /* PLT-02 */
}

/* ═══════════════════════════════════════════════════════════════════
 * PLT-02 : malloc allocated, delete called instead of free
 * ═══════════════════════════════════════════════════════════════════ */
void mismatch_malloc_delete()
{
    int *p = (int *)malloc(sizeof(int));
    *p = 7;
    /* BUG: should be free(p) */
    delete p;                /* PLT-02 */
}

/* ═══════════════════════════════════════════════════════════════════
 * PLT-02 : new[] allocated, delete (scalar) called
 * ═══════════════════════════════════════════════════════════════════ */
void mismatch_new_array_scalar_delete()
{
    int *arr = new int[10];
    /* BUG: should be delete[] arr */
    delete arr;              /* PLT-02 */
}

/* ═══════════════════════════════════════════════════════════════════
 * PLT-07 : C-style malloc/free in C++ function → RAII opportunity
 * ═══════════════════════════════════════════════════════════════════ */
void c_style_alloc_in_cpp(int n)
{
    /* In C++ this should be std::unique_ptr<int[]> arr(new int[n])
       or std::vector<int> arr(n); */
    int *arr = (int *)malloc(n * sizeof(int));  /* PLT-07 */
    if (!arr) return;
    arr[0] = 0;
    free(arr);
}

/* ═══════════════════════════════════════════════════════════════════
 * CORRECT: Rule of Five fully implemented — no warnings expected
 * ═══════════════════════════════════════════════════════════════════ */
class GoodRuleOfFive {
public:
    int *data;
    int  n;

    GoodRuleOfFive(int sz)               : n(sz), data(new int[sz]) {}
    ~GoodRuleOfFive()                    { delete[] data; }
    GoodRuleOfFive(const GoodRuleOfFive &o) : n(o.n), data(new int[o.n])
        { std::memcpy(data, o.data, n * sizeof(int)); }
    GoodRuleOfFive &operator=(const GoodRuleOfFive &o)
        { if (this != &o) { delete[] data; n = o.n; data = new int[n];
                            std::memcpy(data, o.data, n*sizeof(int)); }
          return *this; }
    GoodRuleOfFive(GoodRuleOfFive &&o) noexcept : n(o.n), data(o.data)
        { o.data = nullptr; o.n = 0; }
    GoodRuleOfFive &operator=(GoodRuleOfFive &&o) noexcept
        { if (this != &o) { delete[] data; data = o.data; n = o.n;
                            o.data = nullptr; o.n = 0; }
          return *this; }
};
