/* test_dangling_return.c — CWE-562
 * Expected: danglingReturn
 * Returning pointer to local variable.
 */
int *bad(void) {
    int local = 42;
    int *p = &local;
    return p;  /* BUG: returning address of local */
}

int main(void) {
    int *q = bad();
    return *q;
}
