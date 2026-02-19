// unusedVariable_basic.c — Assignment to variable without use
void bar(void) {
    int total = 42;  // BUG: never read
}
