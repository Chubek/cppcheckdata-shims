// uninitVar_basic.c — Use of uninitialised variable
void foo(void) {
    int x;          // not initialised
    int y = x + 1;  // BUG: read of uninitialised x
    (void)y;
}
