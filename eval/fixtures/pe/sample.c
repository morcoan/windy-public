/* Known-source C test program for decompiler comparison.

   Three deliberately distinct functions:

     add(a, b)        — trivial arithmetic, leaf, no control flow.
     strlen_local(s)  — loop with memory access + branch + return.
     max3(a, b, c)    — multiple branches, decision tree, leaf.

   Compiled with `cl /O0` (default, no inlining) at MSVC.  We do NOT
   mark anything `static` so the symbols stay exported for windy to find.
*/

int add(int a, int b) {
    return a + b;
}

int strlen_local(const char *s) {
    int n = 0;
    while (s[n]) {
        n = n + 1;
    }
    return n;
}

int max3(int a, int b, int c) {
    int m = a;
    if (b > m) m = b;
    if (c > m) m = c;
    return m;
}

/* Required so MSVC links an EXE.  Calls each function so the linker
   doesn't dead-strip them. */
int main(void) {
    volatile int x = add(2, 3);
    volatile const char *s = "hello";
    volatile int y = strlen_local((const char *)s);
    volatile int z = max3(x, y, 10);
    return x + y + z;
}
