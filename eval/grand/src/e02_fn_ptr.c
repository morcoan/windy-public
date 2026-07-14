
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int add1(int x) { return x + 1; }
__declspec(noinline) int apply(int (*f)(int), int x) { return f(x); }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return apply(add1, 41); }
