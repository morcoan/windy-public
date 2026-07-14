
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
typedef int (*cb)(int);
__declspec(noinline) int id(int x) { return x; }
__declspec(noinline) int run(cb f, int x) { return f(x) + 1; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return run(id, 40); }
