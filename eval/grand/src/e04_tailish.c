
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int leaf(int x) { return x * 2; }
__declspec(noinline) int mid(int x) { return leaf(x + 1); }
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int _n = 10; return mid(_n); }
