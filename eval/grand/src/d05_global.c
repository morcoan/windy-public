
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
static int g;
__declspec(noinline) int f(int x) { g = x; return g + 1; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int _n = 5; return f(_n); }
