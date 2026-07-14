
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int imin(int a, int b) { return a < b ? a : b; }
__declspec(noinline) int iabs(int x) { return x < 0 ? -x : x; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return imin(3, iabs(-5)); }
