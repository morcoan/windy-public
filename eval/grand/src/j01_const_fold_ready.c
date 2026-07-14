
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int f(void) { return 2 + 2 * 3; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return f(); }
