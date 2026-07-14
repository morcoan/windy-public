
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int both(int a, int b) { return a != 0 && b != 0; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return both(1, 0); }
