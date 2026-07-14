
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int four(int a, int b, int c, int d) { return a + b + c + d; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return four(1, 2, 3, 4); }
