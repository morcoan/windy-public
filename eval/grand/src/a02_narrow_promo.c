
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int narrow_add(signed char a, signed char b) { return (int)a + (int)b; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return narrow_add(100, 50); }
