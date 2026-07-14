
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int signed_lt(int a, int b) { return a < b; }
__declspec(noinline) int unsigned_lt(unsigned a, unsigned b) { return a < b; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int x = signed_lt(-1, 1); x += unsigned_lt(1u, 2u); return x; }
