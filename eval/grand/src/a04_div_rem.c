
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int idiv(int a, int b) { return b ? a / b : 0; }
__declspec(noinline) int irem(int a, int b) { return b ? a % b : 0; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; return idiv(17, 5) + irem(17, 5); }
