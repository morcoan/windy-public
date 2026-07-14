
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int f(int a, int b, int c) {
    int r = a + b; return r < a ? -1 : r;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; return f(3, 5, 7); }
