
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int six(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; return six(1,2,3,4,5,6); }
