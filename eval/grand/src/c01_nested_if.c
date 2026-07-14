
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int nested_decide(int a, int b, int c) {
    if (a > 0) {
        if (b > 0) return a + b;
        else return a - b;
    } else {
        if (c != 0) return c * 2;
        else return 0;
    }
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; return nested_decide(1, -2, 3); }
