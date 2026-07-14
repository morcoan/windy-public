
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int helper(int a, int b) { return a + b + 3; }
__declspec(noinline) int work(int n) {
    int s = 0, i;
    for (i = 0; i < n; i = i + 1) s = helper(s, i);
    return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int _n = 6; return work(_n); }
