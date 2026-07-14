
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int count_down(int n) {
    int s = 0;
    while (n > 0) { s = s + n; n = n - 1; }
    return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int n = 5; return count_down(n); }
