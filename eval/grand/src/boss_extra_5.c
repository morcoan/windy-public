
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int deep(int n) {
    int s=0,i; for(i=0;i<n;i++) s = s + i * (i+1);
    return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int _n = 15; return deep(_n); }
