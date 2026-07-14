
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int step(int op, int x) {
    switch(op) {
    case 0: return x+1;
    case 1: return x-1;
    default: return x;
    }
}
__declspec(noinline) int run(int n) {
    int i, s=0; for(i=0;i<n;i++) s = step(i&1, s);
    return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int _n = 5; return run(_n); }
