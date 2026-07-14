
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int classify(int n) {
    switch (n) {
    case 0: return 10;
    case 1: return 20;
    case 2: return 30;
    default: return -1;
    }
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; volatile int _n = 2; return classify(_n); }
