
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
int classify(int n);
__declspec(noinline) int dispatch(int op, int x, int y) {
    switch (op) {
    case 1: return x + y;
    case 2: return x - y;
    case 3: return x * y;
    case 4: return y ? x / y : 0;
    default: return classify(x);
    }
}
__declspec(noinline) int classify(int n) {
    if (n == 0) return 10;
    if (n == 1) return 20;
    if (n == 2) return 30;
    return -1;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; return dispatch(1, 8, 2); }
