
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int idx_sum(const int *a, int n) {
    int s = 0, i;
    for (i = 0; i < n; i = i + 1) s = s + a[i];
    return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    volatile int a[3]; a[0]=10; a[1]=20; a[2]=30;
    volatile int n = 3;
    return idx_sum((const int*)a, n);
}
