
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int mat_sum(const int *m, int r, int c) {
    int s = 0, i, j;
    for (i = 0; i < r; i = i + 1)
        for (j = 0; j < c; j = j + 1)
            s = s + m[i * c + j];
    return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    volatile int m[4]; m[0]=1;m[1]=2;m[2]=3;m[3]=4;
    volatile int r = 2, c = 2;
    return mat_sum((const int*)m, r, c);
}
