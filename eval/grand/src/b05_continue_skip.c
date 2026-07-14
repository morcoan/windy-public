
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int kernel(const int *a, int n) {
    int s=0, i;
    for (i=0;i<n;i=i+1) { if (a[i] < 0) continue; s = s + a[i]; }
    return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; int arr[4]; arr[0]=1; arr[1]=-1; arr[2]=3; arr[3]=4; return kernel(arr, 4); }
