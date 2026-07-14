
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int kernel(const int *a, int n, int k) {
    int i;
    for (i=0;i<n;i=i+1) if (a[i]==k) return i;
    return -1;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; int arr[3]; arr[0]=9; arr[1]=7; arr[2]=3; return kernel(arr, 3, 7); }
