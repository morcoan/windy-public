
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
__declspec(noinline) int sum_until_zero(const int *a, int n) {
    int s=0,i; for(i=0;i<n;i++){ if(a[i]==0) break; s+=a[i]; } return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    int arr[4]; arr[0]=1; arr[1]=2; arr[2]=0; arr[3]=9;
    return clamp(sum_until_zero(arr,4), 0, 100);
}
