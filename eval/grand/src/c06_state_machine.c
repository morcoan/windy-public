
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int f(int a, int b, int c) {
    int s=0; if(a) s=1; if(b&&s) s=2; return s;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; return f(3, 5, 7); }
