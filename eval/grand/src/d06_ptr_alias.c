
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int f(int *p, int *q) { *p = 1; *q = 2; return *p + *q; }
int main(void) { g_windy_sink = g_windy_sink ^ 1; int x=0,y=0; return f(&x,&y); }
