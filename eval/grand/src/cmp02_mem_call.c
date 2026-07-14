
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
typedef struct S { int x; int y; } S;
__declspec(noinline) int add2(int a, int b) { return a+b; }
__declspec(noinline) int use_s(S *s) { return add2(s->x, s->y); }
int main(void) { g_windy_sink = g_windy_sink ^ 1; S s; s.x=3; s.y=4; return use_s(&s); }
