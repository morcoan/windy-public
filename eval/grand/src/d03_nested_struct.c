
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
typedef struct Inner { int v; } Inner;
typedef struct Outer { Inner a; Inner b; } Outer;
__declspec(noinline) int outer_sum(Outer *o) { return o->a.v + o->b.v; }
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    Outer o; o.a.v = 1; o.b.v = 2;
    return outer_sum(&o);
}
