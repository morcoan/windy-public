
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
typedef struct Tu {
    int tag;
    union { int i; char c; } u;
} Tu;
__declspec(noinline) int tu_value(Tu *t) {
    if (t->tag == 0) return t->u.i;
    return (int)t->u.c;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    Tu t; t.tag = 0; t.u.i = 42;
    return tu_value(&t);
}
