/* Boss 3 SEH/resource stand-in using structured cleanup simulation */

/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;

typedef struct Res { int id; int live; } Res;
__declspec(noinline) static void res_init(Res *r, int id) { r->id = id; r->live = 1; }
__declspec(noinline) static void res_destroy(Res *r) { if (r->live) { r->live = 0; } }
__declspec(noinline) int parse_tree(const int *buf, int n, int depth) {
    Res a, b; int i, status = 0;
    res_init(&a, 1); res_init(&b, 2);
    if (depth > 8) { status = -1; goto cleanup; }
    for (i = 0; i < n; i = i + 1) {
        if (buf[i] < 0) { status = -2; goto cleanup; }
        if (buf[i] == 0) break;
        a.id = a.id + buf[i];
    }
cleanup:
    res_destroy(&b);
    res_destroy(&a);
    return status ? status : a.id;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    int buf[4]; buf[0]=1; buf[1]=2; buf[2]=0; buf[3]=-1;
    return parse_tree(buf, 4, 1);
}
