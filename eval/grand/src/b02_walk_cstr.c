
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
__declspec(noinline) int walk_cstr(const char *s) {
    int n = 0;
    while (s[n] != '\0') n = n + 1;
    return n;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1; return walk_cstr("grand"); }
