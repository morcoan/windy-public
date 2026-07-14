
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
typedef struct Point { int x; int y; } Point;
__declspec(noinline) int point_mag2(Point p) { return p.x * p.x + p.y * p.y; }
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    Point p; p.x = 3; p.y = 4;
    return point_mag2(p);
}
