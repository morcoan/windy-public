/* Known-source C fixture for analysis and decompiler tests.

   Goals vs the trivial sample.c fixture:
     - nested if/else
     - switch / case / default
     - for-loop with break
     - null-terminated string walk
     - struct field access
     - multi-call dispatch with constants

   Build (MSVC x64, unoptimized so structure stays visible):

     cl /nologo /Od /W3 /TC complex.c /Fe:complex.exe

*/

typedef struct Point {
    int x;
    int y;
} Point;

int clamp(int v, int lo, int hi) {
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

int classify(int n) {
    switch (n) {
    case 0:
        return 10;
    case 1:
        return 20;
    case 2:
        return 30;
    default:
        return -1;
    }
}

int sum_until_zero(const int *a, int n) {
    int s;
    int i;
    s = 0;
    for (i = 0; i < n; i = i + 1) {
        if (a[i] == 0) {
            break;
        }
        s = s + a[i];
    }
    return s;
}

int walk_cstr(const char *s) {
    int n;
    n = 0;
    while (s[n] != '\0') {
        n = n + 1;
    }
    return n;
}

int point_mag2(Point p) {
    return p.x * p.x + p.y * p.y;
}

int nested_decide(int a, int b, int c) {
    if (a > 0) {
        if (b > 0) {
            return a + b;
        } else {
            return a - b;
        }
    } else {
        if (c != 0) {
            return c * 2;
        } else {
            return 0;
        }
    }
}

int dispatch(int op, int x, int y) {
    switch (op) {
    case 1:
        return x + y;
    case 2:
        return x - y;
    case 3:
        return x * y;
    case 4:
        if (y != 0) {
            return x / y;
        }
        return 0;
    default:
        return classify(x);
    }
}

int main(void) {
    volatile int t;
    Point p;
    int arr[4];
    t = 0;
    p.x = 3;
    p.y = 4;
    arr[0] = 1;
    arr[1] = 2;
    arr[2] = 0;
    arr[3] = 9;
    t = t + clamp(-5, 0, 10);
    t = t + classify(2);
    t = t + sum_until_zero(arr, 4);
    t = t + walk_cstr("complex");
    t = t + point_mag2(p);
    t = t + nested_decide(1, -2, 3);
    t = t + dispatch(1, 8, 2);
    return t;
}
