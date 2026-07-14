#include "resource_format.h"

__declspec(noinline) void res_init(Res *r, int id) {
    r->id = id;
    r->live = 1;
}

__declspec(noinline) void res_destroy(Res *r) {
    if (r->live) {
        r->live = 0;
    }
}

__declspec(noinline) int parse_tree(const int *buf, int n, int depth) {
    Res a;
    Res b;
    int i;
    int status = 0;
    res_init(&a, 1);
    res_init(&b, 2);
    if (depth > 8) {
        status = -1;
        goto cleanup;
    }
    for (i = 0; i < n; i = i + 1) {
        if (buf[i] < 0) {
            status = -2;
            goto cleanup;
        }
        if (buf[i] == 0) break;
        a.id = a.id + buf[i];
    }
cleanup:
    res_destroy(&b);
    res_destroy(&a);
    return status ? status : a.id;
}
