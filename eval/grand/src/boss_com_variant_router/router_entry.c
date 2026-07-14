#include "router_interface.h"

int main(void) {
    Variant v;
    void *p = 0;
    int iid = 1;
    v.vt = VT_I4;
    v.u.i = 7;
    QueryInterface(&v, &iid, &p);
    return route_variant(&v) + (p ? 0 : 1);
}
