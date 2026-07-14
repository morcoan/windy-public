#include "router_interface.h"

static int g_refs;

__declspec(noinline) int QueryInterface(void *self, const int *iid, void **ppv) {
    (void)iid;
    if (!ppv) return (int)0x80004003;
    *ppv = self;
    g_refs = g_refs + 1;
    return 0;
}

__declspec(noinline) int AddRef(void) {
    g_refs = g_refs + 1;
    return g_refs;
}

__declspec(noinline) int Release(void) {
    g_refs = g_refs - 1;
    return g_refs;
}
