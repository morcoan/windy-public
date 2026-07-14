
/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;
﻿/* Boss 2 COM/VARIANT stand-in without real COM deps */
typedef struct Variant { int vt; union { int i; void *bstr; void *punk; } u; } Variant;
enum { VT_I4=3, VT_BSTR=8, VT_UNKNOWN=13 };
static int g_refs;
__declspec(noinline) int QueryInterface(void *self, const int *iid, void **ppv) {
    (void)iid;
    if (!ppv) return 0x80004003;
    *ppv = self; g_refs = g_refs + 1; return 0;
}
__declspec(noinline) int AddRef(void) { g_refs = g_refs + 1; return g_refs; }
__declspec(noinline) int Release(void) { g_refs = g_refs - 1; return g_refs; }
__declspec(noinline) int route_variant(Variant *v) {
    if (!v) return 0x80004003;
    switch (v->vt) {
    case VT_I4: return v->u.i;
    case VT_BSTR: return v->u.bstr ? 1 : 0;
    case VT_UNKNOWN: return v->u.punk ? AddRef() : 0x80004003;
    default: return 0x80070057;
    }
}
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    Variant v; v.vt = VT_I4; v.u.i = 7;
    return route_variant(&v);
}
