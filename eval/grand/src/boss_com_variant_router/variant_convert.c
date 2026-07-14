#include "router_interface.h"

__declspec(noinline) int route_variant(Variant *v) {
    if (!v) return (int)0x80004003;
    switch (v->vt) {
    case VT_I4:
        return v->u.i;
    case VT_BSTR:
        return v->u.bstr ? 1 : 0;
    case VT_UNKNOWN:
        return v->u.punk ? AddRef() : (int)0x80004003;
    default:
        return (int)0x80070057;
    }
}
