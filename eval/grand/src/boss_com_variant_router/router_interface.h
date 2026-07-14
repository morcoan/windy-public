#ifndef ROUTER_INTERFACE_H
#define ROUTER_INTERFACE_H

/* Boss 2: COM/VARIANT stand-in (controlled interface, no full WinSDK required). */

typedef struct Variant {
    int vt;
    union {
        int i;
        void *bstr;
        void *punk;
    } u;
} Variant;

enum { VT_I4 = 3, VT_BSTR = 8, VT_UNKNOWN = 13 };

int QueryInterface(void *self, const int *iid, void **ppv);
int AddRef(void);
int Release(void);
int route_variant(Variant *v);

#endif
