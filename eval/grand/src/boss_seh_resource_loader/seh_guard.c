#include "resource_format.h"

#ifdef _MSC_VER
#include <windows.h>
#endif

__declspec(noinline) int filter_av(unsigned long code) {
    /* Distinguish access violation from other exceptions. */
    if (code == 0xC0000005ul) return 1;
    return 0;
}

__declspec(noinline) int seh_load(const int *buf, int n) {
    int status = 0;
#ifdef _MSC_VER
    __try {
        status = parse_tree(buf, n, 1);
    } __except (filter_av(GetExceptionCode()) ? 1 : 0) {
        status = -3; /* SEH path */
    }
#else
    status = parse_tree(buf, n, 1);
#endif
    return status;
}
