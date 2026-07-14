#include "telemetry_types.h"

__declspec(noinline) int read_header(const unsigned char *buf, int size, Header *h) {
    if (size < 8 || !h) return -1;
    h->ver = (unsigned short)(buf[0] | (buf[1] << 8));
    h->flags = (unsigned short)(buf[2] | (buf[3] << 8));
    h->record_count = (int)(buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24));
    return 0;
}
