#include "telemetry_types.h"

__declspec(noinline) int handle_record(const Rec *r, int *crc, int *error_state) {
    if (!r || !crc || !error_state) return -1;
    switch (r->type) {
    case TYPE_NUMBER:
        *crc = crc_add(*crc, r->payload);
        break;
    case TYPE_DELTA:
        *crc = crc_add(*crc, r->payload + r->len);
        break;
    case TYPE_TEXT:
        *crc = crc_add(*crc, r->len);
        break;
    default:
        *error_state = 1;
        break;
    }
    return 0;
}
