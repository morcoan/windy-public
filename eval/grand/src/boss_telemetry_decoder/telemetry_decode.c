#include "telemetry_types.h"

__declspec(noinline) int crc_add(int crc, int v) {
    return crc ^ (v * 1315423911);
}

__declspec(noinline) int decode_packet(const unsigned char *buf, int size, int *out_status) {
    const unsigned char *end;
    const unsigned char *cursor;
    int records_seen = 0;
    int crc = 0;
    int error_state = 0;
    Header h;

    if (!out_status) return 0;
    *out_status = 0;
    if (size < 8 || !buf) {
        *out_status = -1;
        return 0;
    }
    if (read_header(buf, size, &h) != 0) {
        *out_status = -1;
        return 0;
    }
    end = buf + size;
    cursor = buf + 8;
    while (cursor + 12 <= end && records_seen < h.record_count) {
        Rec r;
        r.type = (int)(cursor[0] | (cursor[1] << 8) | (cursor[2] << 16) | (cursor[3] << 24));
        r.len = (int)(cursor[4] | (cursor[5] << 8) | (cursor[6] << 16) | (cursor[7] << 24));
        r.payload = (int)(cursor[8] | (cursor[9] << 8) | (cursor[10] << 16) | (cursor[11] << 24));
        cursor += 12;
        handle_record(&r, &crc, &error_state);
        records_seen = records_seen + 1;
    }
    *out_status = error_state ? -2 : 0;
    return crc ^ records_seen ^ 0x45D9F3B;
}
