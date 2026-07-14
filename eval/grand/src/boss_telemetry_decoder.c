/* Boss 1 telemetry_decoder (single-TU stand-in for multi-module LTCG build) */

/* anti-DCE / anti-fold sink for optimized profiles */
static volatile int g_windy_sink;

typedef struct Header { unsigned short ver; unsigned short flags; int record_count; } Header;
typedef struct Rec { int type; int len; int payload; } Rec;
__declspec(noinline) static int crc_add(int crc, int v) { return crc ^ (v * 1315423911); }
__declspec(noinline) int decode_packet(const unsigned char *buf, int size, int *out_status) {
    const unsigned char *end = buf + size;
    const unsigned char *cursor = buf;
    int records_seen = 0, crc = 0, error_state = 0;
    Header h;
    if (size < 8) { *out_status = -1; return 0; }
    h.ver = (unsigned short)(buf[0] | (buf[1]<<8));
    h.flags = (unsigned short)(buf[2] | (buf[3]<<8));
    h.record_count = (int)(buf[4] | (buf[5]<<8) | (buf[6]<<16) | (buf[7]<<24));
    cursor = buf + 8;
    while (cursor + 12 <= end && records_seen < h.record_count) {
        Rec r;
        r.type = (int)(cursor[0] | (cursor[1]<<8) | (cursor[2]<<16) | (cursor[3]<<24));
        r.len = (int)(cursor[4] | (cursor[5]<<8) | (cursor[6]<<16) | (cursor[7]<<24));
        r.payload = (int)(cursor[8] | (cursor[9]<<8) | (cursor[10]<<16) | (cursor[11]<<24));
        cursor += 12;
        switch (r.type) {
        case 1: crc = crc_add(crc, r.payload); break;
        case 2: crc = crc_add(crc, r.payload + r.len); break;
        case 3: crc = crc_add(crc, r.len); break;
        default: error_state = 1; break;
        }
        records_seen = records_seen + 1;
    }
    *out_status = error_state ? -2 : 0;
    return crc ^ records_seen ^ 0x45D9F3B;
}
int main(void) { g_windy_sink = g_windy_sink ^ 1;
    unsigned char pkt[32];
    int st = 0, i;
    for (i=0;i<32;i++) pkt[i]=(unsigned char)i;
    pkt[4]=1; pkt[5]=0; pkt[6]=0; pkt[7]=0;
    return decode_packet(pkt, 32, &st) + st;
}
