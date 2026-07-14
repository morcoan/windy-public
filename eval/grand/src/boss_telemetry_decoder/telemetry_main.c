#include "telemetry_types.h"

int main(void) {
    unsigned char pkt[32];
    int st = 0;
    int i;
    for (i = 0; i < 32; i = i + 1) {
        pkt[i] = (unsigned char)i;
    }
    /* record_count = 1 little-endian at offset 4 */
    pkt[4] = 1;
    pkt[5] = 0;
    pkt[6] = 0;
    pkt[7] = 0;
    return decode_packet(pkt, 32, &st) + st;
}
