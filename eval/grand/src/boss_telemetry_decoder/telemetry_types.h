/* Boss 1: telemetry_decoder — shared types (multi-TU) */
#ifndef TELEMETRY_TYPES_H
#define TELEMETRY_TYPES_H

typedef struct Header {
    unsigned short ver;
    unsigned short flags;
    int record_count;
} Header;

typedef struct Rec {
    int type;
    int len;
    int payload;
} Rec;

enum {
    TYPE_NUMBER = 1,
    TYPE_DELTA = 2,
    TYPE_TEXT = 3
};

int crc_add(int crc, int v);
int read_header(const unsigned char *buf, int size, Header *h);
int handle_record(const Rec *r, int *crc, int *error_state);
int decode_packet(const unsigned char *buf, int size, int *out_status);

#endif
