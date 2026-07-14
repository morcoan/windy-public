#include "resource_format.h"

int main(void) {
    int buf[4];
    buf[0] = 1;
    buf[1] = 2;
    buf[2] = 0;
    buf[3] = -1;
    return seh_load(buf, 4);
}
