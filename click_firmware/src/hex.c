#include "hex.h"

static int nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(const char *hex, uint8_t *out, int out_max) {
    int n = 0, hi = -1;
    for (; *hex; ++hex) {
        if (*hex == ':' || *hex == ' ' || *hex == '#') continue;
        int v = nib(*hex);
        if (v < 0) return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_max) return -1;
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) return -1;   /* odd number of nibbles */
    return n;
}

int hex_encode(const uint8_t *in, int len, char *out, int out_max) {
    static const char D[] = "0123456789abcdef";
    int o = 0;
    for (int i = 0; i < len; ++i) {
        if (o + 2 >= out_max) break;
        out[o++] = D[in[i] >> 4];
        out[o++] = D[in[i] & 0xF];
    }
    out[o] = 0;
    return o;
}
