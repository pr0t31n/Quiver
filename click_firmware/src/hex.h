/* hex.h — tiny ASCII-hex <-> bytes helpers used by the Click drivers. */
#ifndef HEX_H
#define HEX_H

#include <stdint.h>

/* Decode ASCII hex (ignoring ':' and spaces) into out[]. Returns byte count,
 * or -1 on a malformed nibble / overflow. */
int hex_decode(const char *hex, uint8_t *out, int out_max);

/* Encode len bytes into a NUL-terminated ASCII-hex string. out must hold
 * len*2 + 1 bytes. Returns the string length. */
int hex_encode(const uint8_t *in, int len, char *out, int out_max);

#endif /* HEX_H */
