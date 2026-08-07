/*
 * click_driver.h — the interface every Click driver implements.
 *
 * Each driver file defines exactly one (or more) `const click_driver_t <id>_driver`
 * and is listed in registry.c. `sock` is the 0-based socket index (host "socket
 * N" -> sock N-1). Use the mikrobus[] helpers for all bus access, and the
 * proto_* helpers to talk to the host.
 *
 * Contract:
 *   - probe()      : quick, side-effect-light bus probe. Return 1 if THIS chip
 *                    is present in the socket, else 0. Powers host "SCAN"/autodetect.
 *   - configure()  : parse "k=v k=v" params (may be ""). Return 0 on success.
 *   - selftest()   : deeper health check. Return 0 = OK, negative = fail; you may
 *                    proto_reply() extra detail. Powers host diagnostics stage 6.
 *   - sniff_start(): arm capture (count<=0 = unlimited). Return 0 on success.
 *   - sniff_poll() : non-blocking; called each loop while sniffing. Emit frames
 *                    via proto_emit_rx() and call proto_sniff_count_inc().
 *   - sniff_stop() : disarm capture.
 *   - tx()         : transmit ONE frame from ASCII hex ("<id>#<data>" for CAN).
 *                    Return 0 on success.
 *   - flood()      : repeat tx count times, gap_ms apart (NULL if unsupported).
 *   - special()    : click-specific verbs (NFC READ/EMULATE/RELAY, UWB RANGE/RELAY,
 *                    AT passthrough). argv[0] is the verb. NULL if none.
 */
#ifndef CLICK_DRIVER_H
#define CLICK_DRIVER_H

#include <stdint.h>

typedef struct click_driver {
    const char *id;      /* "can_spi", "rs485_8", ... (matches host CLICKS keys) */
    const char *chip;    /* reported by SCAN, e.g. "MCP2515", "DW3000", "PN7150" */
    const char *bus;     /* "SPI" | "I2C" | "UART" */
    int  (*probe)(uint8_t sock);
    int  (*configure)(uint8_t sock, const char *kv);
    int  (*selftest)(uint8_t sock);
    int  (*sniff_start)(uint8_t sock, int count);
    void (*sniff_poll)(uint8_t sock);
    void (*sniff_stop)(uint8_t sock);
    int  (*tx)(uint8_t sock, const char *frame);
    int  (*flood)(uint8_t sock, const char *frame, uint32_t count, uint32_t gap_ms);
    int  (*special)(uint8_t sock, int argc, char **argv);
} click_driver_t;

/* Small helper for parsing "k=v" tokens out of a params string (in configure()).
 * Returns 1 and fills val[] if key found, else 0. */
int click_kv_get(const char *kv, const char *key, char *val, int val_max);

/* Registry (registry.c) */
extern const click_driver_t * const CLICK_DRIVERS[];
extern const int CLICK_DRIVERS_COUNT;
const click_driver_t *click_by_id(const char *id);

#endif /* CLICK_DRIVER_H */
