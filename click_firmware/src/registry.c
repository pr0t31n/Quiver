/* registry.c — the table of Click drivers + shared param parser. */
#include "click_driver.h"
#include <string.h>

extern const click_driver_t can_spi_driver;
extern const click_driver_t serial_rs232_driver;
extern const click_driver_t serial_rs485_driver;
extern const click_driver_t xbee_driver;
extern const click_driver_t uwb_driver;
extern const click_driver_t nfc_driver;
extern const click_driver_t nbiot_driver;

const click_driver_t * const CLICK_DRIVERS[] = {
    &can_spi_driver,
    &serial_rs232_driver,
    &serial_rs485_driver,
    &xbee_driver,
    &uwb_driver,
    &nfc_driver,
    &nbiot_driver,
};
const int CLICK_DRIVERS_COUNT =
    (int)(sizeof(CLICK_DRIVERS) / sizeof(CLICK_DRIVERS[0]));

const click_driver_t *click_by_id(const char *id) {
    for (int i = 0; i < CLICK_DRIVERS_COUNT; ++i)
        if (strcmp(CLICK_DRIVERS[i]->id, id) == 0)
            return CLICK_DRIVERS[i];
    return 0;
}

/* Parse "k=v k=v ..." — copy the value for `key` into val (NUL-terminated).
 * Returns 1 if found, 0 otherwise. */
int click_kv_get(const char *kv, const char *key, char *val, int val_max) {
    if (!kv || val_max <= 0) return 0;
    int klen = (int)strlen(key);
    const char *p = kv;
    while (*p) {
        while (*p == ' ') p++;
        const char *tok = p;
        while (*p && *p != ' ') p++;
        const char *eq = tok;
        while (eq < p && *eq != '=') eq++;
        if (eq < p && (eq - tok) == klen && strncmp(tok, key, klen) == 0) {
            int n = (int)(p - (eq + 1));
            if (n >= val_max) n = val_max - 1;
            memcpy(val, eq + 1, n);
            val[n] = 0;
            return 1;
        }
    }
    return 0;
}
