/*
 * serial_click.c — passive UART transceiver Clicks:
 *   RS232 4 Click  (RS-232 line driver/receiver, full-duplex)  -> serial_rs232_driver
 *   RS485 8 Click  (RS-485 transceiver, half-duplex)           -> serial_rs485_driver
 *
 * Both are dumb line transceivers: there is no addressable chip to query, so
 * they CANNOT be autodetected. probe() always returns 0 and SCAN reports none.
 *
 * Frame text form (host <-> MCU): raw ASCII-hex of the wire bytes, e.g. 48656c6c6f.
 * Sniffing drains the socket UART and emits captured bytes as RX lines.
 */
#include "click_driver.h"
#include "mikrobus.h"
#include "protocol.h"
#include "hex.h"
#include "board.h"
#include <string.h>
#include <stdlib.h>

/* Capture tuning. TODO: tune LINE_MAX / IDLE_GAP_US per real baud + traffic. */
#define SER_LINE_MAX   256          /* bytes buffered before a forced flush */
#define SER_IDLE_GAP_US 20000u      /* flush after this quiet gap (~20 ms) */

static int      s_sniffing[MIKROBUS_COUNT];
static uint8_t  s_half_duplex[MIKROBUS_COUNT];      /* 1 = RS485, 0 = RS232 */
static uint32_t s_baud[MIKROBUS_COUNT];
static uint8_t  s_buf[MIKROBUS_COUNT][SER_LINE_MAX];
static int      s_len[MIKROBUS_COUNT];
static uint32_t s_last_us[MIKROBUS_COUNT];          /* time of last received byte */

/* ---- shared helpers -------------------------------------------------- */

static uint32_t ser_read_baud(const char *kv) {
    char v[16];
    if (click_kv_get(kv, "baud", v, sizeof v)) {
        long b = strtol(v, NULL, 10);
        if (b > 0) return (uint32_t)b;
    }
    return 115200;      /* default */
}

static int ser_apply(uint8_t s, const char *kv, int half_duplex) {
    s_half_duplex[s] = (uint8_t)(half_duplex ? 1 : 0);
    s_baud[s] = ser_read_baud(kv);
    /* TODO: RS485 8 Click has a DE/RE direction pin on the mikroBUS CS/PWM line;
     * driving it for TX/RX turnaround needs mb_cs_* wiring once verified. */
    return mb_uart_config(s, s_baud[s], s_half_duplex[s]);
}

static void ser_flush(uint8_t s) {
    if (s_len[s] <= 0) return;
    char hx[SER_LINE_MAX * 2 + 1];
    hex_encode(s_buf[s], s_len[s], hx, (int)sizeof hx);
    proto_emit_rx(s + 1, board_micros(), hx);
    proto_sniff_count_inc(s);
    s_len[s] = 0;
}

/* ---- driver ops (shared between RS232 + RS485) ----------------------- */

static int ser_probe(uint8_t s) { (void)s; return 0; }   /* passive: not detectable */

static int ser_configure_rs232(uint8_t s, const char *kv) { return ser_apply(s, kv, 0); }
static int ser_configure_rs485(uint8_t s, const char *kv) { return ser_apply(s, kv, 1); }

static int ser_selftest(uint8_t s) {
    /* Light check: re-apply the UART config; a real loopback needs external
     * wiring (RS232 TX<->RX jumper, or an RS485 bus peer), so we can't verify
     * the line here. TODO: add opt-in loopback when a jumper is present. */
    mb_uart_config(s, s_baud[s] ? s_baud[s] : 115200, s_half_duplex[s]);
    proto_reply("%s passive transceiver: cannot loopback-test without external wiring",
                s_half_duplex[s] ? "RS485" : "RS232");
    return 0;
}

static int ser_sniff_start(uint8_t s, int count) {
    (void)count;
    s_len[s] = 0;
    s_last_us[s] = board_micros();
    s_sniffing[s] = 1;
    return 0;
}

static void ser_sniff_stop(uint8_t s) {
    if (s_sniffing[s]) ser_flush(s);
    s_sniffing[s] = 0;
}

static void ser_sniff_poll(uint8_t s) {
    if (!s_sniffing[s]) return;
    int got = 0;
    for (;;) {
        int c = mb_uart_rx_byte(s);
        if (c < 0) break;
        got = 1;
        s_last_us[s] = board_micros();
        s_buf[s][s_len[s]++] = (uint8_t)c;
        if (c == '\n' || s_len[s] >= SER_LINE_MAX) { ser_flush(s); }
        if (!proto_sniff_active(s)) { s_sniffing[s] = 0; return; }
    }
    /* Idle-gap flush: emit a partial line once the wire has gone quiet. */
    if (!got && s_len[s] > 0 &&
        (uint32_t)(board_micros() - s_last_us[s]) >= SER_IDLE_GAP_US) {
        ser_flush(s);
    }
}

static int ser_tx(uint8_t s, const char *frame) {
    uint8_t bytes[FRAME_HEX_MAX / 2];
    int n = hex_decode(frame, bytes, (int)sizeof bytes);
    if (n < 0) return -1;
    /* TODO: for RS485, assert DE before TX and release after the last byte
     * has shifted out once the direction pin is wired. */
    return (mb_uart_tx(s, bytes, (uint16_t)n) == 0) ? 0 : -1;
}

static int ser_flood(uint8_t s, const char *frame, uint32_t count, uint32_t gap_ms) {
    for (uint32_t i = 0; i < count; ++i) {
        if (ser_tx(s, frame) != 0) return -1;
        if (gap_ms) board_delay_ms(gap_ms);
    }
    return 0;
}

/* ---- exported drivers ------------------------------------------------ */

const click_driver_t serial_rs232_driver = {
    .id = "rs232_4", .chip = "RS232", .bus = "UART",
    .probe = ser_probe, .configure = ser_configure_rs232, .selftest = ser_selftest,
    .sniff_start = ser_sniff_start, .sniff_poll = ser_sniff_poll, .sniff_stop = ser_sniff_stop,
    .tx = ser_tx, .flood = 0, .special = 0,      /* RS232 full-duplex: no flood verb */
};

const click_driver_t serial_rs485_driver = {
    .id = "rs485_8", .chip = "RS485", .bus = "UART",
    .probe = ser_probe, .configure = ser_configure_rs485, .selftest = ser_selftest,
    .sniff_start = ser_sniff_start, .sniff_poll = ser_sniff_poll, .sniff_stop = ser_sniff_stop,
    .tx = ser_tx, .flood = ser_flood, .special = 0,
};
