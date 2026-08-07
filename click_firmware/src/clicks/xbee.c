/*
 * xbee.c — XBee 2 Click (Digi XBee module socket) driver.
 *
 * Digi XBee (IEEE 802.15.4 / DigiMesh) module driven over UART. Two modes:
 *   - Command mode (AT): "+++" guard-time escape, then "ATxx <arg>\r" commands.
 *   - API mode (ATAP 1/2): frames start 0x7E len_hi len_lo <payload> <cksum>.
 *
 * SCAN presence: enter command mode with "+++" and look for an "OK" reply.
 * Sniff/TX operate on full API frames (host supplies/receives complete frames).
 */
#include "click_driver.h"
#include "mikrobus.h"
#include "protocol.h"
#include "hex.h"
#include "board.h"
#include <string.h>
#include <stdlib.h>

/* XBee default serial baud. TODO: some modules ship at 115200 (ATBD 7) —
 * make this configurable / auto-detect if probe fails at 9600. */
#define XBEE_BAUD        9600
#define XBEE_GUARD_MS    1100      /* guard time before/after "+++" */
#define XBEE_REPLY_MS    200       /* how long to wait for an AT reply */
#define XBEE_FRAME_MAX   256

static int s_sniffing[MIKROBUS_COUNT];

/* API-frame reassembly state machine, one per socket. */
typedef struct {
    int      st;        /* 0=wait 0x7E, 1=len_hi, 2=len_lo, 3=payload, 4=cksum */
    uint16_t len;       /* payload length from the 2-byte length field */
    uint16_t got;       /* payload bytes collected so far */
    uint8_t  buf[XBEE_FRAME_MAX];
    uint16_t n;         /* total bytes stored in buf (incl. delimiter/len/cksum) */
} api_rx_t;
static api_rx_t s_rx[MIKROBUS_COUNT];

/* Read available bytes for ~ms milliseconds into buf; return count. */
static int xbee_drain(uint8_t s, uint8_t *buf, int max, uint32_t ms) {
    int n = 0;
    for (uint32_t t = 0; t < ms; ++t) {
        int c;
        while ((c = mb_uart_rx_byte(s)) >= 0 && n < max) buf[n++] = (uint8_t)c;
        board_delay_ms(1);
    }
    return n;
}

/* Enter AT command mode: "+++" bracketed by guard time. Return 1 if "OK" seen. */
static int xbee_enter_cmd(uint8_t s) {
    uint8_t rx[64];
    board_delay_ms(XBEE_GUARD_MS);
    mb_uart_tx(s, (const uint8_t *)"+++", 3);
    int n = xbee_drain(s, rx, sizeof rx, XBEE_GUARD_MS);
    for (int i = 0; i + 1 < n; ++i)
        if (rx[i] == 'O' && rx[i + 1] == 'K') return 1;
    return 0;
}

/* Issue an AT command ("ATxx.."), append '\r', read the short reply into
 * out (NUL-terminated). Returns reply length. */
static int xbee_at(uint8_t s, const char *cmd, char *out, int out_max) {
    mb_uart_tx(s, (const uint8_t *)cmd, (uint16_t)strlen(cmd));
    mb_uart_tx(s, (const uint8_t *)"\r", 1);
    int n = xbee_drain(s, (uint8_t *)out, out_max - 1, XBEE_REPLY_MS);
    /* trim trailing CR so proto_reply prints cleanly */
    while (n > 0 && (out[n - 1] == '\r' || out[n - 1] == '\n')) --n;
    out[n] = '\0';
    return n;
}

static void xbee_exit_cmd(uint8_t s) {
    char r[16];
    xbee_at(s, "ATCN", r, sizeof r);   /* exit command mode */
}

static int xbee_probe(uint8_t s) {
    mb_uart_config(s, XBEE_BAUD, 0);
    int ok = xbee_enter_cmd(s);
    if (ok) xbee_exit_cmd(s);
    return ok ? 1 : 0;
}

static int xbee_configure(uint8_t s, const char *kv) {
    char v[16], cmd[32];
    const char *channel = "15", *panid = "1234", *api = "2";
    if (click_kv_get(kv, "channel", v, sizeof v)) channel = strcpy(cmd + 24, v);
    if (click_kv_get(kv, "panid", v, sizeof v))   panid   = strcpy(cmd + 24, v);
    /* (channel/panid indirection above keeps them alive; overwrite guarded below) */
    char ch[16], pid[16], ap[16];
    strncpy(ch, channel, sizeof ch - 1); ch[sizeof ch - 1] = '\0';
    strncpy(pid, panid, sizeof pid - 1); pid[sizeof pid - 1] = '\0';
    if (click_kv_get(kv, "api_mode", v, sizeof v)) api = strcpy(ap, v);

    mb_uart_config(s, XBEE_BAUD, 0);
    if (!xbee_enter_cmd(s)) { proto_reply("no command-mode response"); return -1; }
    char r[32];
    snprintf(cmd, sizeof cmd, "ATCH %s", ch);  xbee_at(s, cmd, r, sizeof r);
    snprintf(cmd, sizeof cmd, "ATID %s", pid); xbee_at(s, cmd, r, sizeof r);
    snprintf(cmd, sizeof cmd, "ATAP %s", api); xbee_at(s, cmd, r, sizeof r);
    xbee_at(s, "ATWR", r, sizeof r);           /* persist to flash */
    xbee_exit_cmd(s);
    return 0;
}

static int xbee_selftest(uint8_t s) {
    mb_uart_config(s, XBEE_BAUD, 0);
    if (!xbee_enter_cmd(s)) { proto_reply("XBee command mode not responding"); return -1; }
    char vr[32], ch[16];
    xbee_at(s, "ATVR", vr, sizeof vr);
    xbee_at(s, "ATCH", ch, sizeof ch);
    proto_reply("XBee VR=%s CH=%s", vr, ch);
    xbee_exit_cmd(s);
    return 0;
}

static int xbee_sniff_start(uint8_t s, int count) {
    (void)count;
    mb_uart_config(s, XBEE_BAUD, 0);
    memset(&s_rx[s], 0, sizeof s_rx[s]);
    s_sniffing[s] = 1;
    return 0;
}
static void xbee_sniff_stop(uint8_t s) { s_sniffing[s] = 0; }

/* Non-blocking: reassemble one API frame from the byte stream.
 * TODO: non-API (transparent) mode would need a timeout-delimited capture like
 * the serial driver — this path assumes API mode (ATAP 1/2). */
static void xbee_sniff_poll(uint8_t s) {
    if (!s_sniffing[s]) return;
    api_rx_t *f = &s_rx[s];
    int c;
    while ((c = mb_uart_rx_byte(s)) >= 0) {
        uint8_t b = (uint8_t)c;
        switch (f->st) {
        case 0:
            if (b == 0x7E) { f->n = 0; f->buf[f->n++] = b; f->st = 1; }
            break;
        case 1:
            f->len = (uint16_t)b << 8; f->buf[f->n++] = b; f->st = 2;
            break;
        case 2:
            f->len |= b; f->buf[f->n++] = b; f->got = 0;
            if (f->len == 0 || f->len > XBEE_FRAME_MAX - 4) f->st = 0;  /* junk */
            else f->st = 3;
            break;
        case 3:
            f->buf[f->n++] = b;
            if (++f->got >= f->len) f->st = 4;
            break;
        case 4: {
            f->buf[f->n++] = b;                 /* checksum byte */
            char hx[XBEE_FRAME_MAX * 2 + 1];
            hex_encode(f->buf, f->n, hx, sizeof hx);
            proto_emit_rx(s + 1, board_micros(), hx);
            proto_sniff_count_inc(s);
            f->st = 0;
            break;
        }
        default: f->st = 0; break;
        }
        if (f->n >= XBEE_FRAME_MAX) f->st = 0;  /* overflow guard */
    }
}

static int xbee_tx(uint8_t s, const char *frame) {
    /* frame is a complete API frame in ASCII hex (0x7E ... checksum).
     * TODO: could wrap a raw payload into a 0x7E API TX-request frame here. */
    uint8_t buf[XBEE_FRAME_MAX];
    int n = hex_decode(frame, buf, sizeof buf);
    if (n <= 0) return -1;
    return (mb_uart_tx(s, buf, (uint16_t)n) == 0) ? 0 : -1;
}

static int xbee_flood(uint8_t s, const char *frame, uint32_t count, uint32_t gap_ms) {
    for (uint32_t i = 0; i < count; ++i) {
        if (xbee_tx(s, frame) != 0) return -1;
        if (gap_ms) board_delay_ms(gap_ms);
    }
    return 0;
}

const click_driver_t xbee_driver = {
    .id = "xbee_2", .chip = "XBEE", .bus = "UART",
    .probe = xbee_probe, .configure = xbee_configure, .selftest = xbee_selftest,
    .sniff_start = xbee_sniff_start, .sniff_poll = xbee_sniff_poll, .sniff_stop = xbee_sniff_stop,
    .tx = xbee_tx, .flood = xbee_flood, .special = 0,
};
