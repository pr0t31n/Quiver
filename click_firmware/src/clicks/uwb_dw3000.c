/*
 * uwb_dw3000.c — UWB 3 Click (Qorvo DW3000) driver.
 * IEEE 802.15.4z HRP UWB transceiver, SPI. Reference: can_spi.c.
 *
 * Real, verified bit: the DW3000 DEV_ID register (reg file 0x00, sub 0x00)
 * reads 0xDECA0302 as four little-endian bytes — used for probe/selftest.
 *
 * !!! TODO — the exact DW3000 SPI header/transaction encoding (fast-command vs
 *     short/long addressed transactions, the sub-address split, RX/TX paths and
 *     the full config/ranging stack) MUST be finalized against the Qorvo DW3000
 *     User Manual + DW3000 API/driver. Everything below the DEV_ID probe is a
 *     scaffold with explicit TODOs.
 */
#include "click_driver.h"
#include "mikrobus.h"
#include "protocol.h"
#include "hex.h"
#include "board.h"
#include <string.h>
#include <stdlib.h>

/* DW3000 register files (short address form) */
#define DW_REG_DEV_ID      0x00        /* sub 0x00 -> 0xDECA0302 (LE) */
#define DW_REG_SYS_STATUS  0x0F        /* TODO: verify file id + RXFCG bit */
#define DW_REG_RX_BUFFER   0x12        /* TODO: verify RX frame buffer file id */

#define DW_DEV_ID_EXPECT   0xDECA0302u

static int      s_sniffing[MIKROBUS_COUNT];
static uint8_t  s_channel[MIKROBUS_COUNT];    /* config "channel=" (default 5) */
static uint8_t  s_preamble[MIKROBUS_COUNT];   /* config "preamble=" (default 9) */

/*
 * dw_read — read n bytes from (reg_file, sub) into buf.
 *
 * TODO: FINALIZE against the DW3000 User Manual. The DW3000 uses a transaction
 * header where bit7 selects read(0)/write(1) and bits6..1 carry the register
 * file id; a second header byte carries the sub-address when addressed mode is
 * used. The 0x40|(reg_file<<1) form below is a plausible short-addr READ header
 * placeholder ONLY and must be replaced with the exact Qorvo encoding.
 */
static int dw_read(uint8_t s, uint8_t reg_file, uint8_t sub, uint8_t *buf, int n) {
    uint8_t tx[2 + 64];
    uint8_t rx[2 + 64];
    if (n > 64) n = 64;
    memset(tx, 0, sizeof tx);
    tx[0] = (uint8_t)(0x40 | (reg_file << 1));   /* TODO: exact READ header */
    tx[1] = sub;                                 /* TODO: exact sub-addr byte */
    mb_cs_low(s);
    int rc = mb_spi_txrx(s, tx, rx, (uint16_t)(2 + n));
    mb_cs_high(s);
    if (rc < 0) return rc;
    memcpy(buf, rx + 2, (size_t)n);              /* data trails the 2-byte header */
    return n;
}

static uint32_t dw_dev_id(uint8_t s) {
    uint8_t b[4] = {0};
    dw_read(s, DW_REG_DEV_ID, 0x00, b, 4);
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static int uwb_probe(uint8_t s) {
    mb_rst_pulse(s, 2);
    return (dw_dev_id(s) == DW_DEV_ID_EXPECT) ? 1 : 0;
}

static int uwb_configure(uint8_t s, const char *kv) {
    char v[16];
    s_channel[s]  = 5;
    s_preamble[s] = 9;
    if (click_kv_get(kv, "channel", v, sizeof v))  s_channel[s]  = (uint8_t)atoi(v);
    if (click_kv_get(kv, "preamble", v, sizeof v)) s_preamble[s] = (uint8_t)atoi(v);
    /* TODO: apply channel/preamble to the DW3000 config registers (CHAN_CTRL,
     * TX/RX PLEN, PRF, PAC, SFD, etc.) per the User Manual. */
    proto_reply("DW3000 config channel=%u preamble=%u", s_channel[s], s_preamble[s]);
    return 0;
}

static int uwb_selftest(uint8_t s) {
    uint32_t id = dw_dev_id(s);
    uint8_t b[4] = { (uint8_t)id, (uint8_t)(id >> 8),
                     (uint8_t)(id >> 16), (uint8_t)(id >> 24) };
    char hx[9];
    hex_encode(b, 4, hx, sizeof hx);
    proto_reply("DW3000 DEV_ID=%s", hx);
    return (id == DW_DEV_ID_EXPECT) ? 0 : -1;
}

static int uwb_sniff_start(uint8_t s, int count) {
    (void)count;
    s_sniffing[s] = 1;
    /* TODO: arm RX — set RX auto-enable, clear SYS_STATUS, issue the RX-enable
     * fast command so the DW3000 begins listening on the configured channel. */
    return 0;
}

static void uwb_sniff_stop(uint8_t s) {
    s_sniffing[s] = 0;
    /* TODO: issue the transceiver-off / RX-disable fast command. */
}

static void uwb_sniff_poll(uint8_t s) {
    if (!s_sniffing[s]) return;
    /* TODO — full DW3000 RX path. Sketch of the intended flow:
     *   1. read SYS_STATUS and test the RX-good bit (RXFCG). TODO: exact bit.
     *   2. read the received frame length, then read that many bytes from the
     *      RX frame buffer (DW_REG_RX_BUFFER) via dw_read().
     *   3. hex_encode() the payload and emit:
     *        proto_emit_rx(s + 1, board_micros(), hex);
     *        proto_sniff_count_inc(s);
     *   4. clear the RX status bits and re-arm RX.
     * Documented stub for now — does nothing until the RX path is implemented.
     */
    uint8_t status[4] = {0};
    dw_read(s, DW_REG_SYS_STATUS, 0x00, status, 4);
    /* if (status[?] & RXFCG_BIT) { ... read RX_BUFFER, emit, count_inc ... } */
}

static int uwb_special(uint8_t s, int argc, char **argv) {
    if (argc < 1 || !argv[0]) return -1;
    if (strcmp(argv[0], "RANGE") == 0) {
        /* TODO: implement DS-TWR (double-sided two-way ranging). A distance
         * measurement requires a timed poll/response/final exchange with a peer
         * or anchor and TX/RX timestamp reads — not yet implemented. */
        proto_reply("DW3000 RANGE: two-way ranging with a peer/anchor required (TODO DS-TWR)");
        return 0;
    }
    if (strcmp(argv[0], "RELAY") == 0) {
        /* TODO: authorised relay/replay test — capture a ranging exchange and
         * re-transmit it against a target to assess distance-bounding. */
        proto_reply("DW3000 RELAY: authorised-relay-test placeholder (TODO)");
        return 0;
    }
    proto_reply("DW3000 unknown verb: %s", argv[0]);
    return -1;
}

const click_driver_t uwb_driver = {
    .id = "uwb_3", .chip = "DW3000", .bus = "SPI",
    .probe = uwb_probe, .configure = uwb_configure, .selftest = uwb_selftest,
    .sniff_start = uwb_sniff_start, .sniff_poll = uwb_sniff_poll, .sniff_stop = uwb_sniff_stop,
    .tx = 0, .flood = 0, .special = uwb_special,
};
