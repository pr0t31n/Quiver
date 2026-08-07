/*
 * can_spi.c — CAN SPI Click (Microchip MCP2515 + MCP2551) driver.
 * Reference implementation for the click_driver_t interface.
 *
 * Frame text form (host <-> MCU):  <id_hex>#<data_hex>   e.g.  123#DEADBEEF
 * SCAN presence: after RESET the MCP2515 enters CONFIG mode; CANSTAT[7:5]==0b100.
 */
#include "click_driver.h"
#include "mikrobus.h"
#include "protocol.h"
#include "hex.h"
#include <string.h>
#include <stdlib.h>

/* SPI command bytes */
#define MCP_RESET     0xC0
#define MCP_READ      0x03
#define MCP_WRITE     0x02
#define MCP_RTS_TXB0  0x81
#define MCP_BITMOD    0x05
/* Registers */
#define MCP_CANSTAT   0x0E
#define MCP_CANCTRL   0x0F
#define MCP_CNF3      0x28
#define MCP_CNF2      0x29
#define MCP_CNF1      0x2A
#define MCP_CANINTF   0x2C
#define MCP_RXB0CTRL  0x60
#define MCP_RXB0SIDH  0x61
#define MCP_TXB0SIDH  0x31
/* Modes (CANCTRL[7:5]) */
#define MODE_NORMAL   0x00
#define MODE_CONFIG   0x80
#define MODE_LISTEN   0x60
#define MODE_MASK     0xE0

static int      s_sniffing[MIKROBUS_COUNT];
static uint8_t  s_listen[MIKROBUS_COUNT];   /* config "mode=listen" */

static uint8_t reg_read(uint8_t s, uint8_t reg) {
    uint8_t tx[3] = { MCP_READ, reg, 0x00 }, rx[3] = {0};
    mb_cs_low(s); mb_spi_txrx(s, tx, rx, 3); mb_cs_high(s);
    return rx[2];
}
static void reg_write(uint8_t s, uint8_t reg, uint8_t val) {
    uint8_t tx[3] = { MCP_WRITE, reg, val }, rx[3];
    mb_cs_low(s); mb_spi_txrx(s, tx, rx, 3); mb_cs_high(s);
}
static void mcp_reset(uint8_t s) {
    uint8_t tx = MCP_RESET, rx;
    mb_cs_low(s); mb_spi_txrx(s, &tx, &rx, 1); mb_cs_high(s);
    board_delay_ms(5);
}
static void mcp_set_mode(uint8_t s, uint8_t mode) {
    uint8_t v = reg_read(s, MCP_CANCTRL);
    reg_write(s, MCP_CANCTRL, (v & ~MODE_MASK) | mode);
}

static int can_probe(uint8_t s) {
    mcp_reset(s);
    return ((reg_read(s, MCP_CANSTAT) & MODE_MASK) == MODE_CONFIG) ? 1 : 0;
}

static int can_configure(uint8_t s, const char *kv) {
    char v[16];
    /* bitrate: set CNF1/2/3 (values here are placeholders for a 16 MHz xtal;
     * VERIFY against your Click's crystal + the target bus speed). */
    mcp_reset(s);
    reg_write(s, MCP_CNF1, 0x00);
    reg_write(s, MCP_CNF2, 0x90);
    reg_write(s, MCP_CNF3, 0x02);
    reg_write(s, MCP_RXB0CTRL, 0x60);   /* accept all, rollover */
    s_listen[s] = 0;
    if (click_kv_get(kv, "mode", v, sizeof v) && strcmp(v, "listen") == 0)
        s_listen[s] = 1;
    mcp_set_mode(s, s_listen[s] ? MODE_LISTEN : MODE_NORMAL);
    return 0;
}

static int can_selftest(uint8_t s) {
    /* register R/W round-trip on a scratch config register */
    reg_write(s, MCP_CNF3, 0x05);
    if (reg_read(s, MCP_CNF3) != 0x05) { proto_reply("no SPI response from MCP2515"); return -1; }
    proto_reply("MCP2515 SPI ok, mode=%s", s_listen[s] ? "listen" : "normal");
    return 0;
}

static int can_sniff_start(uint8_t s, int count) { (void)count; s_sniffing[s] = 1; return 0; }
static void can_sniff_stop(uint8_t s) { s_sniffing[s] = 0; }

static void can_sniff_poll(uint8_t s) {
    if (!s_sniffing[s]) return;
    if (!(reg_read(s, MCP_CANINTF) & 0x01)) return;      /* RX0IF */
    uint8_t sidh = reg_read(s, MCP_RXB0SIDH);
    uint8_t sidl = reg_read(s, MCP_RXB0SIDH + 1);
    uint16_t id  = ((uint16_t)sidh << 3) | (sidl >> 5);
    uint8_t dlc  = reg_read(s, MCP_RXB0SIDH + 4) & 0x0F;
    uint8_t data[8];
    for (int i = 0; i < dlc && i < 8; ++i) data[i] = reg_read(s, MCP_RXB0SIDH + 5 + i);
    char hx[3 + 1 + 16 + 1];
    int o = 0; static const char D[] = "0123456789abcdef";
    hx[o++] = D[(id >> 8) & 0xF]; hx[o++] = D[(id >> 4) & 0xF]; hx[o++] = D[id & 0xF];
    hx[o++] = '#';
    hex_encode(data, dlc, hx + o, (int)sizeof(hx) - o);
    proto_emit_rx(s + 1, board_micros(), hx);
    reg_write(s, MCP_CANINTF, 0x00);                     /* clear flags */
    proto_sniff_count_inc(s);
}

static int can_tx(uint8_t s, const char *frame) {
    if (s_listen[s]) { proto_reply("cannot TX in listen mode"); return -1; }
    const char *hash = strchr(frame, '#');
    if (!hash) return -1;
    uint16_t id = (uint16_t)strtol(frame, NULL, 16);
    uint8_t data[8];
    int dlc = hex_decode(hash + 1, data, sizeof data);
    if (dlc < 0) return -1;
    reg_write(s, MCP_TXB0SIDH, (uint8_t)(id >> 3));
    reg_write(s, MCP_TXB0SIDH + 1, (uint8_t)(id << 5));
    reg_write(s, MCP_TXB0SIDH + 4, (uint8_t)dlc);
    for (int i = 0; i < dlc; ++i) reg_write(s, MCP_TXB0SIDH + 5 + i, data[i]);
    uint8_t rts = MCP_RTS_TXB0, rx;
    mb_cs_low(s); mb_spi_txrx(s, &rts, &rx, 1); mb_cs_high(s);
    return 0;
}

static int can_flood(uint8_t s, const char *frame, uint32_t count, uint32_t gap_ms) {
    for (uint32_t i = 0; i < count; ++i) {
        if (can_tx(s, frame) != 0) return -1;
        if (gap_ms) board_delay_ms(gap_ms);
    }
    return 0;
}

const click_driver_t can_spi_driver = {
    .id = "can_spi", .chip = "MCP2515", .bus = "SPI",
    .probe = can_probe, .configure = can_configure, .selftest = can_selftest,
    .sniff_start = can_sniff_start, .sniff_poll = can_sniff_poll, .sniff_stop = can_sniff_stop,
    .tx = can_tx, .flood = can_flood, .special = 0,
};
