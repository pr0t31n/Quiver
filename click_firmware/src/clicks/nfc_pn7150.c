/*
 * nfc_pn7150.c — NFC 2 Click (NXP PN7150, 13.56 MHz) driver.
 *
 * The PN7150 is an NFC controller on I2C 7-bit address 0x28. It speaks NCI
 * (NFC Controller Interface, NCI 1.0/1.1): the host writes NCI packets and
 * reads responses/notifications back; the INT line signals that data is
 * available to read. VEN (wired to the mikroBUS RST line here) power-cycles
 * the controller.
 *
 * This driver implements a minimal but real NCI bring-up sequence
 * (CORE_RESET -> CORE_INIT -> RF_DISCOVER_MAP -> RF_DISCOVER) and parses the
 * RF_INTF_ACTIVATED_NTF that the controller raises when a tag enters the field
 * to recover the tag's NFCID1 (UID). Card emulation and relay remain TODO.
 *
 * Reference: NXP UM10936 (PN7150 NCI), NCI 1.0 spec.
 */
#include "click_driver.h"
#include "mikrobus.h"
#include "protocol.h"
#include "hex.h"
#include "board.h"
#include <string.h>

#define PN7150_ADDR   0x28          /* I2C 7-bit address */
#define NCI_HDR       3             /* MT/PBF/GID, OID, PayloadLen */
#define NCI_MAX       260           /* NCI packet: 3-byte header + up to 255 payload */
#define NCI_INT_MS    20            /* how long to wait for INT to assert on a read */

/* NCI command frames (GID/OID + payload). */
/* CORE_RESET_CMD: MT=CMD, GID=CORE(0x0), OID=0x00, len=1, ResetType=1(keep cfg) */
static const uint8_t NCI_CORE_RESET_CMD[] = { 0x20, 0x00, 0x01, 0x01 };
/* CORE_INIT_CMD: GID=CORE, OID=0x01, len=0 -> RSP carries NFCC features/version */
static const uint8_t NCI_CORE_INIT_CMD[]  = { 0x20, 0x01, 0x00 };
/* RF_DISCOVER_MAP_CMD: map 2 protocols to the Frame RF interface (poll mode).
 * len=7: NumEntries=2, {T2T,poll,frame}, {ISO-DEP,poll,frame}. */
static const uint8_t NCI_RF_DISC_MAP_CMD[] = {
    0x21, 0x00, 0x07, 0x02, 0x04, 0x03, 0x02, 0x05, 0x03, 0x03
};
/* RF_DISCOVER_CMD: start discovery, 2 configs: NFC-A poll + NFC-B poll, freq 1. */
static const uint8_t NCI_RF_DISCOVER_CMD[] = {
    0x21, 0x03, 0x05, 0x02, 0x00, 0x01, 0x01, 0x01
};
/* RF_DEACTIVATE_CMD: GID=RF, OID=0x06, len=1, type=0 (idle). */
static const uint8_t NCI_RF_DEACTIVATE_CMD[] = { 0x21, 0x06, 0x01, 0x00 };

static char s_tech[MIKROBUS_COUNT];     /* configured RF technology: 'A'/'B'/'F' */
static int  s_sniffing[MIKROBUS_COUNT];

/* --- NCI transport helpers ------------------------------------------------ */

/* Write one NCI packet. Returns 0 on success, <0 on bus error.
 * PN7150 accepts a raw NCI frame as a single I2C write to its address. */
static int nci_write(uint8_t s, const uint8_t *buf, int n) {
    if (n <= 0 || n > NCI_MAX) return -1;
    return mb_i2c_write(s, PN7150_ADDR, buf, (uint16_t)n);
}

/* Read one NCI packet when the INT line asserts (data available). Reads the
 * 3-byte NCI header first, decodes PayloadLen from byte[2], then reads exactly
 * that many payload bytes. Returns total bytes read (header+payload), 0 if no
 * data arrived within NCI_INT_MS, <0 on bus error.
 *
 * TODO: PN7150 NCI reads are register-LESS I2C reads (a plain
 * HAL_I2C_Master_Receive of N bytes from 0x28, no register byte). mb_i2c_read()
 * here always emits a register address; we pass reg=0x00 as a pragmatic stand-in
 * so the framing/length logic is exercised, but on real hardware this MUST be
 * swapped for a raw receive or the leading register write will desync NCI. */
static int nci_read(uint8_t s, uint8_t *buf, int max) {
    if (max < NCI_HDR) return -1;
    /* Poll INT for a few ms — the controller may take a moment to raise it. */
    int waited = 0;
    while (!mb_int_read(s)) {
        if (waited >= NCI_INT_MS) return 0;         /* nothing waiting */
        board_delay_ms(1);
        waited++;
    }
    if (mb_i2c_read(s, PN7150_ADDR, 0x00, buf, NCI_HDR) < 0) return -1;
    int plen = buf[2];
    if (plen < 0) return -1;
    if (NCI_HDR + plen > max) plen = max - NCI_HDR;  /* clamp to caller buffer */
    if (plen > 0) {
        if (mb_i2c_read(s, PN7150_ADDR, 0x00, buf + NCI_HDR, (uint16_t)plen) < 0)
            return -1;
    }
    return NCI_HDR + plen;
}

/* Write a command, read the reply, and check GID/OID + NCI status byte. Returns
 * 0 when the response opcode matches gid/oid and payload[0]==0x00 (STATUS_OK). */
static int nci_exchange(uint8_t s, const uint8_t *cmd, int n,
                        uint8_t gid, uint8_t oid, uint8_t *rsp, int max) {
    if (nci_write(s, cmd, n) < 0) return -1;
    board_delay_ms(5);
    int r = nci_read(s, rsp, max);
    if (r < NCI_HDR) return -1;
    if (rsp[0] != gid || rsp[1] != oid) return -1;
    /* Response frames carry a status byte as payload[0]; notifications may not. */
    if (r > NCI_HDR && rsp[3] != 0x00) return -1;
    return 0;
}

/* --- NCI bring-up --------------------------------------------------------- */

/* CORE_RESET -> CORE_INIT -> RF_DISCOVER_MAP -> RF_DISCOVER. Returns 0 on
 * success (controller armed for poll-mode discovery), <0 on any step failure. */
static int nfc_init(uint8_t s) {
    uint8_t rsp[NCI_MAX];
    mb_rst_pulse(s, 3);                             /* VEN toggle to reset the controller */
    board_delay_ms(10);
    /* CORE_RESET_RSP = 0x40 0x00 ... */
    if (nci_exchange(s, NCI_CORE_RESET_CMD, (int)sizeof NCI_CORE_RESET_CMD,
                     0x40, 0x00, rsp, (int)sizeof rsp) < 0) return -1;
    /* CORE_INIT_RSP = 0x40 0x01 ... (NFCC features/version in payload) */
    if (nci_exchange(s, NCI_CORE_INIT_CMD, (int)sizeof NCI_CORE_INIT_CMD,
                     0x40, 0x01, rsp, (int)sizeof rsp) < 0) return -1;
    /* RF_DISCOVER_MAP_RSP = 0x41 0x00 <status> */
    if (nci_exchange(s, NCI_RF_DISC_MAP_CMD, (int)sizeof NCI_RF_DISC_MAP_CMD,
                     0x41, 0x00, rsp, (int)sizeof rsp) < 0) return -1;
    /* RF_DISCOVER_RSP = 0x41 0x03 <status> */
    if (nci_exchange(s, NCI_RF_DISCOVER_CMD, (int)sizeof NCI_RF_DISCOVER_CMD,
                     0x41, 0x03, rsp, (int)sizeof rsp) < 0) return -1;
    return 0;
}

/* Parse a NFCID1 (UID) out of an RF_INTF_ACTIVATED_NTF (0x61 0x05) NFC-A frame
 * and hex-encode it into out. Returns UID byte count, or 0 if not parseable.
 *
 * NFC-A activation payload layout (NCI 1.0, RF Technology Specific Params):
 *   [3..] RF Discovery ID, RF Interface, RF Protocol, Activation RF Tech Mode,
 *   Max Data Packet Size, Initial Credits, RF Tech Params Length, then the
 *   NFC-A params: SENS_RES(2) NFCID1 Length(1) NFCID1[len] SEL_RES(1)...
 * We scan for the tech-params length field and read NFCID1 from within it. */
static int parse_uid(const uint8_t *pkt, int n, char *out, int out_max) {
    if (n < NCI_HDR + 8) return 0;
    if (pkt[0] != 0x61 || pkt[1] != 0x05) return 0;
    int tp_len = pkt[NCI_HDR + 6];                  /* RF Tech Params length */
    int base   = NCI_HDR + 7;                       /* first tech-param byte (SENS_RES) */
    if (tp_len < 3 || base + 3 > n) return 0;
    int id_len = pkt[base + 2];                     /* NFCID1 length: 4/7/10 */
    int id_off = base + 3;
    if (id_len < 4 || id_len > 10 || id_off + id_len > n) return 0;
    return hex_encode(pkt + id_off, id_len, out, out_max) > 0 ? id_len : 0;
}

/* --- driver entry points -------------------------------------------------- */

static int nfc_probe(uint8_t s) {
    mb_rst_pulse(s, 3);                             /* VEN toggle to reset/power the controller */
    board_delay_ms(10);
    return (mb_i2c_ping(s, PN7150_ADDR) == 0) ? 1 : 0;
}

static int nfc_configure(uint8_t s, const char *kv) {
    char v[8];
    s_tech[s] = 'A';                                /* default technology A */
    if (click_kv_get(kv, "tech", v, sizeof v) && v[0]) {
        char t = v[0];
        if (t >= 'a' && t <= 'z') t = (char)(t - 'a' + 'A');
        if (t == 'A' || t == 'B' || t == 'F') s_tech[s] = t;
    }
    /* TODO: translate s_tech[s] into a tailored RF_DISCOVER_CMD tech list; the
     * default frame already arms both NFC-A and NFC-B poll. */
    proto_reply("PN7150 configured tech=%c", s_tech[s]);
    return 0;
}

static int nfc_selftest(uint8_t s) {
    uint8_t rsp[NCI_MAX];
    mb_rst_pulse(s, 3);                             /* VEN toggle before reset command */
    board_delay_ms(10);
    if (nci_exchange(s, NCI_CORE_RESET_CMD, (int)sizeof NCI_CORE_RESET_CMD,
                     0x40, 0x00, rsp, (int)sizeof rsp) < 0) {
        proto_reply("PN7150 NCI reset failed");
        return -1;
    }
    if (nci_exchange(s, NCI_CORE_INIT_CMD, (int)sizeof NCI_CORE_INIT_CMD,
                     0x40, 0x01, rsp, (int)sizeof rsp) < 0) {
        proto_reply("PN7150 NCI init failed");
        return -1;
    }
    /* CORE_INIT_RSP payload carries NFCC firmware/version bytes near the tail. */
    char hx[32];
    int m = (rsp[2] >= 4) ? 4 : rsp[2];
    hex_encode(rsp + NCI_HDR, m, hx, (int)sizeof hx);
    proto_reply("PN7150 NCI ok ver=%s", hx);
    return 0;
}

static int nfc_sniff_start(uint8_t s, int count) {
    (void)count;
    if (nfc_init(s) < 0) { s_sniffing[s] = 0; return -1; }
    s_sniffing[s] = 1;
    return 0;
}

static void nfc_sniff_stop(uint8_t s) {
    s_sniffing[s] = 0;
    nci_write(s, NCI_RF_DEACTIVATE_CMD, (int)sizeof NCI_RF_DEACTIVATE_CMD);
}

static void nfc_sniff_poll(uint8_t s) {
    if (!s_sniffing[s]) return;
    if (!mb_int_read(s)) return;                    /* no NCI data waiting */
    uint8_t pkt[NCI_MAX];
    int n = nci_read(s, pkt, (int)sizeof pkt);
    if (n < NCI_HDR) return;
    /* On RF_INTF_ACTIVATED_NTF, recover and emit the tag's NFCID1 (UID). */
    if (pkt[0] == 0x61 && pkt[1] == 0x05) {
        char uid[NCI_MAX * 2 + 1];
        if (parse_uid(pkt, n, uid, (int)sizeof uid) > 0) {
            proto_emit_rx(s + 1, board_micros(), uid);
            proto_sniff_count_inc(s);
        }
    }
}

static int nfc_special(uint8_t s, int argc, char **argv) {
    if (argc < 1 || !argv[0]) { proto_err("NFC: missing verb"); return -1; }
    if (strcmp(argv[0], "READ") == 0) {
        if (nfc_init(s) < 0) { proto_err("PN7150 READ: init failed"); return -1; }
        /* Poll a short while for a single activation notification. */
        uint8_t pkt[NCI_MAX];
        char uid[NCI_MAX * 2 + 1];
        for (int i = 0; i < 50; i++) {              /* ~ up to 50 * NCI_INT_MS */
            int n = nci_read(s, pkt, (int)sizeof pkt);
            if (n >= NCI_HDR && parse_uid(pkt, n, uid, (int)sizeof uid) > 0) {
                proto_reply("PN7150 READ uid=%s", uid);
                return 0;
            }
        }
        proto_reply("PN7150 READ: no tag in field");
        return 0;
    }
    if (strcmp(argv[0], "EMULATE") == 0) {
        proto_reply("PN7150 EMULATE: card-emulation placeholder (TODO: NCI listen mode)");
        /* TODO: configure NFCEE + listen-mode routing to emulate a Type-A tag. */
        return 0;
    }
    if (strcmp(argv[0], "RELAY") == 0) {
        proto_reply("PN7150 RELAY: reader<->card relay placeholder (TODO)");
        /* TODO: bridge one PN7150 in reader mode to another in listen mode. */
        return 0;
    }
    proto_err("NFC: unknown verb %s", argv[0]);
    return -1;
}

const click_driver_t nfc_driver = {
    .id = "nfc_2", .chip = "PN7150", .bus = "I2C",
    .probe = nfc_probe, .configure = nfc_configure, .selftest = nfc_selftest,
    .sniff_start = nfc_sniff_start, .sniff_poll = nfc_sniff_poll, .sniff_stop = nfc_sniff_stop,
    .tx = 0, .flood = 0, .special = nfc_special,
};
