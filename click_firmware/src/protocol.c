/* protocol.c — host<->MCU line protocol parser + dispatch. */
#include "protocol.h"
#include "board.h"
#include "mikrobus.h"
#include "click_driver.h"
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

/* ── per-socket state ──────────────────────────────────────────────────────── */
static const click_driver_t *g_bound[MIKROBUS_COUNT];
static int      g_sniff[MIKROBUS_COUNT];
static uint32_t g_sniff_n[MIKROBUS_COUNT];
static uint32_t g_sniff_limit[MIKROBUS_COUNT];   /* 0 = unlimited */

static char  g_line[PROTO_LINE_MAX];
static int   g_len;

/* ── output helpers ────────────────────────────────────────────────────────── */
static void emit_line(const char *s) {
    host_write((const uint8_t *)s, (uint16_t)strlen(s));
    host_write((const uint8_t *)"\n", 1);
}
void proto_reply(const char *fmt, ...) {
    char buf[PROTO_LINE_MAX];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    emit_line(buf);
}
void proto_ok(const char *fmt, ...) {
    char buf[PROTO_LINE_MAX]; int o = 0;
    o += snprintf(buf, sizeof buf, "OK ");
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf + o, sizeof buf - o, fmt, ap);
    va_end(ap);
    emit_line(buf);
}
void proto_err(const char *fmt, ...) {
    char buf[PROTO_LINE_MAX]; int o = 0;
    o += snprintf(buf, sizeof buf, "ERR ");
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf + o, sizeof buf - o, fmt, ap);
    va_end(ap);
    emit_line(buf);
}
void proto_emit_rx(uint8_t sock, uint32_t us, const char *hex) {
    proto_reply("RX %u %lu %s", (unsigned)sock, (unsigned long)us, hex);
}

/* ── sniff bookkeeping (called by drivers) ─────────────────────────────────── */
int proto_sniff_active(uint8_t s) { return (s < MIKROBUS_COUNT) ? g_sniff[s] : 0; }
void proto_sniff_count_inc(uint8_t s) {
    if (s >= MIKROBUS_COUNT) return;
    g_sniff_n[s]++;
    if (g_sniff_limit[s] && g_sniff_n[s] >= g_sniff_limit[s]) {
        g_sniff[s] = 0;
        if (g_bound[s] && g_bound[s]->sniff_stop) g_bound[s]->sniff_stop(s);
        proto_ok("sniff done %lu", (unsigned long)g_sniff_n[s]);
    }
}

/* ── dispatch ──────────────────────────────────────────────────────────────── */
static int parse_sock(const char *tok, uint8_t *out) {
    if (!tok) return -1;
    int n = atoi(tok);                 /* host sends 1-based */
    if (n < 1 || n > MIKROBUS_COUNT) return -1;
    *out = (uint8_t)(n - 1);
    return 0;
}

static void dispatch(int argc, char **argv) {
    if (argc == 0) return;
    const char *cmd = argv[0];
    uint8_t s;

    if (!strcmp(cmd, "PING")) {
        proto_reply("PONG %s", QCLICK_FW_VERSION);

    } else if (!strcmp(cmd, "SCAN")) {
        for (uint8_t sock = 0; sock < MIKROBUS_COUNT; ++sock) {
            const click_driver_t *hit = 0;
            for (int i = 0; i < CLICK_DRIVERS_COUNT; ++i) {
                const click_driver_t *d = CLICK_DRIVERS[i];
                if (d->probe && d->probe(sock)) { hit = d; break; }
            }
            if (hit) proto_reply("SOCK %u %s %s", sock + 1, hit->chip, hit->bus);
            else     proto_reply("SOCK %u none -", sock + 1);
        }
        proto_ok("scan done");

    } else if (!strcmp(cmd, "STATUS")) {
        for (uint8_t sock = 0; sock < MIKROBUS_COUNT; ++sock) {
            if (g_bound[sock]) proto_reply("SOCK %u %s bound", sock + 1, g_bound[sock]->id);
            else               proto_reply("SOCK %u none -", sock + 1);
        }
        proto_ok("status done");

    } else if (!strcmp(cmd, "CFG")) {
        if (argc < 3 || parse_sock(argv[1], &s)) { proto_err("usage CFG <sock> <click> [k=v]"); return; }
        const click_driver_t *d = click_by_id(argv[2]);
        if (!d) { proto_err("unknown click %s", argv[2]); return; }
        char params[PROTO_LINE_MAX]; params[0] = 0;
        for (int i = 3; i < argc; ++i) {
            if (params[0]) strncat(params, " ", sizeof params - strlen(params) - 1);
            strncat(params, argv[i], sizeof params - strlen(params) - 1);
        }
        g_bound[s] = d;
        int rc = d->configure ? d->configure(s, params) : 0;
        if (rc == 0) proto_ok("cfg sock %u %s", s + 1, d->id);
        else         proto_err("configure failed rc=%d", rc);

    } else if (!strcmp(cmd, "SELFTEST")) {
        if (argc < 2 || parse_sock(argv[1], &s)) { proto_err("usage SELFTEST <sock>"); return; }
        if (!g_bound[s]) { proto_err("socket %u not configured", s + 1); return; }
        int rc = g_bound[s]->selftest ? g_bound[s]->selftest(s) : 0;
        if (rc == 0) proto_ok("selftest sock %u pass", s + 1);
        else         proto_err("selftest sock %u fail rc=%d", s + 1, rc);

    } else if (!strcmp(cmd, "SNIFF")) {
        if (argc < 2 || parse_sock(argv[1], &s)) { proto_err("usage SNIFF <sock> [count]"); return; }
        if (!g_bound[s] || !g_bound[s]->sniff_start) { proto_err("socket %u cannot sniff", s + 1); return; }
        g_sniff_n[s] = 0;
        g_sniff_limit[s] = (argc >= 3) ? (uint32_t)strtoul(argv[2], NULL, 10) : 0;
        if (g_bound[s]->sniff_start(s, (int)g_sniff_limit[s]) != 0) { proto_err("sniff start failed"); return; }
        g_sniff[s] = 1;
        proto_ok("sniff started sock %u", s + 1);

    } else if (!strcmp(cmd, "STOP")) {
        if (argc < 2 || parse_sock(argv[1], &s)) { proto_err("usage STOP <sock>"); return; }
        g_sniff[s] = 0;
        if (g_bound[s] && g_bound[s]->sniff_stop) g_bound[s]->sniff_stop(s);
        proto_ok("stopped sock %u", s + 1);

    } else if (!strcmp(cmd, "TX")) {
        if (argc < 3 || parse_sock(argv[1], &s)) { proto_err("usage TX <sock> <hex>"); return; }
        if (!g_bound[s] || !g_bound[s]->tx) { proto_err("socket %u cannot TX", s + 1); return; }
        int rc = g_bound[s]->tx(s, argv[2]);
        if (rc == 0) proto_ok("tx sock %u", s + 1); else proto_err("tx failed rc=%d", rc);

    } else if (!strcmp(cmd, "FLOOD")) {
        if (argc < 4 || parse_sock(argv[1], &s)) { proto_err("usage FLOOD <sock> <hex> <count> [gap_ms]"); return; }
        if (!g_bound[s] || !g_bound[s]->flood) { proto_err("socket %u cannot flood", s + 1); return; }
        uint32_t count = (uint32_t)strtoul(argv[2 + 1], NULL, 10);   /* argv[3] */
        uint32_t gap   = (argc >= 5) ? (uint32_t)strtoul(argv[4], NULL, 10) : 0;
        int rc = g_bound[s]->flood(s, argv[2], count, gap);
        if (rc == 0) proto_ok("flood sock %u count %lu", s + 1, (unsigned long)count);
        else         proto_err("flood failed rc=%d", rc);

    } else if (!strcmp(cmd, "AT")) {
        if (argc < 2 || parse_sock(argv[1], &s)) { proto_err("usage AT <sock> <command>"); return; }
        if (!g_bound[s] || !g_bound[s]->special) { proto_err("socket %u no AT interface", s + 1); return; }
        /* pass ["AT", <command tokens...>] */
        char *sargv[16]; int sargc = 0;
        sargv[sargc++] = (char *)"AT";
        for (int i = 2; i < argc && sargc < 16; ++i) sargv[sargc++] = argv[i];
        g_bound[s]->special(s, sargc, sargv);
        proto_ok("at sock %u", s + 1);

    } else if (!strcmp(cmd, "NFC") || !strcmp(cmd, "UWB")) {
        if (argc < 3 || parse_sock(argv[1], &s)) { proto_err("usage %s <sock> <verb>", cmd); return; }
        if (!g_bound[s] || !g_bound[s]->special) { proto_err("socket %u no special interface", s + 1); return; }
        g_bound[s]->special(s, argc - 2, &argv[2]);   /* argv[0] = verb */
        proto_ok("%s sock %u", cmd, s + 1);

    } else {
        proto_err("unknown command %s", cmd);
    }
}

static void handle_line(char *line) {
    char *argv[16]; int argc = 0;
    char *p = line;
    while (*p && argc < 16) {
        while (*p == ' ') *p++ = 0;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ') p++;
    }
    dispatch(argc, argv);
}

/* ── public API ────────────────────────────────────────────────────────────── */
void proto_init(void) {
    for (int i = 0; i < MIKROBUS_COUNT; ++i) {
        g_bound[i] = 0; g_sniff[i] = 0; g_sniff_n[i] = 0; g_sniff_limit[i] = 0;
    }
    g_len = 0;
    proto_reply("PONG %s", QCLICK_FW_VERSION);   /* boot banner */
}

void proto_task(void) {
    int c;
    while ((c = host_read_byte()) >= 0) {
        if (c == '\r') continue;
        if (c == '\n') {
            g_line[g_len] = 0;
            if (g_len) handle_line(g_line);
            g_len = 0;
        } else if (g_len < PROTO_LINE_MAX - 1) {
            g_line[g_len++] = (char)c;
        } else {
            g_len = 0;   /* overflow — drop the line */
            proto_err("line too long");
        }
    }
}

void proto_sniff_task(void) {
    for (uint8_t s = 0; s < MIKROBUS_COUNT; ++s)
        if (g_sniff[s] && g_bound[s] && g_bound[s]->sniff_poll)
            g_bound[s]->sniff_poll(s);
}
