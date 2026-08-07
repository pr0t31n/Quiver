/*
 * nbiot.c — 5G NB IoT Click (cellular NB-IoT modem over UART, AT commands).
 *
 * SAFETY / LEGAL: This driver is CONNECTIVITY / AT-ENUMERATION ONLY.
 * RF jamming / DoS (deliberate transmit-to-deny, flooding the air interface,
 * spectrum saturation) is ILLEGAL and is deliberately NOT implemented here.
 * The sniff_start/sniff_poll/sniff_stop, tx and flood hooks are all NULL (0)
 * on purpose. The only exposed capability is issuing benign AT commands to
 * enumerate the modem/network state (signal quality, registration, etc.).
 *
 * TODO: AT command syntax varies by modem model. This driver targets the
 *       generic 3GPP / u-blox SARA-style AT set as shipped on the MIKROE
 *       "5G NB IoT Click". Verify against YOUR modem's AT manual before
 *       trusting model-specific responses.
 */
#include "click_driver.h"
#include "mikrobus.h"
#include "protocol.h"
#include "board.h"
#include <string.h>
#include <stdlib.h>

#define NBIOT_APN_MAX       48
#define NBIOT_REPLY_MAX     256
#define NBIOT_AT_TIMEOUT_MS 3000

static char s_apn[MIKROBUS_COUNT][NBIOT_APN_MAX];

/*
 * at_cmd — write "<cmd>\r\n" to the modem, then read UART bytes until a line
 * containing "OK" or "ERROR" is seen, or until timeout_ms elapses. The full
 * response text (including intermediate lines) is captured in reply[].
 * Returns 1 if "OK" was seen, 0 otherwise (ERROR / timeout).
 */
static int at_cmd(uint8_t s, const char *cmd, char *reply, int reply_max, uint32_t timeout_ms)
{
    uint8_t crlf[2] = { '\r', '\n' };
    if (cmd && cmd[0])
        mb_uart_tx(s, (const uint8_t *)cmd, (uint16_t)strlen(cmd));
    mb_uart_tx(s, crlf, 2);

    int rlen = 0;
    if (reply && reply_max > 0) reply[0] = '\0';

    uint32_t start = board_micros();
    uint32_t budget_us = timeout_ms * 1000u;
    int saw_ok = 0, saw_err = 0;

    while ((board_micros() - start) < budget_us) {
        int c = mb_uart_rx_byte(s);
        if (c < 0) { board_delay_ms(1); continue; }
        if (reply && rlen < reply_max - 1) {
            reply[rlen++] = (char)c;
            reply[rlen] = '\0';
        }
        /* Cheap terminator scan over accumulated text. The modem terminates a
         * final result code with "OK" or "ERROR" on its own line. */
        if (reply) {
            if (!saw_ok && strstr(reply, "OK")) saw_ok = 1;
            if (!saw_err && strstr(reply, "ERROR")) saw_err = 1;
            if (saw_ok || saw_err) break;
        }
    }
    return saw_ok ? 1 : 0;
}

/* proto_reply the response text one line at a time (splits on CR/LF, skips
 * blank lines) so the host log stays readable. */
static void reply_lines(char *reply)
{
    char *p = reply;
    while (p && *p) {
        char *nl = p;
        while (*nl && *nl != '\r' && *nl != '\n') nl++;
        char save = *nl;
        *nl = '\0';
        if (p[0]) proto_reply("%s", p);
        if (save == '\0') break;
        *nl = save;
        p = nl + 1;
    }
}

static int nbiot_configure(uint8_t s, const char *kv)
{
    char v[NBIOT_APN_MAX];
    uint32_t baud = 115200;
    if (click_kv_get(kv, "baud", v, sizeof v)) {
        long b = strtol(v, NULL, 10);
        if (b > 0) baud = (uint32_t)b;
    }
    s_apn[s][0] = '\0';
    if (click_kv_get(kv, "apn", v, sizeof v)) {
        strncpy(s_apn[s], v, NBIOT_APN_MAX - 1);
        s_apn[s][NBIOT_APN_MAX - 1] = '\0';
    }

    mb_uart_config(s, baud, 0);
    proto_reply("nbiot configured baud=%lu apn=%s",
                (unsigned long)baud, s_apn[s][0] ? s_apn[s] : "(none)");
    return 0;
}

static int nbiot_probe(uint8_t s)
{
    char reply[NBIOT_REPLY_MAX];
    /* A bare "AT" should elicit "OK" from any AT-speaking modem. */
    return at_cmd(s, "AT", reply, sizeof reply, NBIOT_AT_TIMEOUT_MS) ? 1 : 0;
}

static int nbiot_selftest(uint8_t s)
{
    char reply[NBIOT_REPLY_MAX];

    int ok = at_cmd(s, "AT", reply, sizeof reply, NBIOT_AT_TIMEOUT_MS);
    reply_lines(reply);
    if (!ok) { proto_reply("no AT response from modem"); return -1; }

    /* Signal quality (RSSI/BER). TODO: some modems use +CESQ instead. */
    at_cmd(s, "AT+CSQ", reply, sizeof reply, NBIOT_AT_TIMEOUT_MS);
    reply_lines(reply);

    /* EPS network registration state. TODO: +CREG? on non-EPS stacks. */
    at_cmd(s, "AT+CEREG?", reply, sizeof reply, NBIOT_AT_TIMEOUT_MS);
    reply_lines(reply);

    return 0;
}

static int nbiot_special(uint8_t s, int argc, char **argv)
{
    char reply[NBIOT_REPLY_MAX];
    if (argc < 1) { proto_reply("nbiot: no verb"); return 0; }

    if (strcasecmp(argv[0], "AT") == 0) {
        /* Reconstruct the remaining tokens into one AT command string. */
        char cmd[NBIOT_REPLY_MAX];
        int o = 0;
        for (int i = 1; i < argc && o < (int)sizeof(cmd) - 1; ++i) {
            if (i > 1 && o < (int)sizeof(cmd) - 1) cmd[o++] = ' ';
            int n = (int)strlen(argv[i]);
            for (int j = 0; j < n && o < (int)sizeof(cmd) - 1; ++j)
                cmd[o++] = argv[i][j];
        }
        cmd[o] = '\0';
        at_cmd(s, cmd[0] ? cmd : "AT", reply, sizeof reply, NBIOT_AT_TIMEOUT_MS);
        reply_lines(reply);
        return 0;
    }

    if (strcasecmp(argv[0], "CSQ") == 0) {
        at_cmd(s, "AT+CSQ", reply, sizeof reply, NBIOT_AT_TIMEOUT_MS);
        reply_lines(reply);
        return 0;
    }

    if (strcasecmp(argv[0], "CEREG") == 0) {
        at_cmd(s, "AT+CEREG?", reply, sizeof reply, NBIOT_AT_TIMEOUT_MS);
        reply_lines(reply);
        return 0;
    }

    /* Anything else — refuse. No RF DoS / jamming is exposed by this driver. */
    proto_reply("nbiot: only AT enumeration is supported (no RF DoS/jamming)");
    return 0;
}

const click_driver_t nbiot_driver = {
    .id = "5g_nb_iot", .chip = "MODEM", .bus = "UART",
    .probe = nbiot_probe, .configure = nbiot_configure, .selftest = nbiot_selftest,
    /* Connectivity / AT-enumeration only — no capture, no transmit, no flood. */
    .sniff_start = 0, .sniff_poll = 0, .sniff_stop = 0,
    .tx = 0, .flood = 0, .special = nbiot_special,
};
