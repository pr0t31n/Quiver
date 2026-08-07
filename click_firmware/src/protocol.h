/*
 * protocol.h — host <-> MCU line protocol (see nucleo_f429zi.py in Quiver).
 *
 * Commands (host -> MCU, one line, '\n'-terminated):
 *   PING | SCAN | STATUS | CFG <s> <click> [k=v..] | SELFTEST <s> |
 *   SNIFF <s> [count] | STOP <s> | TX <s> <hex> | FLOOD <s> <hex> <n> [gap] |
 *   AT <s> <cmd> | NFC <s> <verb> | UWB <s> <verb>
 * Replies (MCU -> host):
 *   PONG QCLICK-FW <ver> | OK .. | ERR .. | SOCK <n> <chip|none> <bus> |
 *   RX <s> <us> <hex>
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

void proto_init(void);
void proto_task(void);              /* poll host UART, parse + dispatch a line */
void proto_sniff_task(void);        /* service any active sniff on each socket */

/* Reply helpers used by core + drivers. */
void proto_reply(const char *fmt, ...);            /* prints "<line>\n" to host */
void proto_ok(const char *fmt, ...);               /* prints "OK <line>\n"     */
void proto_err(const char *fmt, ...);              /* prints "ERR <line>\n"    */
void proto_emit_rx(uint8_t sock, uint32_t us, const char *hex);  /* RX line */

/* Sniff bookkeeping (per socket, owned by core; drivers query these). */
int  proto_sniff_active(uint8_t sock);
void proto_sniff_count_inc(uint8_t sock);          /* auto-stops at the limit */

#endif /* PROTOCOL_H */
