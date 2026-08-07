/*
 * board.h — Quiver Click firmware board configuration (Nucleo-F429ZI).
 *
 * The ST-Link on the Nucleo bridges the STM32 USART3 (PD8 TX / PD9 RX) to the
 * host Virtual COM Port. That link carries the Quiver Click command protocol.
 * Default host<->MCU baud is 115200; keep it in sync with the Quiver host tool
 * (Configure Shield -> "VCP link baud").
 */
#ifndef BOARD_H
#define BOARD_H

#include "stm32f4xx_hal.h"

#define QCLICK_FW_VERSION   "QCLICK-FW 0.1.0"

/* Host command/console link (ST-Link VCP <-> USART3) */
#define HOST_UART           USART3
#define HOST_UART_BAUD      115200
#define HOST_UART_TX_PORT   GPIOD
#define HOST_UART_TX_PIN    GPIO_PIN_8
#define HOST_UART_RX_PORT   GPIOD
#define HOST_UART_RX_PIN    GPIO_PIN_9

/* Line buffer sizes */
#define PROTO_LINE_MAX      256
#define FRAME_HEX_MAX       520     /* max ASCII-hex payload per frame */

void board_init(void);              /* clocks, systick, GPIO clocks */
uint32_t board_micros(void);        /* free-running microsecond counter */
void board_delay_ms(uint32_t ms);

/* Host UART raw I/O (implemented in main.c) */
void     host_uart_init(void);
void     host_write(const uint8_t *buf, uint16_t len);
int      host_read_byte(void);      /* returns byte 0-255, or -1 if none */

#endif /* BOARD_H */
