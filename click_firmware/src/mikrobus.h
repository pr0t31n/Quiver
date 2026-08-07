/*
 * mikrobus.h — mikroBUS socket abstraction for the MIKROE Click Shield for
 * Nucleo-144, driven from a Nucleo-F429ZI.
 *
 * Sockets are indexed 0..3 in code == "socket 1..4" in the host tool
 * (host socket N -> mikrobus[N-1]).
 *
 * !!! PIN MAP MUST BE VERIFIED against the "Click Shield for Nucleo-144"
 *     schematic (v102) for YOUR board revision before trusting it on hardware.
 *     The assignments in mikrobus.c follow the standard Nucleo-144 Arduino /
 *     ST-morpho routing but ARE the most likely place for a wiring bug.
 */
#ifndef MIKROBUS_H
#define MIKROBUS_H

#include <stdint.h>
#include "stm32f4xx_hal.h"

#define MIKROBUS_COUNT 4

typedef struct {
    /* Shared bus handles (may be shared across sockets; CS/addr disambiguates) */
    SPI_HandleTypeDef  *spi;
    I2C_HandleTypeDef  *i2c;
    UART_HandleTypeDef *uart;
    /* mikroBUS control/GPIO lines */
    GPIO_TypeDef *cs_port;   uint16_t cs_pin;    /* SPI chip-select */
    GPIO_TypeDef *rst_port;  uint16_t rst_pin;   /* RST */
    GPIO_TypeDef *int_port;  uint16_t int_pin;   /* INT */
    GPIO_TypeDef *an_port;   uint16_t an_pin;    /* AN */
    GPIO_TypeDef *pwm_port;  uint16_t pwm_pin;   /* PWM */
} mikrobus_socket_t;

extern mikrobus_socket_t mikrobus[MIKROBUS_COUNT];

void mikrobus_init(void);            /* configure SPI/I2C/UART peripherals + GPIO */

/* Chip-select / reset helpers (socket index 0..3) */
void mb_cs_low(uint8_t s);
void mb_cs_high(uint8_t s);
void mb_rst_pulse(uint8_t s, uint32_t ms);
int  mb_int_read(uint8_t s);

/* Blocking bus transfers. Return 0 on success, <0 on error. */
int  mb_spi_txrx(uint8_t s, const uint8_t *tx, uint8_t *rx, uint16_t n);
int  mb_i2c_read (uint8_t s, uint8_t addr7, uint8_t reg, uint8_t *buf, uint16_t n);
int  mb_i2c_write(uint8_t s, uint8_t addr7, const uint8_t *buf, uint16_t n);
int  mb_i2c_ping (uint8_t s, uint8_t addr7);   /* 0 if device ACKs */

/* Per-socket UART: dynamically retarget a USART to the socket's TX/RX pins. */
int  mb_uart_config(uint8_t s, uint32_t baud, int half_duplex);
int  mb_uart_tx(uint8_t s, const uint8_t *buf, uint16_t n);
int  mb_uart_rx_byte(uint8_t s);               /* -1 if none available */

#endif /* MIKROBUS_H */
