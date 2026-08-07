/*
 * mikrobus.c — mikroBUS bus abstraction for the MIKROE Click Shield for
 * Nucleo-144, driven from a Nucleo-F429ZI.
 *
 * CONFIRMED (Nucleo-144 F429ZI Arduino/Zio header defaults, per ST UM1974 +
 * Zephyr board def):
 *   SPI1  : SCK=PA5  MISO=PA6  MOSI=PA7   (AF5),  CS(D10)=PD14
 *   I2C1  : SCL=PB8  SDA=PB9              (AF4, open-drain)
 *   USART6: TX=PG14  RX=PG9               (AF8)  -> socket 1 UART (Arduino D1/D0)
 *   USART3: host VCP (PD8/PD9) — see main.c
 * SPI and I2C are SHARED across sockets (per-socket CS / 7-bit addr disambiguate).
 *
 * NEEDS VERIFICATION against the "Click Shield for Nucleo-144" schematic (v102):
 *   - socket 1 control lines (AN/RST/PWM/INT) use the STANDARD Arduino mikroBUS
 *     positions below (high confidence);
 *   - sockets 2-4 control lines + their UART routing are the product's own Zio
 *     assignment and are marked (VERIFY). The shield exposes 3 sockets (one a
 *     Shuttle) per the datasheet; MIKROBUS_COUNT is kept at 4 to match the host
 *     tool — an unpopulated 4th socket simply never detects anything. Adjust
 *     MIKROBUS_COUNT + the host CLICK_SOCKETS if your board differs.
 */
#include "mikrobus.h"
#include "board.h"

/* Shared bus handles */
static SPI_HandleTypeDef  hspi1_shared;
static I2C_HandleTypeDef  hi2c1_shared;

/* Per-socket UART handles + routing table. Socket 1 = USART6 (confirmed). */
static UART_HandleTypeDef huart_sock[MIKROBUS_COUNT];
static int  s_half_duplex[MIKROBUS_COUNT];

typedef struct {
    USART_TypeDef *inst;
    GPIO_TypeDef  *port; uint16_t tx_pin, rx_pin; uint8_t af;
} uart_route_t;

/* socket 1: USART6 PG14/PG9 (AF8) — confirmed. 2-4: (VERIFY) plausible Zio USARTs. */
static const uart_route_t UART_ROUTE[MIKROBUS_COUNT] = {
    { USART6, GPIOG, GPIO_PIN_14, GPIO_PIN_9,  GPIO_AF8_USART6 },   /* socket 1 */
    { USART2, GPIOD, GPIO_PIN_5,  GPIO_PIN_6,  GPIO_AF7_USART2 },   /* socket 2 (VERIFY) */
    { USART1, GPIOB, GPIO_PIN_6,  GPIO_PIN_7,  GPIO_AF7_USART1 },   /* socket 3 (VERIFY) */
    { UART4,  GPIOA, GPIO_PIN_0,  GPIO_PIN_1,  GPIO_AF8_UART4  },   /* socket 4 (VERIFY) */
};

/*
 * Control-line pin map. Socket 1 == standard Arduino mikroBUS positions:
 *   AN=A0(PA3) RST=A3(PF3) CS=D10(PD14) PWM=D3(PE13) INT=D2(PF15).
 * Sockets 2-4 (VERIFY vs schematic v102) use distinct free Zio GPIO.
 */
mikrobus_socket_t mikrobus[MIKROBUS_COUNT] = {
    /* socket 1 (confirmed positions) */
    { &hspi1_shared, &hi2c1_shared, &huart_sock[0],
      GPIOD, GPIO_PIN_14,  GPIOF, GPIO_PIN_3,  GPIOF, GPIO_PIN_15,
      GPIOA, GPIO_PIN_3,   GPIOE, GPIO_PIN_13 },
    /* socket 2 (VERIFY) */
    { &hspi1_shared, &hi2c1_shared, &huart_sock[1],
      GPIOD, GPIO_PIN_15,  GPIOE, GPIO_PIN_9,  GPIOF, GPIO_PIN_14,
      GPIOC, GPIO_PIN_0,   GPIOE, GPIO_PIN_11 },
    /* socket 3 (VERIFY) */
    { &hspi1_shared, &hi2c1_shared, &huart_sock[2],
      GPIOF, GPIO_PIN_12,  GPIOF, GPIO_PIN_13, GPIOE, GPIO_PIN_0,
      GPIOC, GPIO_PIN_3,   GPIOD, GPIO_PIN_12 },
    /* socket 4 (VERIFY — likely the Shuttle) */
    { &hspi1_shared, &hi2c1_shared, &huart_sock[3],
      GPIOE, GPIO_PIN_1,   GPIOG, GPIO_PIN_0,  GPIOG, GPIO_PIN_1,
      GPIOF, GPIO_PIN_10,  GPIOE, GPIO_PIN_14 },
};

/* ── GPIO clock helper ─────────────────────────────────────────────────────── */
static void gpio_clk_enable(GPIO_TypeDef *p) {
    if (p == GPIOA) __HAL_RCC_GPIOA_CLK_ENABLE();
    else if (p == GPIOB) __HAL_RCC_GPIOB_CLK_ENABLE();
    else if (p == GPIOC) __HAL_RCC_GPIOC_CLK_ENABLE();
    else if (p == GPIOD) __HAL_RCC_GPIOD_CLK_ENABLE();
    else if (p == GPIOE) __HAL_RCC_GPIOE_CLK_ENABLE();
    else if (p == GPIOF) __HAL_RCC_GPIOF_CLK_ENABLE();
    else if (p == GPIOG) __HAL_RCC_GPIOG_CLK_ENABLE();
}
static void gpio_out(GPIO_TypeDef *port, uint16_t pin) {
    gpio_clk_enable(port);
    GPIO_InitTypeDef g = {0};
    g.Pin = pin; g.Mode = GPIO_MODE_OUTPUT_PP; g.Pull = GPIO_NOPULL; g.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(port, &g);
}
static void gpio_in(GPIO_TypeDef *port, uint16_t pin) {
    gpio_clk_enable(port);
    GPIO_InitTypeDef g = {0};
    g.Pin = pin; g.Mode = GPIO_MODE_INPUT; g.Pull = GPIO_PULLUP;
    HAL_GPIO_Init(port, &g);
}
static void gpio_af(GPIO_TypeDef *port, uint16_t pin, uint8_t af, uint32_t otype) {
    gpio_clk_enable(port);
    GPIO_InitTypeDef g = {0};
    g.Pin = pin; g.Mode = otype; g.Pull = GPIO_PULLUP;
    g.Speed = GPIO_SPEED_FREQ_VERY_HIGH; g.Alternate = af;
    HAL_GPIO_Init(port, &g);
}

void mikrobus_init(void) {
    for (int s = 0; s < MIKROBUS_COUNT; ++s) {
        gpio_out(mikrobus[s].cs_port,  mikrobus[s].cs_pin);
        gpio_out(mikrobus[s].rst_port, mikrobus[s].rst_pin);
        gpio_in (mikrobus[s].int_port, mikrobus[s].int_pin);
        mb_cs_high(s);
        HAL_GPIO_WritePin(mikrobus[s].rst_port, mikrobus[s].rst_pin, GPIO_PIN_SET);
        s_half_duplex[s] = 0;
    }

    /* Shared SPI1 — PA5/PA6/PA7 (AF5), mode 0, 8-bit, ~5.6 MHz @ 90 MHz APB2/16 */
    __HAL_RCC_SPI1_CLK_ENABLE();
    gpio_af(GPIOA, GPIO_PIN_5, GPIO_AF5_SPI1, GPIO_MODE_AF_PP);
    gpio_af(GPIOA, GPIO_PIN_6, GPIO_AF5_SPI1, GPIO_MODE_AF_PP);
    gpio_af(GPIOA, GPIO_PIN_7, GPIO_AF5_SPI1, GPIO_MODE_AF_PP);
    hspi1_shared.Instance = SPI1;
    hspi1_shared.Init.Mode = SPI_MODE_MASTER;
    hspi1_shared.Init.Direction = SPI_DIRECTION_2LINES;
    hspi1_shared.Init.DataSize = SPI_DATASIZE_8BIT;
    hspi1_shared.Init.CLKPolarity = SPI_POLARITY_LOW;
    hspi1_shared.Init.CLKPhase = SPI_PHASE_1EDGE;
    hspi1_shared.Init.NSS = SPI_NSS_SOFT;
    hspi1_shared.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16;
    hspi1_shared.Init.FirstBit = SPI_FIRSTBIT_MSB;
    hspi1_shared.Init.TIMode = SPI_TIMODE_DISABLE;
    hspi1_shared.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
    HAL_SPI_Init(&hspi1_shared);

    /* Shared I2C1 — PB8(SCL)/PB9(SDA) (AF4, open-drain), 100 kHz */
    __HAL_RCC_I2C1_CLK_ENABLE();
    gpio_af(GPIOB, GPIO_PIN_8, GPIO_AF4_I2C1, GPIO_MODE_AF_OD);
    gpio_af(GPIOB, GPIO_PIN_9, GPIO_AF4_I2C1, GPIO_MODE_AF_OD);
    hi2c1_shared.Instance = I2C1;
    hi2c1_shared.Init.ClockSpeed = 100000;
    hi2c1_shared.Init.DutyCycle = I2C_DUTYCYCLE_2;
    hi2c1_shared.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    hi2c1_shared.Init.OwnAddress1 = 0;
    hi2c1_shared.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c1_shared.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
    HAL_I2C_Init(&hi2c1_shared);

    /* Per-socket USARTs are brought up lazily by mb_uart_config(). */
}

void mb_cs_low(uint8_t s)  { HAL_GPIO_WritePin(mikrobus[s].cs_port, mikrobus[s].cs_pin, GPIO_PIN_RESET); }
void mb_cs_high(uint8_t s) { HAL_GPIO_WritePin(mikrobus[s].cs_port, mikrobus[s].cs_pin, GPIO_PIN_SET); }

void mb_rst_pulse(uint8_t s, uint32_t ms) {
    HAL_GPIO_WritePin(mikrobus[s].rst_port, mikrobus[s].rst_pin, GPIO_PIN_RESET);
    board_delay_ms(ms ? ms : 1);
    HAL_GPIO_WritePin(mikrobus[s].rst_port, mikrobus[s].rst_pin, GPIO_PIN_SET);
    board_delay_ms(ms ? ms : 1);
}

int mb_int_read(uint8_t s) {
    return HAL_GPIO_ReadPin(mikrobus[s].int_port, mikrobus[s].int_pin) == GPIO_PIN_SET ? 1 : 0;
}

int mb_spi_txrx(uint8_t s, const uint8_t *tx, uint8_t *rx, uint16_t n) {
    return HAL_SPI_TransmitReceive(mikrobus[s].spi, (uint8_t *)tx, rx, n, 100) == HAL_OK ? 0 : -1;
}

int mb_i2c_read(uint8_t s, uint8_t addr7, uint8_t reg, uint8_t *buf, uint16_t n) {
    return HAL_I2C_Mem_Read(mikrobus[s].i2c, (uint16_t)(addr7 << 1), reg,
                            I2C_MEMADD_SIZE_8BIT, buf, n, 100) == HAL_OK ? 0 : -1;
}
int mb_i2c_write(uint8_t s, uint8_t addr7, const uint8_t *buf, uint16_t n) {
    return HAL_I2C_Master_Transmit(mikrobus[s].i2c, (uint16_t)(addr7 << 1),
                                   (uint8_t *)buf, n, 100) == HAL_OK ? 0 : -1;
}
int mb_i2c_ping(uint8_t s, uint8_t addr7) {
    return HAL_I2C_IsDeviceReady(mikrobus[s].i2c, (uint16_t)(addr7 << 1), 2, 50) == HAL_OK ? 0 : -1;
}

static void usart_clk_enable(USART_TypeDef *u) {
    if (u == USART1) __HAL_RCC_USART1_CLK_ENABLE();
    else if (u == USART2) __HAL_RCC_USART2_CLK_ENABLE();
    else if (u == USART6) __HAL_RCC_USART6_CLK_ENABLE();
    else if (u == UART4)  __HAL_RCC_UART4_CLK_ENABLE();
}

int mb_uart_config(uint8_t s, uint32_t baud, int half_duplex) {
    const uart_route_t *r = &UART_ROUTE[s];
    s_half_duplex[s] = half_duplex;
    usart_clk_enable(r->inst);
    gpio_af(r->port, r->tx_pin, r->af, GPIO_MODE_AF_PP);
    gpio_af(r->port, r->rx_pin, r->af, GPIO_MODE_AF_PP);

    UART_HandleTypeDef *h = &huart_sock[s];
    h->Instance = r->inst;
    h->Init.BaudRate = baud;
    h->Init.WordLength = UART_WORDLENGTH_8B;
    h->Init.StopBits = UART_STOPBITS_1;
    h->Init.Parity = UART_PARITY_NONE;
    h->Init.Mode = UART_MODE_TX_RX;
    h->Init.HwFlowCtl = UART_HWCONTROL_NONE;
    h->Init.OverSampling = UART_OVERSAMPLING_16;
    /* RS485 half-duplex: the CS/mikroBUS-GPIO line is used as the DE (driver
     * enable) control, toggled around TX in mb_uart_tx(). (VERIFY which pin the
     * RS485 8 Click uses for DE on this shield.) */
    return HAL_UART_Init(h) == HAL_OK ? 0 : -1;
}

int mb_uart_tx(uint8_t s, const uint8_t *buf, uint16_t n) {
    int rc;
    if (s_half_duplex[s]) mb_cs_high(s);           /* DE high -> drive the bus */
    rc = HAL_UART_Transmit(&huart_sock[s], (uint8_t *)buf, n, 200) == HAL_OK ? 0 : -1;
    if (s_half_duplex[s]) {
        while (__HAL_UART_GET_FLAG(&huart_sock[s], UART_FLAG_TC) == RESET) { }
        mb_cs_low(s);                              /* DE low -> release / listen */
    }
    return rc;
}

int mb_uart_rx_byte(uint8_t s) {
    USART_TypeDef *u = huart_sock[s].Instance;
    if (!u) return -1;
    if (u->SR & USART_SR_RXNE)                      /* STM32F4: SR/DR register model */
        return (int)(u->DR & 0xFF);
    return -1;
}
