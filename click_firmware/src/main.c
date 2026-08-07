/*
 * main.c — Quiver Click firmware entry point (Nucleo-F429ZI).
 *
 * Boots the STM32, brings up the host command link on USART3 (bridged to the
 * ST-Link VCP), initialises the mikroBUS sockets, and runs the protocol loop.
 *
 * TODO: SystemClock_Config() here is a placeholder — replace with the CubeMX-
 *       generated clock tree for the F429ZI (typ. 180 MHz via PLL/HSE 8 MHz).
 */
#include "board.h"
#include "mikrobus.h"
#include "protocol.h"

static UART_HandleTypeDef huart_host;

/* ── time base ─────────────────────────────────────────────────────────────── */
void board_delay_ms(uint32_t ms) { HAL_Delay(ms); }

uint32_t board_micros(void) {
    /* DWT cycle counter -> microseconds. Assumes SystemCoreClock is set. */
    return DWT->CYCCNT / (SystemCoreClock / 1000000U);
}

static void dwt_init(void) {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

/* ── clock (placeholder) ───────────────────────────────────────────────────── */
static void SystemClock_Config(void) {
    /* TODO: replace with the CubeMX-generated 180 MHz config for STM32F429ZI.
     * The default HSI path lets the firmware boot for bring-up/testing. */
    RCC_OscInitTypeDef osc = {0};
    RCC_ClkInitTypeDef clk = {0};
    __HAL_RCC_PWR_CLK_ENABLE();
    osc.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    osc.HSIState = RCC_HSI_ON;
    osc.PLL.PLLState = RCC_PLL_NONE;
    HAL_RCC_OscConfig(&osc);
    clk.ClockType = RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                    RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    clk.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
    clk.AHBCLKDivider = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = RCC_HCLK_DIV1;
    clk.APB2CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_0);
}

void board_init(void) {
    HAL_Init();
    SystemClock_Config();
    dwt_init();
}

/* ── host UART (USART3 <-> ST-Link VCP) ────────────────────────────────────── */
void host_uart_init(void) {
    GPIO_InitTypeDef g = {0};
    __HAL_RCC_GPIOD_CLK_ENABLE();
    __HAL_RCC_USART3_CLK_ENABLE();
    /* PD8 = USART3_TX, PD9 = USART3_RX (AF7) */
    g.Pin = HOST_UART_TX_PIN | HOST_UART_RX_PIN;
    g.Mode = GPIO_MODE_AF_PP;
    g.Pull = GPIO_PULLUP;
    g.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    g.Alternate = GPIO_AF7_USART3;
    HAL_GPIO_Init(GPIOD, &g);

    huart_host.Instance = HOST_UART;
    huart_host.Init.BaudRate = HOST_UART_BAUD;
    huart_host.Init.WordLength = UART_WORDLENGTH_8B;
    huart_host.Init.StopBits = UART_STOPBITS_1;
    huart_host.Init.Parity = UART_PARITY_NONE;
    huart_host.Init.Mode = UART_MODE_TX_RX;
    huart_host.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart_host.Init.OverSampling = UART_OVERSAMPLING_16;
    HAL_UART_Init(&huart_host);
}

void host_write(const uint8_t *buf, uint16_t len) {
    HAL_UART_Transmit(&huart_host, (uint8_t *)buf, len, 500);
}

int host_read_byte(void) {
    if (huart_host.Instance->SR & USART_SR_RXNE)
        return (int)(huart_host.Instance->DR & 0xFF);
    return -1;
}

/* ── main loop ─────────────────────────────────────────────────────────────── */
int main(void) {
    board_init();
    host_uart_init();
    mikrobus_init();
    proto_init();

    for (;;) {
        proto_task();          /* parse + dispatch host commands */
        proto_sniff_task();    /* service any active per-socket sniffers */
    }
}

/* HAL tick */
void SysTick_Handler(void) { HAL_IncTick(); }
