# Quiver Click Firmware (STM32F429ZI)

Companion firmware for the Quiver **Nucleo-F429ZI → Click Shield (mikroBUS)**
pentest subsystem. It drives the Click boards in mikroBUS sockets 1–4 and bridges
them to the Quiver host tool over the ST-Link Virtual COM Port (USART3), speaking
the line protocol below.

> **Scaffold status:** the command protocol, dispatch, mikroBUS abstraction, and
> per-Click drivers are implemented. Two areas are deliberately marked `TODO` and
> **must be finalised against hardware before field use**: (1) the exact mikroBUS
> pin/peripheral map in `src/mikrobus.c` (verify against the *Click Shield for
> Nucleo-144* schematic v102 + the STM32F429ZI AF table), and (2) `SystemClock_Config`
> in `src/main.c` (drop in the CubeMX-generated 180 MHz tree). Deep protocol stacks
> (DW3000 ranging, PN7150 NCI, full XBee API) are stubbed with `TODO`s.

## Build

```bash
sudo apt install gcc-arm-none-eabi        # ARM toolchain
./build.sh                                # clones STM32CubeF4, builds build/quiver_click.hex
# or manually:
make CUBEF4=/path/to/STM32CubeF4
```

Flash from Quiver (**Nucleo-F429ZI → Click Shield → Flash Click Firmware**), or:

```bash
export QUIVER_CLICK_FW=$PWD/build/quiver_click.hex
make flash            # st-flash
make flash-pyocd      # pyocd
```

## Layout

```
src/
  board.h        host UART / version / buffer sizes
  main.c         boot, USART3<->VCP bridge, main loop        (TODO: SystemClock_Config)
  mikrobus.h/.c  socket abstraction + SPI/I2C/UART wrappers  (TODO: verify pin map)
  protocol.h/.c  line parser + command dispatch + sniff bookkeeping
  click_driver.h the driver interface every Click implements
  registry.c     driver table + click_kv_get param parser
  hex.h/.c       ascii-hex <-> bytes
  clicks/
    can_spi.c        CAN SPI (MCP2515)     sniff/inject/flood/replay
    serial_click.c   RS232 4 + RS485 8     sniff/inject/(flood 485)/replay
    xbee.c           XBee 2 (802.15.4)     sniff/inject/flood
    uwb_dw3000.c     UWB 3 (DW3000)        probe/selftest + range/relay stubs
    nfc_pn7150.c     NFC 2 (PN7150)        probe/selftest + read/emulate/relay stubs
    nbiot.c          5G NB IoT             AT enumeration only (no RF DoS)
```

## Host ↔ MCU protocol

One ASCII command per line (`\n`-terminated); replies are `OK`/`ERR`/`PONG`/`SOCK`/`RX`.
Socket numbers are 1-based on the wire (`sock 1` → `mikrobus[0]`).

| Command | Meaning |
|---|---|
| `PING` | → `PONG QCLICK-FW <ver>` |
| `SCAN` | probe each socket → `SOCK <n> <chip\|none> <bus>` |
| `STATUS` | per-socket bound driver |
| `CFG <s> <click> [k=v…]` | bind a click to a socket + params |
| `SELFTEST <s>` | bus health (`OK`/`ERR`) |
| `SNIFF <s> [count]` | stream `RX <s> <us> <hex>` frames |
| `STOP <s>` | stop sniff/flood |
| `TX <s> <hex>` | inject one frame (`<id>#<data>` for CAN) |
| `FLOOD <s> <hex> <count> [gap_ms]` | repeated TX (flood / DoS) |
| `AT <s> <command>` | modem AT pass-through (NB-IoT) |
| `NFC <s> READ\|EMULATE\|RELAY` | NFC 2 actions |
| `UWB <s> RANGE\|RELAY` | UWB 3 actions |

Adding a new Click = one file in `src/clicks/` implementing `click_driver_t`, plus
one line in `registry.c`. The host side already understands the protocol.

## Authorised use only

Active operations (inject / flood / replay / emulate / relay) transmit onto the
target bus/RF and are gated behind an authorisation prompt on the host. Use only
against assets in scope for the engagement. Cellular RF jamming/DoS is intentionally
**not** implemented (illegal); the NB-IoT Click is limited to AT enumeration.
