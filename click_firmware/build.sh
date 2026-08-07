#!/usr/bin/env bash
# build.sh — fetch STM32CubeF4 (if needed), build the Quiver Click firmware,
# and report the resulting hex for Quiver's "Flash Click Firmware" action.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# Prefer the copy fetched into Quiver's firmware tree at deploy time
# (firmware/nucleo_f429zi/STM32CubeF4); fall back to a local checkout.
_QUIVER_CUBEF4="$HERE/../firmware/nucleo_f429zi/STM32CubeF4"
if [ -z "${CUBEF4:-}" ] && [ -d "$_QUIVER_CUBEF4/Drivers/STM32F4xx_HAL_Driver" ]; then
    CUBEF4="$_QUIVER_CUBEF4"
fi
CUBEF4="${CUBEF4:-$HERE/STM32CubeF4}"

# 1. Toolchain check
if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    echo "[!] arm-none-eabi-gcc not found."
    echo "    Kali/Debian: sudo apt install gcc-arm-none-eabi"
    exit 1
fi

# 2. STM32CubeF4 (HAL + CMSIS + startup)
if [ ! -d "$CUBEF4/Drivers/STM32F4xx_HAL_Driver" ]; then
    echo "[+] STM32CubeF4 not found at $CUBEF4 — cloning (shallow)…"
    git clone --depth 1 https://github.com/STMicroelectronics/STM32CubeF4 "$CUBEF4"
fi

# 3. Linker script (grab a Nucleo-F429ZI example script if none present)
if [ ! -f "$HERE/STM32F429ZITx_FLASH.ld" ]; then
    CAND="$(find "$CUBEF4" -name 'STM32F429ZITx_FLASH.ld' 2>/dev/null | head -1 || true)"
    if [ -n "$CAND" ]; then
        echo "[+] Using linker script: $CAND"
        cp "$CAND" "$HERE/STM32F429ZITx_FLASH.ld"
    else
        echo "[!] STM32F429ZITx_FLASH.ld not found — generate one with STM32CubeMX"
        echo "    or copy from a Cube Nucleo-F429ZI example project."
        exit 1
    fi
fi

# 4. Build
echo "[+] Building…"
make CUBEF4="$CUBEF4" -j"$(nproc 2>/dev/null || echo 2)"

HEX="$HERE/build/quiver_click.hex"
echo
echo "[+] Firmware built: $HEX"
echo "    Flash it from Quiver:  Nucleo-F429ZI -> Click Shield -> Flash Click Firmware"
echo "    or set: export QUIVER_CLICK_FW=$HEX"
