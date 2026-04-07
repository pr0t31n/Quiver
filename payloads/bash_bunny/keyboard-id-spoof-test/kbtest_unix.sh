#!/bin/bash
# =============================================================================
#  Script    : kbtest_unix.sh
#  Purpose   : Staged macOS / Linux helper for keyboard-id-spoof-test payload.
#              Reads current spoofed identity from BashBunny/current_test.txt,
#              enumerates USB / HID / keyboard devices, and writes the result
#              to BashBunny/results/<VID>_<PID>.txt.
#  Invoked   : By BB payload.txt via HID keystroke injection (Terminal/xterm).
# =============================================================================

# ── Locate BashBunny mount point ──────────────────────────────────────────────
BB=""
for mnt in \
    /Volumes/BashBunny \
    /run/media/*/BashBunny \
    /media/BashBunny \
    /media/*/BashBunny \
    /mnt/BashBunny; do
    # Expand globs
    for expanded in $mnt; do
        if [ -d "$expanded" ]; then
            BB="$expanded"
            break 2
        fi
    done
done

[ -z "$BB" ] && exit 1

# ── Read identity written by BB payload ───────────────────────────────────────
INFO=$(cat "$BB/current_test.txt" 2>/dev/null || echo "UNKNOWN UNKNOWN Unknown Unknown Unknown UNKNOWN")
VID=$(echo "$INFO"  | awk '{print $1}')
PID=$(echo "$INFO"  | awk '{print $2}')
MFR=$(echo "$INFO"  | awk '{print $3}')
PROD=$(echo "$INFO" | awk '{print $4}')
SER=$(echo "$INFO"  | awk '{print $5}')
MODE=$(echo "$INFO" | awk '{print $6}')
[ -z "$MODE" ] && MODE="SPOOFED"

# ── Build result directory ────────────────────────────────────────────────────
mkdir -p "$BB/results"
OUTFILE="$BB/results/${VID}_${PID}.txt"

# ── Collect system USB / HID / keyboard enumeration ───────────────────────────
{
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    OS_NAME=$(uname -s)

    echo "=== Keyboard HID Spoof Validation ($OS_NAME) ==="
    echo "Spoofed VID : $VID"
    echo "Spoofed PID : $PID"
    echo "Manufacturer: $MFR"
    echo "Product     : $PROD"
    echo "Serial      : $SER"
    echo "Mode        : $MODE"
    echo "Hostname    : $(hostname)"
    echo "Username    : $(whoami)"
    echo "Timestamp   : $TS"
    uname -a 2>/dev/null | sed 's/^/OS Details : /' || true
    echo ""

    # ── macOS-specific ────────────────────────────────────────────────────────
    if [ "$OS_NAME" = "Darwin" ]; then
        echo "--- system_profiler SPUSBDataType ---"
        system_profiler SPUSBDataType 2>/dev/null | \
            grep -A 12 -i "keyboard\|${VID}\|${PID}" | head -120 || echo "(no match)"
        echo ""

        echo "--- ioreg IOUSB (VID/PID/Product/Manufacturer) ---"
        ioreg -p IOUSB -l -w 0 2>/dev/null | \
            grep -i "idvendor\|idproduct\|kUSBProductString\|kUSBVendorString\|kUSBSerialNumberString\|Product\|Manufacturer" | \
            head -80 || echo "(ioreg not available)"
        echo ""

        echo "--- ioreg IOHIDFamily (Keyboards) ---"
        ioreg -p IOService -c IOHIDDevice -d 2 2>/dev/null | \
            grep -A 5 -i "keyboard\|transport\|vendorid\|productid" | head -60 || true
        echo ""

    # ── Linux-specific ────────────────────────────────────────────────────────
    else
        echo "--- lsusb (all) ---"
        lsusb 2>/dev/null || echo "(lsusb not available)"
        echo ""

        echo "--- lsusb -v (Keyboard class devices, trunc) ---"
        lsusb -v 2>/dev/null | \
            grep -A 20 -i "bInterfaceClass.*3\|keyboard\|idVendor.*0x${VID}\|idProduct.*0x${PID}" | \
            head -100 || echo "(no verbose match)"
        echo ""

        echo "--- /proc/bus/input/devices (Keyboards) ---"
        grep -A 5 -i "keyboard" /proc/bus/input/devices 2>/dev/null | head -60 || \
            echo "(not available)"
        echo ""

        echo "--- udevadm: keyboard event nodes ---"
        for dev in /dev/input/event*; do
            udevadm info --query=all --name="$dev" 2>/dev/null | \
                grep -i "keyboard\|ID_VENDOR\|ID_MODEL\|ID_SERIAL" && echo "---"
        done | head -80 || true
        echo ""

        echo "--- dmesg (recent USB/HID, last 40 lines) ---"
        dmesg 2>/dev/null | grep -i "usb\|hid\|input" | tail -40 || \
            echo "(dmesg not available or no permission)"
        echo ""
    fi

    echo "=== END ==="

} > "$OUTFILE" 2>/dev/null

exit 0
