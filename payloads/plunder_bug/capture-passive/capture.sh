#!/usr/bin/env bash
# ================================================================
#  Plunder Bug — capture-passive
#  Description : Silent tap mode. Flushes host IP stack on the
#                Plunder Bug interface so the host transmits NO
#                traffic onto the tapped segment — completely
#                invisible to the target device and switch.
#                Run this BEFORE starting any capture to guarantee
#                host-side passivity.
#  Host OS     : Linux (iptables required)
#  Requires    : sudo, Plunder Bug connected via USB-C
#  Usage       : sudo ./capture.sh [enable|disable] [interface]
#                sudo ./capture.sh enable          # enter passive mode
#                sudo ./capture.sh disable eth2    # restore interface
#                sudo ./capture.sh capture eth2    # passive + capture
# ================================================================

set -euo pipefail

MODE="${1:-enable}"
IFACE="${2:-}"
LOOT_DIR="./loot/$(date +%Y%m%d_%H%M%S)_passive"

detect_iface() {
    for iface in /sys/class/net/*/address; do
        addr=$(cat "$iface" 2>/dev/null || true)
        if [[ "${addr,,}" == 00:13:37* ]]; then
            basename "$(dirname "$iface")"
            return
        fi
    done
}

[ -z "$IFACE" ] && IFACE=$(detect_iface)
[ -z "$IFACE" ] && { echo "[!] Plunder Bug not found."; exit 1; }

passive_enable() {
    echo "[*] Entering passive mode on $IFACE..."
    # Drop all OUTPUT on this interface (host won't transmit)
    sudo iptables  -A OUTPUT -o "$IFACE" -j DROP 2>/dev/null || true
    sudo ip6tables -A OUTPUT -o "$IFACE" -j DROP 2>/dev/null || true
    # Flush any existing IP address (prevents ARP responses)
    sudo ip addr flush dev "$IFACE" 2>/dev/null || true
    # Disable IPv6 autoconfiguration
    echo 1 | sudo tee /proc/sys/net/ipv6/conf/"$IFACE"/disable_ipv6 >/dev/null 2>/dev/null || true
    echo "[+] $IFACE is now in passive mode — host will not transmit on this segment."
}

passive_disable() {
    echo "[*] Restoring $IFACE to active mode..."
    sudo iptables  -D OUTPUT -o "$IFACE" -j DROP 2>/dev/null || true
    sudo ip6tables -D OUTPUT -o "$IFACE" -j DROP 2>/dev/null || true
    echo 0 | sudo tee /proc/sys/net/ipv6/conf/"$IFACE"/disable_ipv6 >/dev/null 2>/dev/null || true
    sudo dhclient "$IFACE" &>/dev/null &
    echo "[+] $IFACE restored. DHCP acquiring in background."
}

case "$MODE" in
    enable)
        passive_enable
        ;;
    disable)
        passive_disable
        ;;
    capture)
        mkdir -p "$LOOT_DIR"
        passive_enable
        echo "[*] Starting passive capture... (Ctrl+C to stop)"
        echo ""
        cleanup() {
            passive_disable
            echo "[+] PCAP: ${LOOT_DIR}/capture.pcap"
        }
        trap cleanup EXIT INT TERM
        sudo tcpdump -i "$IFACE" -w "${LOOT_DIR}/capture.pcap" \
            --buffer-size=4096 2>/dev/null
        ;;
    *)
        echo "Usage: $0 [enable|disable|capture] [interface]"
        exit 1
        ;;
esac
