#!/usr/bin/env bash
# CC2531 Zigbee2MQTT Bridge Setup
# Sets up Zigbee2MQTT with CC2531 Z-Stack coordinator firmware
#
# Requirements: Node.js >= 18, npm, MQTT broker (mosquitto)

set -euo pipefail
echo "=== CC2531 Zigbee2MQTT Setup ==="

OS="linux"
[[ "$(uname)" == "Darwin" ]] && OS="macos"

# --- Check prerequisites ---
if ! command -v node &>/dev/null; then
    echo "Node.js not found."
    if [[ "$OS" == "linux" ]]; then
        echo "Installing Node.js 18 via NodeSource..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        echo "Install: brew install node"
        exit 1
    fi
fi
echo "  [OK] Node.js: $(node --version)"

if ! command -v mosquitto &>/dev/null; then
    echo "Mosquitto MQTT broker not found."
    [[ "$OS" == "linux" ]] && sudo apt-get install -y mosquitto mosquitto-clients \
        || echo "Install: brew install mosquitto"
fi

# --- Find CC2531 port ---
echo ""
echo "Looking for CC2531 serial port..."
CC2531_PORT=""
for p in /dev/ttyACM* /dev/ttyUSB* /dev/cu.usbmodem*; do
    [[ -e "$p" ]] && CC2531_PORT="$p" && break
done
if [[ -z "$CC2531_PORT" ]]; then
    echo "  WARNING: CC2531 not detected. Connect the dongle and rerun, or set port manually."
    CC2531_PORT="/dev/ttyACM0"
fi
echo "  CC2531 port: $CC2531_PORT"

# --- Install Zigbee2MQTT ---
Z2M_DIR="/opt/zigbee2mqtt"
if [[ ! -d "$Z2M_DIR" ]]; then
    echo ""
    echo "Installing Zigbee2MQTT..."
    sudo git clone --depth 1 https://github.com/Koenkk/zigbee2mqtt.git "$Z2M_DIR"
    cd "$Z2M_DIR"
    sudo npm ci
    echo "  [OK] Zigbee2MQTT installed at $Z2M_DIR"
else
    echo "  [OK] Zigbee2MQTT already at $Z2M_DIR"
fi

# --- Write config ---
CONFIG_FILE="$Z2M_DIR/data/configuration.yaml"
sudo mkdir -p "$Z2M_DIR/data"
cat <<EOF | sudo tee "$CONFIG_FILE" > /dev/null
homeassistant: false
permit_join: true
mqtt:
  base_topic: zigbee2mqtt
  server: 'mqtt://localhost'
serial:
  port: $CC2531_PORT
advanced:
  log_level: info
  network_key: GENERATE
EOF
echo "  [OK] Config written to $CONFIG_FILE"

echo ""
echo "=== Next Steps ==="
echo "1. Start Mosquitto: sudo systemctl start mosquitto"
echo "2. Start Zigbee2MQTT: cd $Z2M_DIR && sudo npm start"
echo "3. Monitor MQTT: mosquitto_sub -t 'zigbee2mqtt/#' -v"
echo "4. Web UI: Install zigbee2mqtt-frontend or use Home Assistant integration"
echo "5. After devices join, set permit_join: false in config"
