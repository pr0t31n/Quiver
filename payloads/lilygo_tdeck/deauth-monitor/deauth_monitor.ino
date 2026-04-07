// =============================================================================
//  deauth_monitor.ino
//  Description : 802.11 deauthentication and disassociation frame monitor
//                for the LilyGo T-Deck (ESP32-S3). Uses promiscuous mode WiFi
//                to sniff 802.11 management frames and displays per-BSSID
//                counts on the built-in 320x240 LCD (ST7789).
//  Board       : LilyGo T-Deck (ESP32-S3)
//  Display     : ST7789 320x240, driven by TFT_eSPI or LovyanGFX
//  Serial out  : JSON per event {"type":"deauth","bssid":"xx:xx","reason":7,"target":"ff:ff"}
//  Libraries   : TFT_eSPI (or LovyanGFX), Arduino ESP32 core
// =============================================================================

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <TFT_eSPI.h>    // Replace with LovyanGFX if preferred
#include <map>
#include <vector>
#include <algorithm>

// ---------------------------------------------------------------------------
// T-Deck Pin Definitions
// ---------------------------------------------------------------------------
#define TFT_CS    12
#define TFT_DC    11
#define TFT_RST   10
#define TFT_MOSI  41
#define TFT_SCLK  40
#define TFT_BL    42   // Backlight

#define BOARD_POWERON 10  // T-Deck power enable (GPIO10 on some revisions)

// Trackball / keyboard pins (T-Deck specific)
#define TRACKBALL_UP    3
#define TRACKBALL_DOWN  15
#define TRACKBALL_LEFT  1
#define TRACKBALL_RIGHT 2
#define TRACKBALL_CLICK 0

// ---------------------------------------------------------------------------
// 802.11 Frame Definitions
// ---------------------------------------------------------------------------

// Minimal 802.11 MAC header (radiotap header stripped by ESP32 before callback)
typedef struct {
    uint8_t  frame_ctrl[2];
    uint16_t duration;
    uint8_t  addr1[6];   // destination / target
    uint8_t  addr2[6];   // source
    uint8_t  addr3[6];   // BSSID
    uint16_t seq_ctrl;
} wifi_mac_header_t;

#define FRAME_TYPE_MASK    0x0C
#define FRAME_SUBTYPE_MASK 0xF0
#define FRAME_TYPE_MGMT    0x00
#define FRAME_SUBTYPE_DISASSOC  0xA0
#define FRAME_SUBTYPE_DEAUTH    0xC0

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

TFT_eSPI tft = TFT_eSPI();

struct BssidStats {
    uint32_t deauth_count;
    uint32_t disassoc_count;
    uint32_t last_reason;
    unsigned long last_seen_ms;
    char target[18];
};

std::map<String, BssidStats> bssid_stats;
uint32_t total_deauth = 0;
uint32_t total_disassoc = 0;
unsigned long last_display_update = 0;
const unsigned long DISPLAY_UPDATE_INTERVAL_MS = 1000;

// Storm detection
struct StormEntry {
    unsigned long timestamps[20];
    uint8_t count;
    bool alerted;
};
std::map<String, StormEntry> storm_tracker;
const int STORM_THRESHOLD = 10;
const unsigned long STORM_WINDOW_MS = 5000;

// ---------------------------------------------------------------------------
// MAC address helpers
// ---------------------------------------------------------------------------

String macToString(const uint8_t *addr) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return String(buf);
}

// ---------------------------------------------------------------------------
// Storm detection
// ---------------------------------------------------------------------------

bool checkStorm(const String &bssid) {
    unsigned long now = millis();
    StormEntry &entry = storm_tracker[bssid];

    // Shift out old timestamps
    uint8_t valid = 0;
    for (uint8_t i = 0; i < entry.count; i++) {
        if (now - entry.timestamps[i] < STORM_WINDOW_MS) {
            entry.timestamps[valid++] = entry.timestamps[i];
        }
    }
    entry.count = valid;

    if (entry.count < 20) {
        entry.timestamps[entry.count++] = now;
    }

    return entry.count >= STORM_THRESHOLD;
}

// ---------------------------------------------------------------------------
// Serial JSON output
// ---------------------------------------------------------------------------

void emitEvent(const char *type, const String &bssid, uint8_t reason, const String &target) {
    Serial.print("{\"type\":\"");
    Serial.print(type);
    Serial.print("\",\"bssid\":\"");
    Serial.print(bssid);
    Serial.print("\",\"reason\":");
    Serial.print(reason);
    Serial.print(",\"target\":\"");
    Serial.print(target);
    Serial.println("\"}");
}

// ---------------------------------------------------------------------------
// Promiscuous mode callback
// ---------------------------------------------------------------------------

void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_mac_header_t *hdr = (wifi_mac_header_t *)ppkt->payload;

    uint8_t fc0 = hdr->frame_ctrl[0];
    uint8_t frame_type = fc0 & FRAME_TYPE_MASK;
    uint8_t frame_subtype = fc0 & FRAME_SUBTYPE_MASK;

    if (frame_type != FRAME_TYPE_MGMT) return;
    if (frame_subtype != FRAME_SUBTYPE_DEAUTH && frame_subtype != FRAME_SUBTYPE_DISASSOC) return;

    String bssid = macToString(hdr->addr3);
    String target = macToString(hdr->addr1);

    // Reason code is the first 2 bytes after the MAC header
    uint8_t reason = 0;
    if (ppkt->rx_ctrl.sig_len >= (sizeof(wifi_mac_header_t) + 2)) {
        reason = ppkt->payload[sizeof(wifi_mac_header_t)];
    }

    BssidStats &stats = bssid_stats[bssid];
    stats.last_seen_ms = millis();
    strncpy(stats.target, target.c_str(), 17);
    stats.target[17] = '\0';
    stats.last_reason = reason;

    if (frame_subtype == FRAME_SUBTYPE_DEAUTH) {
        stats.deauth_count++;
        total_deauth++;
        emitEvent("deauth", bssid, reason, target);

        if (checkStorm(bssid) && !storm_tracker[bssid].alerted) {
            storm_tracker[bssid].alerted = true;
            Serial.print("{\"type\":\"storm_alert\",\"bssid\":\"");
            Serial.print(bssid);
            Serial.println("\"}");
        }
    } else {
        stats.disassoc_count++;
        total_disassoc++;
        emitEvent("disassoc", bssid, reason, target);
    }
}

// ---------------------------------------------------------------------------
// Display rendering
// ---------------------------------------------------------------------------

void updateDisplay() {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setTextSize(1);

    // Header
    tft.setCursor(2, 2);
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.print("=== Deauth Monitor ===");

    tft.setCursor(2, 14);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    char header[40];
    snprintf(header, sizeof(header), "Deauth:%lu  Disassoc:%lu", total_deauth, total_disassoc);
    tft.print(header);

    // Column headers
    tft.setCursor(2, 28);
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.print("BSSID              D    DA  STORM");

    // Sort BSSIDs by deauth count descending
    std::vector<std::pair<String, BssidStats>> sorted_stats(bssid_stats.begin(), bssid_stats.end());
    std::sort(sorted_stats.begin(), sorted_stats.end(),
              [](const auto &a, const auto &b) {
                  return (a.second.deauth_count + a.second.disassoc_count) >
                         (b.second.deauth_count + b.second.disassoc_count);
              });

    int y = 40;
    int shown = 0;
    for (const auto &kv : sorted_stats) {
        if (shown >= 5) break;
        if (y >= 235) break;

        const String &mac = kv.first;
        const BssidStats &s = kv.second;
        bool storm = (storm_tracker.count(mac) && storm_tracker[mac].alerted);

        tft.setCursor(2, y);
        tft.setTextColor(storm ? TFT_RED : TFT_GREEN, TFT_BLACK);

        char line[40];
        snprintf(line, sizeof(line), "%-17s %4lu %4lu   %s",
                 mac.c_str(),
                 s.deauth_count,
                 s.disassoc_count,
                 storm ? "!!" : "--");
        tft.print(line);
        y += 12;
        shown++;
    }

    if (bssid_stats.empty()) {
        tft.setCursor(2, 55);
        tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
        tft.print("Waiting for frames...");
    }

    // Storm alerts
    if (!storm_tracker.empty()) {
        int alert_y = 220;
        for (const auto &kv : storm_tracker) {
            if (kv.second.alerted) {
                tft.setCursor(2, alert_y);
                tft.setTextColor(TFT_RED, TFT_BLACK);
                char alert[40];
                snprintf(alert, sizeof(alert), "STORM: %s", kv.first.c_str());
                tft.print(alert);
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    delay(500);

    // T-Deck power-on sequence
    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);

    // Display init
    tft.init();
    tft.setRotation(1);   // Landscape
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(1);
    tft.setCursor(10, 10);
    tft.print("Deauth Monitor Starting...");

    Serial.println("{\"type\":\"init\",\"device\":\"T-Deck\",\"fw\":\"deauth_monitor\"}");

    // WiFi promiscuous mode setup
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);

    // Set channel (channel 6 is common default; change as needed)
    esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);

    tft.fillScreen(TFT_BLACK);
    tft.setCursor(2, 2);
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.print("Deauth Monitor Active");
    tft.setCursor(2, 14);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.print("CH6 | Waiting for frames...");

    Serial.println("{\"type\":\"status\",\"state\":\"listening\",\"channel\":6}");
}

// ---------------------------------------------------------------------------
// Loop
// ---------------------------------------------------------------------------

void loop() {
    unsigned long now = millis();

    if (now - last_display_update >= DISPLAY_UPDATE_INTERVAL_MS) {
        last_display_update = now;
        updateDisplay();
    }

    // Channel hopping every 2 seconds (optional — uncomment to enable)
    // static unsigned long last_hop = 0;
    // static uint8_t ch = 1;
    // if (now - last_hop >= 2000) {
    //     last_hop = now;
    //     ch = (ch % 13) + 1;
    //     esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    // }

    delay(10);
}
