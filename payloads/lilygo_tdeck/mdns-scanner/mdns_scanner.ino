// =============================================================================
//  mdns_scanner.ino
//  Description : mDNS/Bonjour service discovery scanner for LilyGo T-Deck.
//                Connects to WiFi, queries mDNS services using ESPmDNS,
//                and displays results on the T-Deck 320x240 display with
//                scrolling. Serial outputs JSON per discovered service.
//  Board       : LilyGo T-Deck (ESP32-S3)
//  Libraries   : ESPmDNS (built-in), TFT_eSPI, WiFi (ESP32 core)
//  Serial out  : JSON per service {"name":"...","type":"...","host":"...","ip":"...","port":80}
// =============================================================================

#include <Arduino.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include <TFT_eSPI.h>
#include <vector>

// ---------------------------------------------------------------------------
// WiFi Credentials — edit before flashing or configure via Serial prompt
// ---------------------------------------------------------------------------
// Leave WIFI_SSID empty to prompt via Serial at startup.
#define WIFI_SSID    ""
#define WIFI_PASS    ""
#define WIFI_TIMEOUT 15000   // ms

// ---------------------------------------------------------------------------
// T-Deck Pin Definitions
// ---------------------------------------------------------------------------
#define TFT_CS    12
#define TFT_DC    11
#define TFT_RST   10
#define TFT_MOSI  41
#define TFT_SCLK  40
#define TFT_BL    42

// Trackball pins
#define TRACKBALL_UP    3
#define TRACKBALL_DOWN  15
#define TRACKBALL_LEFT  1
#define TRACKBALL_RIGHT 2
#define TRACKBALL_CLICK 0

// ---------------------------------------------------------------------------
// Service types to query
// ---------------------------------------------------------------------------
const char* SERVICE_TYPES[] = {
    "_http",
    "_https",
    "_ssh",
    "_smb",
    "_ftp",
    "_homekit",
    "_googlecast",
    "_airplay",
    "_raop",
    "_ipp",
    "_printer",
    "_rfb",
    "_mqtt",
    "_workstation",
    nullptr
};

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

TFT_eSPI tft = TFT_eSPI();

struct ServiceEntry {
    String name;
    String service_type;
    String hostname;
    String ip;
    int port;
    String txt;
};

std::vector<ServiceEntry> discovered;
int scroll_offset = 0;
bool scan_complete = false;
String wifi_ssid = "";
String wifi_pass = "";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void drawHeader(const char *msg) {
    tft.fillRect(0, 0, 320, 18, TFT_NAVY);
    tft.setCursor(2, 3);
    tft.setTextColor(TFT_CYAN, TFT_NAVY);
    tft.setTextSize(1);
    tft.print(msg);
}

void drawStatus(const char *msg, uint16_t color = TFT_WHITE) {
    tft.fillRect(0, 220, 320, 20, TFT_BLACK);
    tft.setCursor(2, 223);
    tft.setTextColor(color, TFT_BLACK);
    tft.setTextSize(1);
    tft.print(msg);
}

void emitServiceJSON(const ServiceEntry &svc) {
    Serial.print("{\"type\":\"service\",\"name\":\"");
    Serial.print(svc.name);
    Serial.print("\",\"service_type\":\"");
    Serial.print(svc.service_type);
    Serial.print("\",\"host\":\"");
    Serial.print(svc.hostname);
    Serial.print("\",\"ip\":\"");
    Serial.print(svc.ip);
    Serial.print("\",\"port\":");
    Serial.print(svc.port);
    Serial.println("}");
}

// ---------------------------------------------------------------------------
// WiFi connection (with optional Serial credential prompt)
// ---------------------------------------------------------------------------

bool connectWiFi() {
    String ssid = String(WIFI_SSID);
    String pass = String(WIFI_PASS);

    if (ssid.length() == 0) {
        tft.fillScreen(TFT_BLACK);
        drawHeader("WiFi Setup — Enter credentials via Serial");
        tft.setCursor(2, 30);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.setTextSize(1);
        tft.println("Open Serial monitor at 115200 baud.");
        tft.println("Enter SSID and password when prompted.");

        Serial.println("[*] Enter WiFi SSID:");
        unsigned long t = millis();
        while (!Serial.available() && millis() - t < 30000) delay(100);
        if (Serial.available()) ssid = Serial.readStringUntil('\n');
        ssid.trim();

        Serial.println("[*] Enter WiFi Password:");
        t = millis();
        while (!Serial.available() && millis() - t < 30000) delay(100);
        if (Serial.available()) pass = Serial.readStringUntil('\n');
        pass.trim();
    }

    wifi_ssid = ssid;
    wifi_pass = pass;

    tft.fillScreen(TFT_BLACK);
    drawHeader("Connecting to WiFi...");
    tft.setCursor(2, 25);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.print("SSID: ");
    tft.println(ssid);

    Serial.print("{\"type\":\"wifi_connect\",\"ssid\":\"");
    Serial.print(ssid);
    Serial.println("\"}");

    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(), pass.c_str());

    unsigned long start = millis();
    int dots = 0;
    while (WiFi.status() != WL_CONNECTED && millis() - start < WIFI_TIMEOUT) {
        delay(500);
        tft.setCursor(2 + dots * 6, 50);
        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        tft.print(".");
        dots++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        String ip = WiFi.localIP().toString();
        tft.setCursor(2, 65);
        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        tft.print("Connected! IP: ");
        tft.println(ip);
        Serial.print("{\"type\":\"wifi_ok\",\"ip\":\"");
        Serial.print(ip);
        Serial.println("\"}");
        delay(1000);
        return true;
    } else {
        tft.setCursor(2, 65);
        tft.setTextColor(TFT_RED, TFT_BLACK);
        tft.print("WiFi connection failed!");
        Serial.println("{\"type\":\"wifi_error\",\"reason\":\"timeout\"}");
        delay(2000);
        return false;
    }
}

// ---------------------------------------------------------------------------
// mDNS scanning
// ---------------------------------------------------------------------------

void scanMDNS() {
    tft.fillScreen(TFT_BLACK);
    drawHeader("mDNS Scanner — Scanning...");

    if (!MDNS.begin("tdeck")) {
        tft.setCursor(2, 30);
        tft.setTextColor(TFT_RED, TFT_BLACK);
        tft.print("mDNS init failed!");
        Serial.println("{\"type\":\"error\",\"reason\":\"MDNS init failed\"}");
        return;
    }

    int y = 25;
    int idx = 0;
    while (SERVICE_TYPES[idx] != nullptr) {
        const char *stype = SERVICE_TYPES[idx++];

        // Update display
        tft.fillRect(0, 18, 320, 12, TFT_BLACK);
        tft.setCursor(2, 20);
        tft.setTextColor(TFT_YELLOW, TFT_BLACK);
        tft.setTextSize(1);
        char qbuf[40];
        snprintf(qbuf, sizeof(qbuf), "Querying %s._tcp...", stype);
        tft.print(qbuf);

        int n = MDNS.queryService(stype, "tcp");
        Serial.print("{\"type\":\"query\",\"service\":\"");
        Serial.print(stype);
        Serial.print("\",\"found\":");
        Serial.print(n);
        Serial.println("}");

        for (int i = 0; i < n; i++) {
            ServiceEntry entry;
            entry.name = MDNS.hostname(i);
            entry.service_type = String(stype) + "._tcp";
            entry.hostname = MDNS.hostname(i);
            entry.ip = MDNS.IP(i).toString();
            entry.port = MDNS.port(i);
            entry.txt = "";

            discovered.push_back(entry);
            emitServiceJSON(entry);

            // Brief display feedback
            if (y < 210) {
                tft.setCursor(2, y);
                tft.setTextColor(TFT_GREEN, TFT_BLACK);
                char line[50];
                snprintf(line, sizeof(line), "[+] %s  %s:%d",
                         entry.ip.c_str(),
                         entry.service_type.c_str(),
                         entry.port);
                tft.print(line);
                y += 11;
            }
        }
    }

    scan_complete = true;
    Serial.print("{\"type\":\"scan_complete\",\"total\":");
    Serial.print(discovered.size());
    Serial.println("}");
}

// ---------------------------------------------------------------------------
// Display results with scroll
// ---------------------------------------------------------------------------

void displayResults() {
    tft.fillScreen(TFT_BLACK);
    char header_buf[40];
    snprintf(header_buf, sizeof(header_buf), "mDNS Results: %d services", (int)discovered.size());
    drawHeader(header_buf);

    int y = 20;
    int items_per_page = 9;
    int start = scroll_offset;
    int end = min((int)discovered.size(), start + items_per_page);

    for (int i = start; i < end; i++) {
        const ServiceEntry &svc = discovered[i];
        tft.setCursor(2, y);
        tft.setTextColor(TFT_CYAN, TFT_BLACK);
        tft.setTextSize(1);

        char line1[50], line2[50];
        snprintf(line1, sizeof(line1), "%s", svc.name.substring(0, 40).c_str());
        snprintf(line2, sizeof(line2), "  %s:%d [%s]",
                 svc.ip.c_str(), svc.port, svc.service_type.c_str());

        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.print(line1);
        tft.setCursor(2, y + 10);
        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        tft.print(line2);
        y += 22;
    }

    if (discovered.empty()) {
        tft.setCursor(2, 60);
        tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
        tft.print("No services discovered.");
        tft.setCursor(2, 80);
        tft.print("Check WiFi connectivity.");
    }

    // Scroll indicator
    char scroll_info[30];
    snprintf(scroll_info, sizeof(scroll_info), "[%d/%d] UP/DN to scroll",
             min(start + items_per_page, (int)discovered.size()),
             (int)discovered.size());
    drawStatus(scroll_info, TFT_YELLOW);
}

// ---------------------------------------------------------------------------
// Trackball input
// ---------------------------------------------------------------------------

void handleTrackball() {
    if (digitalRead(TRACKBALL_DOWN) == LOW) {
        delay(150);
        if (scroll_offset + 9 < (int)discovered.size()) {
            scroll_offset++;
            displayResults();
        }
    }
    if (digitalRead(TRACKBALL_UP) == LOW) {
        delay(150);
        if (scroll_offset > 0) {
            scroll_offset--;
            displayResults();
        }
    }
}

// ---------------------------------------------------------------------------
// Setup / Loop
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    delay(500);

    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);

    pinMode(TRACKBALL_UP, INPUT_PULLUP);
    pinMode(TRACKBALL_DOWN, INPUT_PULLUP);
    pinMode(TRACKBALL_LEFT, INPUT_PULLUP);
    pinMode(TRACKBALL_RIGHT, INPUT_PULLUP);
    pinMode(TRACKBALL_CLICK, INPUT_PULLUP);

    tft.init();
    tft.setRotation(1);
    tft.fillScreen(TFT_BLACK);
    tft.setTextSize(1);

    Serial.println("{\"type\":\"init\",\"device\":\"T-Deck\",\"fw\":\"mdns_scanner\"}");

    if (connectWiFi()) {
        scanMDNS();
        displayResults();
    } else {
        drawHeader("mDNS Scanner — WiFi Error");
        tft.setCursor(2, 40);
        tft.setTextColor(TFT_RED, TFT_BLACK);
        tft.print("Could not connect to WiFi.");
        tft.setCursor(2, 55);
        tft.print("Set WIFI_SSID/WIFI_PASS and reflash,");
        tft.setCursor(2, 70);
        tft.print("or enter credentials via Serial.");
    }
}

void loop() {
    if (scan_complete) {
        handleTrackball();
    }
    delay(50);
}
