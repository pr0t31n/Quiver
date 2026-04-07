// Particle Photon 2 — IoT Sensor Data Logger
// Reads ADC inputs and publishes sensor data to Particle cloud
// Flash via: particle flash --usb firmware.ino
// Or: particle compile photon2 firmware.ino --saveTo firmware.bin && particle flash --usb firmware.bin

#include "Particle.h"

SYSTEM_MODE(AUTOMATIC);   // Connect to Particle cloud automatically
SYSTEM_THREAD(ENABLED);   // System thread enabled for WiFi + user thread

// ── Configuration ─────────────────────────────────────────────────────────────
const int PUBLISH_INTERVAL_MS = 30000;   // Publish every 30 seconds
const int ADC_SAMPLES         = 10;      // ADC oversample count

// ── Globals ───────────────────────────────────────────────────────────────────
unsigned long lastPublish = 0;
int sampleCount           = 0;

void setup() {
    Serial.begin(115200);
    pinMode(A0, INPUT);
    pinMode(A1, INPUT);

    Serial.println("Photon 2 Sensor Logger starting...");
    Serial.println("Device ID: " + System.deviceID());
    Serial.println("Device OS: " + System.version());
}

void loop() {
    // Publish at configured interval
    if (millis() - lastPublish >= PUBLISH_INTERVAL_MS) {
        lastPublish = millis();
        publishSensorData();
        sampleCount++;
    }
}

void publishSensorData() {
    // Read ADC (average multiple samples for noise reduction)
    long rawA0 = 0, rawA1 = 0;
    for (int i = 0; i < ADC_SAMPLES; i++) {
        rawA0 += analogRead(A0);
        rawA1 += analogRead(A1);
        delay(5);
    }
    float voltA0 = (rawA0 / ADC_SAMPLES) * (3.3f / 4095.0f);
    float voltA1 = (rawA1 / ADC_SAMPLES) * (3.3f / 4095.0f);

    // Build JSON payload
    char payload[256];
    snprintf(payload, sizeof(payload),
        "{\"sample\":%d,\"a0_v\":%.3f,\"a1_v\":%.3f,\"uptime_s\":%lu,\"rssi\":%d}",
        sampleCount, voltA0, voltA1, millis() / 1000,
        (int)WiFi.RSSI());

    // Publish to Particle cloud (viewable at console.particle.io)
    bool ok = Particle.publish("sensor_data", payload, PRIVATE);

    Serial.printf("[%lu] Published (#%d): %s  [%s]\n",
        millis(), sampleCount, payload, ok ? "OK" : "FAIL");
}
