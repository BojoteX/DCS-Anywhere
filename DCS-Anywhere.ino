// DCS-Anywhere.ino - Standalone USB to DCSBIOS Basic framework

// Use debugLog, debugLogf to debug output to your network console via UDP

// Needed for DCSBIOS over USB
#include "RingBuffer.h" 
#include "GPDevice.h"
#include "WiFiDebug.h"

// --- DCS-BIOS Library Config ---
#define DCSBIOS_DISABLE_SERVO
#define DCSBIOS_DEFAULT_SERIAL
#include <DcsBios.h>

// Globals
volatile bool mainLoopStarted = false; // Required for USB Handshaking logic
unsigned long lastSend = 0; // Just used for sample sending commands every x seconds

// --- DCS Aircraft Name Buffer --- (Just for testing)
#define ACFT_NAME_ADDR 0x0000
#define ACFT_NAME_LEN  24
char aircraftName[ACFT_NAME_LEN + 1] = {};
void onAircraftName(char* str) {
    // Always safe: copy with null-termination for ASCII use
    strncpy(aircraftName, str, ACFT_NAME_LEN);
    aircraftName[ACFT_NAME_LEN] = 0;

    // Print as null-terminated string (ASCII-safe)
    logDebugf("[DCSBIOS] Aircraft Name: %s\n", aircraftName);
}
DcsBios::StringBuffer<ACFT_NAME_LEN> aircraftNameBuffer(ACFT_NAME_ADDR, onAircraftName);

// --- DCS Frame Handler (USB/UDP Stream Processing) --- 
void handleDcsBiosFrame(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        DcsBios::parser.processChar(data[i]);
    DcsBios::PollingInput::pollInputs();
    DcsBios::ExportStreamListener::loopAll();
}

// --- ESP32 Setup ---
void setup() {
    setDcsFrameHandler(handleDcsBiosFrame); // This is the equivalent of what was DcsBios::setup
    wifiLogger.begin("MyHotspotNetwork","TestingOnly"); // SSID + PASSWD
    GPDevice_init();
}

void loop() {
    // ---- USB handshake: do not change ----
    if (!mainLoopStarted) {
        dcsSendCommand("STARTING HANDSHAKE\n");
        mainLoopStarted = true;
    }

    // Process any received DCS frames via USB
    onDcsBiosUdpPacket(); // This is the equivalent of what was DcsBios::loop

    // Example periodic DCS-BIOS command + status log
    if (millis() - lastSend > 5000) {
        lastSend = millis();
        const char* cmd = "UFC_1 1\n";
        dcsSendCommand(cmd);
        logDebugf("[DCSBIOS] Aircraft Name: %s\n", aircraftName);
    }
}