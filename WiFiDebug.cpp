#include "WiFiDebug.h"
#include <cstring>

const uint8_t WiFiDebug::default_ip[4] = { WIFI_DEBUG_REMOTE_IP };

WiFiDebug wifiLogger; // Global instance

WiFiDebug::WiFiDebug() : remotePort(WIFI_DEBUG_REMOTE_PORT), remoteIP(default_ip) {}

void WiFiDebug::begin(const char* ssid, const char* pass, const uint8_t* remote_ip, uint16_t port) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, pass);
    remotePort = port;
    remoteIP = IPAddress(remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3]);
    while (WiFi.status() != WL_CONNECTED) {
        delay(300);
    }
    udp.begin(WiFi.localIP(), 0); // local port auto
    println("WiFiDebug logger started");
}

void WiFiDebug::sendChunks(const char* data, size_t len, bool addNewline) {
    if (!data || WiFi.status() != WL_CONNECTED) return;

    size_t sent = 0;
    while (sent < len) {
        size_t chunk = ((len - sent) > MAX_MSG_LEN) ? MAX_MSG_LEN : (len - sent);
        udp.beginPacket(remoteIP, remotePort);
        udp.write((const uint8_t*)(data + sent), chunk);
        // Only append newline to last packet if requested
        if ((sent + chunk) == len && addNewline) {
            udp.write((const uint8_t*)"\n", 1);
        }
        udp.endPacket();
        sent += chunk;
    }
}

void WiFiDebug::print(const char* msg) {
    if (!msg) return;
    sendChunks(msg, strlen(msg), false);
}

void WiFiDebug::println(const char* msg) {
    if (!msg) {
        sendChunks("\n", 1, false);
        return;
    }
    sendChunks(msg, strlen(msg), true);
}

// --- The CRITICAL FIX ---
void WiFiDebug::printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void WiFiDebug::vprintf(const char* fmt, va_list args) {
    if (!fmt || WiFi.status() != WL_CONNECTED) return;
    char buf[LOG_BUF_SIZE];
    vsnprintf(buf, sizeof(buf), fmt, args);
    buf[sizeof(buf) - 1] = '\0';
    print(buf);
}

void WiFiDebug::writeBuf(const void* buf, size_t len) {
    if (!buf || len == 0 || WiFi.status() != WL_CONNECTED) return;
    sendChunks(reinterpret_cast<const char*>(buf), len, false);
}

void WiFiDebug::print(const char* msg, int val) {
    char buf[LOG_BUF_SIZE];
    snprintf(buf, sizeof(buf), "%s%d", msg ? msg : "", val);
    print(buf);
}

void WiFiDebug::print(const char* msg, unsigned int val) {
    char buf[LOG_BUF_SIZE];
    snprintf(buf, sizeof(buf), "%s%u", msg ? msg : "", val);
    print(buf);
}

void WiFiDebug::print(const char* msg, const char* val) {
    char buf[LOG_BUF_SIZE];
    snprintf(buf, sizeof(buf), "%s%s", msg ? msg : "", val ? val : "");
    print(buf);
}
