#pragma once

#include <WiFi.h>
#include <WiFiUdp.h>
#include <cstdarg>
#include <cstddef> // for size_t

#ifndef WIFI_DEBUG_SSID
#define WIFI_DEBUG_SSID     "YOUR_WIFI_SSID"
#endif
#ifndef WIFI_DEBUG_PASS
#define WIFI_DEBUG_PASS     "YOUR_WIFI_PASSWORD"
#endif
#ifndef WIFI_DEBUG_REMOTE_IP
#define WIFI_DEBUG_REMOTE_IP 255,255,255,255
#endif
#ifndef WIFI_DEBUG_REMOTE_PORT
#define WIFI_DEBUG_REMOTE_PORT 4210
#endif

class WiFiDebug {
public:
    WiFiDebug();
    void begin(const char* ssid = WIFI_DEBUG_SSID, const char* pass = WIFI_DEBUG_PASS,
               const uint8_t* remote_ip = default_ip, uint16_t port = WIFI_DEBUG_REMOTE_PORT);

    void print(const char* msg);
    void println(const char* msg);
    void printf(const char* fmt, ...);
    void vprintf(const char* fmt, va_list args);

    void writeBuf(const void* buf, size_t len);

    void print(const char* msg, int val);
    void print(const char* msg, unsigned int val);
    void print(const char* msg, const char* val);

private:
    WiFiUDP udp;
    IPAddress remoteIP;
    uint16_t remotePort;
    static constexpr size_t LOG_BUF_SIZE = 256;
    static constexpr size_t MAX_MSG_LEN = 240;
    static const uint8_t default_ip[4];
    void sendChunks(const char* data, size_t len, bool addNewline);
};

// Global instance for use everywhere
extern WiFiDebug wifiLogger;

// Drop-in helpers
inline void logDebug(const char* msg)                   { wifiLogger.print(msg); }
inline void logDebugln(const char* msg)                 { wifiLogger.println(msg); }
inline void logDebug(const char* msg, int val)          { wifiLogger.print(msg, val); }
inline void logDebug(const char* msg, unsigned int val) { wifiLogger.print(msg, val); }
inline void logDebug(const char* msg, const char* val)  { wifiLogger.print(msg, val); }
inline void logDebug(const void* buf, size_t len)       { wifiLogger.writeBuf(buf, len); }
inline void logDebugf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    wifiLogger.vprintf(fmt, args);  // Correctly calls vprintf!
    va_end(args);
}
