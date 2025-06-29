// RingBuffer.h 

#pragma once

#include "Config.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdarg>

typedef void (*OnDcsFrameHandler)(const uint8_t* data, size_t len);

void setDcsFrameHandler(OnDcsFrameHandler handler);
void handleDcsBiosFrame(const uint8_t* data, size_t len);

// Message struct for UDP/USB buffers
struct DcsMsg {
    uint8_t data[DCS_UDP_PACKET_MAXLEN];
    size_t  len;
    bool    isLastChunk;
};

using DcsUdpRingMsg     = DcsMsg;
using DcsRawUsbOutRingMsg = DcsMsg;

// ---- RingBuffer Class Template ----
template<size_t SIZE, size_t MAXLEN>
class RingBuffer {
public:
    RingBuffer();
    bool pop(DcsMsg* out);
    void push(const uint8_t* data, size_t len, bool isLastChunk);
    void pushChunked(const uint8_t* data, size_t len);
    size_t pending() const;
    size_t available() const;
    uint32_t getOverflow() const { return overflow_; }
    size_t getHighWater() const { return highWater_; }
    float avgMsgLen() const;
    size_t maxMsgLen() const { return maxLen_; }

private:
    DcsMsg buffer_[SIZE];
    volatile uint8_t head_, tail_;
    volatile uint32_t overflow_, msgCount_, totalBytes_;
    volatile size_t highWater_, maxLen_;
};

extern RingBuffer<DCS_UDP_RINGBUF_SIZE, DCS_UDP_PACKET_MAXLEN> dcsUdpRing;
extern RingBuffer<DCS_USB_RINGBUF_SIZE, DCS_USB_PACKET_MAXLEN> dcsUsbRing;

// API shims for legacy function names (for drop-in compatibility)
size_t   dcsUdpRingbufPending();
size_t   dcsUdpRingbufAvailable();
bool     dcsUdpRingbufPop(DcsUdpRingMsg* out);
void     dcsUdpRingbufPush(const uint8_t* data, size_t len, bool isLastChunk);
void     dcsUdpRingbufPushChunked(const uint8_t* data, size_t len);

uint32_t dcsUdpRecvGetOverflow();
size_t   dcsUdpRecvGetHighWater();
size_t   dcsUdpRecvGetPending();
float    dcsUdpRecvAvgMsgLen();
size_t   dcsUdpRecvMaxMsgLen();

size_t   dcsRawUsbOutRingbufPending();
size_t   dcsRawUsbOutRingbufAvailable();
bool     dcsRawUsbOutRingbufPop(DcsRawUsbOutRingMsg* out);
void     dcsRawUsbOutRingbufPush(const uint8_t* data, size_t len, bool isLastChunk);
void     dcsRawUsbOutRingbufPushChunked(const uint8_t* data, size_t len);

uint32_t dcsRawUsbOutGetOverflow();
size_t   dcsRawUsbOutGetHighWater();
size_t   dcsRawUsbOutGetPending();
float    dcsRawUsbOutAvgMsgLen();
size_t   dcsRawUsbOutMaxMsgLen();

void    onDcsBiosUdpPacket();
void    dcsSendCommand(const char* cmd);
