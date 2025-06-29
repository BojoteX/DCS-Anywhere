// RingBuffer.cpp - 

#include "RingBuffer.h"
#include "WiFiDebug.h" // Logger

// Forward declaration for GPDevice dummy report
void GPDevice_sendDummyReport();

// ---- Static RingBuffer Instances ----
RingBuffer<DCS_UDP_RINGBUF_SIZE, DCS_UDP_PACKET_MAXLEN> dcsUdpRing;
RingBuffer<DCS_USB_RINGBUF_SIZE, DCS_USB_PACKET_MAXLEN> dcsUsbRing;

// ---- DCS Frame Handler ----
static OnDcsFrameHandler s_onDcsFrameHandler = nullptr;
void setDcsFrameHandler(OnDcsFrameHandler handler) {
    s_onDcsFrameHandler = handler;
}

// ---- RingBuffer Implementation ----
template<size_t SIZE, size_t MAXLEN>
RingBuffer<SIZE, MAXLEN>::RingBuffer()
    : head_(0), tail_(0), overflow_(0), msgCount_(0),
    totalBytes_(0), highWater_(0), maxLen_(0) {
}

template<size_t SIZE, size_t MAXLEN>
bool RingBuffer<SIZE, MAXLEN>::pop(DcsMsg* out) {
    if (head_ == tail_) return false;
    *out = buffer_[tail_];
    tail_ = (tail_ + 1) % SIZE;
    return true;
}

template<size_t SIZE, size_t MAXLEN>
void RingBuffer<SIZE, MAXLEN>::push(const uint8_t* data, size_t len, bool isLastChunk) {
    if (((head_ + 1) % SIZE) == tail_) { overflow_++; return; }
    if (len > MAXLEN) len = MAXLEN;
    memcpy(buffer_[head_].data, data, len);
    buffer_[head_].len = len;
    buffer_[head_].isLastChunk = isLastChunk;
    head_ = (head_ + 1) % SIZE;
    size_t pend = pending();
    if (pend > highWater_) highWater_ = pend;
    totalBytes_ += len;
    msgCount_++;
    if (len > maxLen_) maxLen_ = len;
}

template<size_t SIZE, size_t MAXLEN>
void RingBuffer<SIZE, MAXLEN>::pushChunked(const uint8_t* data, size_t len) {
    const size_t max_data = MAXLEN;
    size_t needed = (len + max_data - 1) / max_data;
    if (available() < needed) { overflow_++; return; }
    size_t pos = 0;
    for (size_t chunk = 0; chunk < needed; ++chunk) {
        size_t chunk_len = (len - pos > max_data) ? max_data : (len - pos);
        bool last = (chunk == needed - 1);
        push(data + pos, chunk_len, last);
        pos += chunk_len;
    }
}

template<size_t SIZE, size_t MAXLEN>
size_t RingBuffer<SIZE, MAXLEN>::pending() const {
    if (head_ >= tail_) return head_ - tail_;
    return SIZE - (tail_ - head_);
}

template<size_t SIZE, size_t MAXLEN>
size_t RingBuffer<SIZE, MAXLEN>::available() const {
    if (head_ >= tail_)
        return SIZE - (head_ - tail_) - 1;
    else
        return (tail_ - head_) - 1;
}

template<size_t SIZE, size_t MAXLEN>
float RingBuffer<SIZE, MAXLEN>::avgMsgLen() const {
    return (msgCount_ > 0) ? ((float)totalBytes_ / msgCount_) : 0.0f;
}

// ---- Explicit Template Instantiation ----
template class RingBuffer<DCS_UDP_RINGBUF_SIZE, DCS_UDP_PACKET_MAXLEN>;
template class RingBuffer<DCS_USB_RINGBUF_SIZE, DCS_USB_PACKET_MAXLEN>;

// ---- Legacy API shims (drop-in, do not remove) ----
size_t   dcsUdpRingbufPending() { return dcsUdpRing.pending(); }
size_t   dcsUdpRingbufAvailable() { return dcsUdpRing.available(); }
bool     dcsUdpRingbufPop(DcsUdpRingMsg* out) { return dcsUdpRing.pop(out); }
void     dcsUdpRingbufPush(const uint8_t* d, size_t l, bool last) { dcsUdpRing.push(d, l, last); }
void     dcsUdpRingbufPushChunked(const uint8_t* d, size_t l) { dcsUdpRing.pushChunked(d, l); }
uint32_t dcsUdpRecvGetOverflow() { return dcsUdpRing.getOverflow(); }
size_t   dcsUdpRecvGetHighWater() { return dcsUdpRing.getHighWater(); }
size_t   dcsUdpRecvGetPending() { return dcsUdpRing.pending(); }
float    dcsUdpRecvAvgMsgLen() { return dcsUdpRing.avgMsgLen(); }
size_t   dcsUdpRecvMaxMsgLen() { return dcsUdpRing.maxMsgLen(); }

size_t   dcsRawUsbOutRingbufPending() { return dcsUsbRing.pending(); }
size_t   dcsRawUsbOutRingbufAvailable() { return dcsUsbRing.available(); }
bool     dcsRawUsbOutRingbufPop(DcsRawUsbOutRingMsg* out) { return dcsUsbRing.pop(out); }
void     dcsRawUsbOutRingbufPush(const uint8_t* d, size_t l, bool last) { dcsUsbRing.push(d, l, last); }
void     dcsRawUsbOutRingbufPushChunked(const uint8_t* d, size_t l) { dcsUsbRing.pushChunked(d, l); }
uint32_t dcsRawUsbOutGetOverflow() { return dcsUsbRing.getOverflow(); }
size_t   dcsRawUsbOutGetHighWater() { return dcsUsbRing.getHighWater(); }
size_t   dcsRawUsbOutGetPending() { return dcsUsbRing.pending(); }
float    dcsRawUsbOutAvgMsgLen() { return dcsUsbRing.avgMsgLen(); }
size_t   dcsRawUsbOutMaxMsgLen() { return dcsUsbRing.maxMsgLen(); }

// ---- Complete Frame Drain/Reassembly Logic ----
void onDcsBiosUdpPacket() {
    struct { uint8_t data[DCS_UDP_MAX_REASSEMBLED]; size_t len; } frames[MAX_UDP_FRAMES_PER_DRAIN];
    size_t frameCount = 0, reassemblyLen = 0;
    DcsUdpRingMsg pkt;

    while (dcsUdpRingbufPop(&pkt)) {
        if (reassemblyLen + pkt.len > sizeof(frames[0].data)) {
            reassemblyLen = 0;
            logDebug("❌ [RING BUFFER] Overflow! increase DCS_UDP_MAX_REASSEMBLED");
            continue;
        }
        memcpy(frames[frameCount].data + reassemblyLen, pkt.data, pkt.len);
        reassemblyLen += pkt.len;
        if (pkt.isLastChunk) {
            frames[frameCount].len = reassemblyLen;
            frameCount++;
            reassemblyLen = 0;
            if (frameCount == MAX_UDP_FRAMES_PER_DRAIN) break;
        }
    }
    if (s_onDcsFrameHandler) for (size_t n = 0; n < frameCount; ++n)
        s_onDcsFrameHandler(frames[n].data, frames[n].len);
}

void dcsSendCommand(const char* cmd) {
    if (!cmd) return;
    dcsRawUsbOutRingbufPushChunked(reinterpret_cast<const uint8_t*>(cmd), strlen(cmd));
    GPDevice_sendDummyReport();
}