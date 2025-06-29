// GPDevice.h

#pragma once

#include <USBHID.h>
#include <USB.h>
#include "RingBuffer.h"

// Protocol string constants
#define FEATURE_HANDSHAKE_REQ  "DCSBIOS-HANDSHAKE"
#define FEATURE_HANDSHAKE_RESP "DCSBIOS-READY"

void GPDevice_init();
void GPDevice_sendDummyReport();

extern USBHID HID;

// External variables and functions
extern const uint8_t cockpitos_hid_report_desc[];
extern volatile bool mainLoopStarted;

class GPDevice : public USBHIDDevice {
public:
    GPDevice();

    uint16_t _onGetDescriptor(uint8_t* buf) override;
    uint16_t _onGetFeature(uint8_t report_id, uint8_t* buffer, uint16_t len) override;
    void     _onSetFeature(uint8_t report_id, const uint8_t* buffer, uint16_t len) override;
    void     _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) override;
    bool     sendDummyInReport();

    static void hidSetProtocolHandler(void* arg, esp_event_base_t, int32_t, void* event_data);
    static void hidSetIdleHandler(void* arg, esp_event_base_t, int32_t, void* event_data);
};