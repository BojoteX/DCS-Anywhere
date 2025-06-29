// GPDevice.cpp 

#include "Config.h"
#include <USB.h>
#include <USBHID.h>
#include "GPDevice.h"
#include "WiFiDebug.h"
#include "Arduino.h"

// --- USB Device Instances ---
USBHID    HID;
GPDevice  gamepad;

// HID report descriptor
const uint8_t cockpitos_hid_report_desc[] = {
    // Gamepad Input Report (64 bytes)
    0x05, 0x01, 0x09, 0x05, 0xA1, 0x01,
    0x09, 0x36, 0x09, 0x36, 0x09, 0x36, 0x15, 0x00, 0x26, 0xFF, 0x0F, 0x75, 0x10, 0x95, 0x03, 0x81, 0x02,
    0x05, 0x09, 0x19, 0x01, 0x29, 0x20, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x20, 0x81, 0x02,
    0x75, 0x08, 0x95, 0x06, 0x81, 0x03,
    0x75, 0x08, 0x95, 0x30, 0x81, 0x03,
    0x06, 0x00, 0xFF, 0x09, 0x01, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
    0x06, 0x00, 0xFF, 0x09, 0x02, 0x75, 0x08, 0x95, 0x40, 0xB1, 0x02,
    0xC0
};

void GPDevice_init() {
    HID.begin();
    USB.begin();
    delay(3000);
    logDebugf("%s initialized\n", MY_DEVICE_NAME);
}

void GPDevice_sendDummyReport() {
    gamepad.sendDummyInReport(); // HID handshake kick
}

GPDevice::GPDevice() {
    USB.VID(MY_DEVICE_VID); // If you change here, Python HID Controller needs to change too
    USB.PID(MY_DEVICE_PID); // If you change here, Python HID Controller needs to change too
    USB.manufacturerName("CockpitOS Firmware Project");
    USB.productName(MY_DEVICE_NAME);
    USB.serialNumber(MY_DEVICE_NAME); // Set in Main INO
    HID.addDevice(this, sizeof(cockpitos_hid_report_desc));
    HID.onEvent(ARDUINO_USB_HID_SET_PROTOCOL_EVENT, GPDevice::hidSetProtocolHandler);
    HID.onEvent(ARDUINO_USB_HID_SET_IDLE_EVENT, GPDevice::hidSetIdleHandler);
}

uint16_t GPDevice::_onGetDescriptor(uint8_t* buf) {
    memcpy(buf, cockpitos_hid_report_desc, sizeof(cockpitos_hid_report_desc));
    return sizeof(cockpitos_hid_report_desc);
}

// --- Outbound Feature Handler (Device → Host) ---
uint16_t GPDevice::_onGetFeature(uint8_t report_id, uint8_t* buffer, uint16_t len) {
    if (!mainLoopStarted) {
        memset(buffer, 0, 64);
        return 64;
    }
    if (dcsRawUsbOutRingbufPending() > 0) {
        DcsRawUsbOutRingMsg msg;
        dcsRawUsbOutRingbufPop(&msg);
        memcpy(buffer, msg.data, msg.len);
        if (msg.len < 64) memset(buffer + msg.len, 0, 64 - msg.len);
        return 64;
    }
    memset(buffer, 0, 64);
    return 64;
}

// --- Inbound Feature Handler (Host → Device) ---
void GPDevice::_onSetFeature(uint8_t report_id, const uint8_t* buffer, uint16_t len) {
    if (mainLoopStarted && len > 0) {
        dcsRawUsbOutRingbufPushChunked(buffer, len);
    }
}

// --- OUT report (Host→Device) ---
void GPDevice::_onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) {
    if (!mainLoopStarted) return;
    dcsUdpRingbufPushChunked(buffer, len);
}

// --- Dummy IN report (Device→Host) ---
bool GPDevice::sendDummyInReport() {
    uint8_t dummy[64] = { 0 };
    return HID.SendReport(0, dummy, 64, 0);
}

// --- HID Optional Event Handlers ---
void GPDevice::hidSetProtocolHandler(void*, esp_event_base_t, int32_t, void*) {}
void GPDevice::hidSetIdleHandler(void*, esp_event_base_t, int32_t, void*) {}