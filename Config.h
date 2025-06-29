// Your Device Name
#define MY_DEVICE_NAME "ESP32S2 Device"

// USB VID/PID
#define MY_DEVICE_VID 0xCAFE
#define MY_DEVICE_PID 0xCAF3

// Protocol constants for DCSBIOS over USB communication (DOT NOT CHANGE)
#define MAX_UDP_FRAMES_PER_DRAIN   1
#define DCS_USB_RINGBUF_SIZE       8
#define DCS_USB_PACKET_MAXLEN      64
#define DCS_UDP_RINGBUF_SIZE       32
#define DCS_UDP_PACKET_MAXLEN      64
#define DCS_UDP_MAX_REASSEMBLED    1472
