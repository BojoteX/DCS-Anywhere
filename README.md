# 🚀 DCS-Anywhere

*A minimal USB HID and UDP bridge for DCS-BIOS. Connect your panels to any PC, run DCS anywhere.*

---

## ✈️ What is DCS-Anywhere?

**DCS-Anywhere** lets you connect your DCS-BIOS-enabled cockpit panels (built with ESP32 microcontrollers) to *any* PC on your network, no serial ports, no drivers, no physical link to your DCS computer required.  
It uses a high-performance USB HID protocol (no COM ports!) and a Python network bridge that relays DCS-BIOS traffic via UDP multicast.

---

## 🛠️ Requirements

- **PC running DCS World** with:
  - [DCS-BIOS Skunkworks fork](https://github.com/DCS-Skunkworks/dcs-bios) installed and exporting UDP traffic
- **Panel hardware**:
  - **ESP32, ESP32-S2, or ESP32-S3** running the [ESP32 Arduino Core](https://github.com/espressif/arduino-esp32) (only Arduino C++, no MicroPython or STM32!)
  - [DCS-BIOS Arduino Library](https://github.com/DCS-Skunkworks/dcs-bios) installed in your Arduino IDE
- **Host PC for panels** (can be Windows, Linux, or Mac)
  - [Python 3.7+](https://www.python.org/)
  - [`hidapi`](https://pypi.org/project/hidapi/), `tkinter`, and standard libraries (`pip install hidapi`)
- **Network**: All machines must be on the same LAN (multicast UDP must be permitted).

---

## 📁 Directory Structure

```
DCS-Anywhere/
├── DCSBIOS_USB.ino         	# Main ESP32 firmware
├── WiFiDebug.cpp/h            # UDP network logging
├── RingBuffer.cpp/h           # USB/UDP frame buffer
├── GPDevice.cpp/h             # USB HID interface
├── Config.h                   # Device/protocol config
│
├── Tools/
│   ├── DCS_stream_replay.py      # Replay DCS-BIOS UDP streams
│   ├── DCS_commands_logger.py    # Log all UDP commands to DCS
│   ├── UDP_console_debugger.py   # Live debug console for ESP32
│   └── dcsbios_data.json         # Example binary stream data
│
├── HID Manager/
│   └── HID_Manager.py  	   # Python network-to-HID bridge/dashboard
│
├── README.md
└── (plus additional .cpp/.h sources)
```

---

## ⚡ Key Features

- 🔌 **No Serial Ports:** All panel communication is via USB HID. *No drivers, no COM headaches.*
- 🌐 **Panels can be remote:** Plug your panels into ANY computer on your network (not just your DCS machine)!
- 🧠 **Smart network bridge:** Python HID Manager auto-detects the DCS PC’s IP via multicast—no user setup.
- 📝 **Modern, modular C++ and Python:** Easy to adapt for any DCS-BIOS panel project.
- 🛠️ **Developer tools:** Simulate DCS traffic, log panel commands, and debug over the network.
- 💻 **Full cross-platform:** Panels and bridge run on Windows, Linux, MacOS.

---

## 🔗 **Required Software & Links**

- **DCS-BIOS Skunkworks (PC):**  
  [https://github.com/DCS-Skunkworks/dcs-bios](https://github.com/DCS-Skunkworks/dcs-bios)
- **DCS-BIOS Arduino Library (Arduino IDE):**  
  [https://github.com/DCS-Skunkworks/dcs-bios](https://github.com/DCS-Skunkworks/dcs-bios)
- **ESP32 Arduino Core (for your IDE):**  
  [https://github.com/espressif/arduino-esp32](https://github.com/espressif/arduino-esp32)
- **Python HIDAPI:**  
  `pip install hidapi`
- **tkinter** (for dashboard GUI; standard with Python on Windows, or `sudo apt install python3-tk` on Linux)

---

## 🚦 Supported Hardware

- ✔️ **ESP32**, **ESP32S2**, **ESP32S3** (with Arduino framework)
- ❌ **Not supported:** STM32, Teensy, MicroPython, ESP8266, or any non-Arduino board.
- ❗ *Tested only with Arduino Core for ESP32 using Arduino IDE 2.x. No PlatformIO, ESP-IDF, or other toolchains.*

---

## 🏁 Quick Start

### 1. **Flash ESP32 Firmware**

- Open `DCSBIOS_USB.ino` and its dependencies in Arduino IDE.
- Ensure **DCS-BIOS Arduino Library** and **ESP32 Arduino Core** are installed.
- Select ESP32S2 Dev Module as your board (or any ESP32 compatible board)
- Upload to your ESP32 panel hardware.

### 2. **Set up DCS World & Skunkworks DCS-BIOS**

- On your DCS computer, install [DCS-BIOS Skunkworks](https://github.com/DCS-Skunkworks/dcs-bios) and enable UDP export.

### 3. **Run the Python HID Manager (on your "panel hub" PC)**

- Install Python 3.7+ and `hidapi`.
- Run:  
  ```sh
  python HID\ Manager/HID_Manager.py
  ```
- Plug in your ESP32 panel(s).

### 4. **Debug, Log, and Simulate (optional)**

- Use `Tools/UDP_console_debugger.py` for live debug logs.
- Simulate DCS-BIOS streams with `Tools/DCS_stream_replay.py`.
- Log panel-to-DCS traffic with `Tools/DCS_commands_logger.py`.

---

## 🌐 How It Works

- **DCS World (PC)** ➡️ DCS-BIOS UDP Multicast ➡️ **Python HID Manager** ➡️ USB HID ➡️ **ESP32 Panel**
- **ESP32 Panel** ➡️ USB HID FEATURE reports ➡️ **Python HID Manager** ➡️ UDP ➡️ **DCS-BIOS on PC**

- The Python script listens for DCS-BIOS UDP multicast frames, splits them into USB packets, and relays to your panels.
- Panel input (buttons, axes) is sent back as ASCII commands via USB HID, forwarded by Python over UDP to DCS-BIOS.

---

## 🖥️ Platform Support

- **Panels:** ESP32, ESP32S2, ESP32S3 (Arduino C++)
- **Hub PC:** Any OS with Python 3.7+ (Windows, Linux, macOS)
- **DCS World PC:** Windows, with DCS-BIOS Skunkworks

---

## 🧩 Included Tools

| Tool                        | Purpose                                      |
|-----------------------------|----------------------------------------------|
| `UDP_console_debugger.py`   | Shows all ESP32 UDP debug output             |
| `DCS_stream_replay.py`      | Replays a recorded DCS-BIOS stream (from JSON)|
| `DCS_commands_logger.py`    | Logs all UDP commands sent to DCS            |
| `dcsbios_data.json`         | Sample DCS-BIOS session (for sim/replay)     |

---

## 🙋 FAQ

**Q: Can I use this with any microcontroller?**  
A: **No, only ESP32/ESP32S2/ESP32S3 with Arduino Core are supported.**

**Q: Do I have to plug my panels into the DCS PC?**  
A: **No!** Plug them into any PC, anywhere on your LAN.

**Q: Does this work on Mac/Linux?**  
A: Yes—both for the panel bridge and Python dashboard.

**Q: Do I need to manually enter any IP addresses?**  
A: No. The Python HID Manager listens to multicast and auto-configures everything.

**Q: What if I don't have DCS running?**  
A: You can use the included tools to simulate streams and debug your panels without DCS.

---

## 📄 License

MIT License (see [LICENSE](LICENSE))

---

**Made by the CockpitOS Firmware Project Team.  
Plug in, fly anywhere.**
