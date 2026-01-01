#!/usr/bin/env python3
"""
CockpitOS HID Manager - Refactored for Scale (v3, production-hardened)
Handles 200+ devices with fixed thread pool (O(1) threads, not O(N))

Features:
- Fixed thread pool architecture (12 threads regardless of device count)
- Non-blocking HID polling
- Professional curses-based console UI
- Cross-platform (Windows, Linux, macOS)
- File/stdout logging with backpressure warnings
- Retry logic with exponential backoff for transient failures
- Thread-safe statistics collection
- Fully importable as a library (no module-level side effects)

Author: CockpitOS Project
License: MIT
"""

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS AND BOOTSTRAP
# ══════════════════════════════════════════════════════════════════════════════

from __future__ import annotations

import sys
import os
import time
import socket
import struct
import threading
import queue
import configparser
import ipaddress
import logging
from collections import deque
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Callable, Tuple, Any, Deque

# Script directory - computed but NOT changed at import time
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Platform detection
IS_WINDOWS = (os.name == 'nt') or sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform == 'darwin'


def _detect_raspberry_pi() -> bool:
    """Detect if running on Raspberry Pi hardware."""
    if not IS_LINUX:
        return False
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read().lower()
            return 'raspberry' in cpuinfo or 'bcm2' in cpuinfo
    except Exception:
        return False


def _detect_arm_platform() -> bool:
    """Detect if running on ARM architecture."""
    import platform
    machine = platform.machine().lower()
    return 'arm' in machine or 'aarch' in machine


IS_RASPBERRY_PI = _detect_raspberry_pi()
IS_ARM = _detect_arm_platform()

# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECK
# ══════════════════════════════════════════════════════════════════════════════

REQUIRED_MODULES = {
    "hid": "hidapi",
    "filelock": "filelock",
    "curses": "windows-curses" if IS_WINDOWS else None,
}

missing = []
for mod, pip_name in REQUIRED_MODULES.items():
    try:
        __import__(mod)
    except ImportError:
        if pip_name:
            missing.append(pip_name)
        else:
            missing.append(mod)

if missing:
    print("Missing required modules:")
    for m in missing:
        print(f"  - {m}")
    to_pip = [m for m in missing if m not in ("curses",)]
    if to_pip:
        print(f"\nInstall with: pip install {' '.join(to_pip)}")
    input("\nPress Enter to exit...")
    sys.exit(1)

import hid
import curses
from filelock import FileLock, Timeout

# ══════════════════════════════════════════════════════════════════════════════
# SINGLE INSTANCE LOCK
# ══════════════════════════════════════════════════════════════════════════════

LOCKFILE = os.path.join(SCRIPT_DIR, "hid_manager.lock")

# Global lock reference - acquired in main(), not at import time
_instance_lock: Optional[FileLock] = None


def acquire_instance_lock() -> FileLock:
    """
    Acquire single-instance lock. Call this in main(), not at import time.
    Returns the lock object (caller must release on exit).
    Raises SystemExit if another instance is running.
    """
    global _instance_lock
    try:
        _instance_lock = FileLock(LOCKFILE)
        _instance_lock.acquire(timeout=0.1)
        return _instance_lock
    except Timeout:
        print("ERROR: Another instance of CockpitOS HID Manager is already running.")
        input("Press Enter to exit...")
        sys.exit(1)


def release_instance_lock() -> None:
    """Release the single-instance lock if held."""
    global _instance_lock
    if _instance_lock is not None:
        try:
            _instance_lock.release()
        except Exception:
            # Suppress all errors during cleanup - lock may already be released
            # or file may be inaccessible. Logging here could cause recursion issues.
            pass
        _instance_lock = None

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# Protocol constants
DEFAULT_REPORT_SIZE    = 64
DEFAULT_MULTICAST_IP   = "239.255.50.10"
DEFAULT_UDP_PORT       = 5010
DEFAULT_DCS_TX_PORT    = 7778
HANDSHAKE_REQ          = b"DCSBIOS-HANDSHAKE"
FEATURE_REPORT_ID      = 0       # Default HID report ID (0 = no report ID prefix)

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM-SPECIFIC TUNING
# ─────────────────────────────────────────────────────────────────────────────
# Raspberry Pi 4 has known USB limitations:
# - Shared USB/Ethernet bandwidth on BCM2711
# - Limited USB power budget (~1.2A total)
# - ARM CPU less efficient at high-frequency polling
# - File descriptor limits can be hit with many HID devices
#
# These settings are auto-adjusted for Pi to improve stability at 10+ devices.

if IS_RASPBERRY_PI:
    # Raspberry Pi optimized settings
    TX_WORKERS             = 2       # Fewer workers reduce USB contention
    RX_POLLERS             = 2       # Fewer pollers reduce CPU load
    RX_POLL_INTERVAL_MS    = 5       # Slower polling reduces USB bus saturation
    HANDSHAKE_WORKERS      = 2       # Parallel handshakes prevent queue stalls
    HANDSHAKE_STAGGER_MS   = 100     # Stagger device init to avoid USB surge
    TX_ALL_OR_NOTHING      = True    # Drop entire frame if any queue full (consistency)
    MAX_DEVICES            = 20      # Practical limit for Pi USB bandwidth
    UDP_RX_BUFFER_SIZE     = 1 * 1024 * 1024  # 1MB - lower memory pressure
elif IS_ARM:
    # Generic ARM (not Pi) - moderate settings
    TX_WORKERS             = 3
    RX_POLLERS             = 3
    RX_POLL_INTERVAL_MS    = 2
    HANDSHAKE_WORKERS      = 2
    HANDSHAKE_STAGGER_MS   = 50
    TX_ALL_OR_NOTHING      = False
    MAX_DEVICES            = 128
    UDP_RX_BUFFER_SIZE     = 2 * 1024 * 1024
else:
    # Windows/Linux x86/x64 - full performance
    TX_WORKERS             = 4       # HID write workers
    RX_POLLERS             = 4       # HID read pollers
    RX_POLL_INTERVAL_MS    = 1       # Polling interval (ms)
    HANDSHAKE_WORKERS      = 3       # Parallel handshake workers
    HANDSHAKE_STAGGER_MS   = 0       # No stagger needed on fast platforms
    TX_ALL_OR_NOTHING      = False   # Best-effort dispatch (faster)
    MAX_DEVICES            = 256     # Registry capacity
    UDP_RX_BUFFER_SIZE     = 4 * 1024 * 1024  # 4MB kernel buffer

# Common settings (all platforms)
TX_QUEUE_SIZE          = 1024    # Dispatch queue depth
LOG_HISTORY_SIZE       = 2000    # Max log lines kept
LOG_PATH               = os.path.join(SCRIPT_DIR, "hid_manager.log")
LOG_STDOUT             = True    # Also log to stdout/stderr (in addition to UI)
HANDSHAKE_QUEUE_WARN   = 6       # Warn if more than this many pending handshakes
TX_DROP_LOG_INTERVAL_S = 5.0     # Throttle log spam for TX drops

# Device open retry configuration
DEVICE_OPEN_MAX_RETRIES = 3      # Max retry attempts for device open
DEVICE_OPEN_BASE_DELAY  = 0.5    # Base delay for exponential backoff (seconds)
DEVICE_OPEN_MAX_DELAY   = 4.0    # Maximum delay between retries (seconds)

# Handshake retry configuration (for devices that fail handshake)
HANDSHAKE_RETRY_ENABLED = True   # Enable retry for failed handshakes
HANDSHAKE_RETRY_MAX     = 3      # Max retry attempts after initial failure
HANDSHAKE_RETRY_DELAY   = 5.0    # Delay between retry attempts (seconds)

# Thread shutdown timeouts
THREAD_JOIN_TIMEOUT     = 2.0    # Timeout for thread joins (seconds)
THREAD_JOIN_WARN        = True   # Log warning if thread doesn't join in time

# Debug log rate limiting (per device)
DEBUG_LOG_INTERVAL_S    = 2.0    # Minimum interval between debug logs per device

# UI refresh
UI_REFRESH_MS          = 50      # Console refresh interval

# Maximum expected HID report size (for validation)
MAX_HID_REPORT_SIZE    = 256     # Reasonable upper bound for validation


def extract_feature_payload(resp: List[int], expected_size: int = DEFAULT_REPORT_SIZE,
                            report_id: Optional[int] = None) -> bytes:
    """
    Normalize HID feature report payload (strip report ID when present).

    Args:
        resp: Raw HID response as list of integers
        expected_size: Expected payload size for validation
        report_id: Expected report ID to strip (uses global setting if None)

    Returns:
        Extracted payload as bytes, empty bytes if invalid
    """
    if not resp:
        return b""

    # Validate response is within reasonable bounds
    if len(resp) > MAX_HID_REPORT_SIZE:
        # Truncate to maximum expected size to prevent memory issues
        resp = resp[:MAX_HID_REPORT_SIZE]

    # Validate all values are valid bytes (0-255)
    if not all(isinstance(b, int) and 0 <= b <= 255 for b in resp):
        return b""

    # Use provided report_id or global default
    rid = report_id if report_id is not None else FEATURE_REPORT_ID
    if resp[0] == rid:
        return bytes(resp[1:])
    return bytes(resp)


# ══════════════════════════════════════════════════════════════════════════════
# LINUX USB DIAGNOSTICS
# ══════════════════════════════════════════════════════════════════════════════

def get_linux_usb_diagnostics() -> Dict[str, Any]:
    """
    Gather Linux-specific USB diagnostic information.
    Helps diagnose issues on Raspberry Pi and other Linux systems.

    Returns:
        Dictionary with USB diagnostic data, empty dict on non-Linux or errors.
    """
    if not IS_LINUX:
        return {}

    diagnostics: Dict[str, Any] = {}

    try:
        # Check file descriptor limits
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        diagnostics['fd_limit_soft'] = soft
        diagnostics['fd_limit_hard'] = hard

        # Count current open file descriptors
        fd_count = len(os.listdir('/proc/self/fd'))
        diagnostics['fd_in_use'] = fd_count
        diagnostics['fd_remaining'] = soft - fd_count

    except Exception:
        pass

    try:
        # Check for USB power issues in dmesg (requires root or dmesg access)
        import subprocess
        result = subprocess.run(
            ['dmesg', '--level=warn,err', '-T'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            usb_errors = [
                line for line in result.stdout.split('\n')
                if 'usb' in line.lower() and ('over-current' in line.lower() or
                   'power' in line.lower() or 'disconnect' in line.lower() or
                   'reset' in line.lower())
            ][-5:]  # Last 5 USB-related warnings/errors
            if usb_errors:
                diagnostics['recent_usb_errors'] = usb_errors
        else:
            # dmesg returned non-zero (permission denied or other issue)
            diagnostics['dmesg_unavailable'] = True
    except PermissionError:
        diagnostics['dmesg_unavailable'] = True
    except Exception:
        diagnostics['dmesg_unavailable'] = True

    try:
        # Check USB device count
        usb_devices_path = '/sys/bus/usb/devices'
        if os.path.exists(usb_devices_path):
            usb_count = len([d for d in os.listdir(usb_devices_path) if d[0].isdigit()])
            diagnostics['usb_device_count'] = usb_count
    except Exception:
        pass

    return diagnostics


def log_usb_diagnostics(uiq: Optional[queue.Queue]) -> None:
    """Log USB diagnostic information for troubleshooting."""
    if not IS_LINUX:
        return

    diag = get_linux_usb_diagnostics()
    if not diag:
        return

    # Log platform info
    platform_info = "Raspberry Pi" if IS_RASPBERRY_PI else ("ARM Linux" if IS_ARM else "Linux x86/x64")
    log_event(uiq, 'USB', f"Platform: {platform_info}")

    # Log FD usage
    if 'fd_remaining' in diag:
        if diag['fd_remaining'] < 50:
            log_event(uiq, 'USB',
                f"WARNING: Low file descriptors remaining ({diag['fd_remaining']}). "
                f"Consider: ulimit -n 4096", "warning")
        else:
            log_event(uiq, 'USB',
                f"File descriptors: {diag['fd_in_use']} used, {diag['fd_remaining']} remaining")

    # Log USB device count
    if 'usb_device_count' in diag:
        log_event(uiq, 'USB', f"Total USB devices on system: {diag['usb_device_count']}")

    # Log recent USB errors
    if 'recent_usb_errors' in diag:
        log_event(uiq, 'USB', "Recent USB errors in dmesg (check `dmesg | grep -i usb`):", "warning")
        for err in diag['recent_usb_errors'][:3]:
            log_event(uiq, 'USB', f"  {err.strip()[:80]}", "warning")
    elif diag.get('dmesg_unavailable'):
        log_event(uiq, 'USB', "Note: dmesg unavailable (requires root). USB error diagnostics skipped.", "debug")


def get_device_usb_info(path: bytes) -> Dict[str, str]:
    """
    Get detailed USB info for a device path (Linux only).

    Args:
        path: HID device path (e.g., b'/dev/hidraw0')

    Returns:
        Dictionary with USB device details.
    """
    info: Dict[str, str] = {}
    if not IS_LINUX:
        return info

    try:
        path_str = path.decode() if isinstance(path, bytes) else path
        # Extract hidraw number
        if 'hidraw' in path_str:
            hidraw_num = path_str.split('hidraw')[-1]
            sysfs_path = f'/sys/class/hidraw/hidraw{hidraw_num}/device'

            # Try to get USB device path
            if os.path.islink(sysfs_path):
                real_path = os.path.realpath(sysfs_path)
                info['sysfs_path'] = real_path

                # Navigate up to find USB device info
                usb_path = real_path
                for _ in range(5):  # Walk up max 5 levels
                    usb_path = os.path.dirname(usb_path)
                    busnum = os.path.join(usb_path, 'busnum')
                    devnum = os.path.join(usb_path, 'devnum')
                    if os.path.exists(busnum) and os.path.exists(devnum):
                        with open(busnum) as f:
                            info['usb_bus'] = f.read().strip()
                        with open(devnum) as f:
                            info['usb_dev'] = f.read().strip()
                        info['usb_address'] = f"Bus {info['usb_bus']} Device {info['usb_dev']}"
                        break
    except Exception:
        pass

    return info


# ══════════════════════════════════════════════════════════════════════════════
# SETTINGS FILE HANDLING
# ══════════════════════════════════════════════════════════════════════════════

SETTINGS_PATH = os.path.join(SCRIPT_DIR, "settings.ini")

# Logger instance - lazily initialized to avoid module-level side effects
_logger: Optional[logging.Logger] = None
_logger_lock = threading.Lock()


def get_logger() -> logging.Logger:
    """
    Get or create the application logger (lazy initialization).
    Thread-safe singleton pattern.
    """
    global _logger
    if _logger is not None:
        return _logger

    with _logger_lock:
        # Double-check after acquiring lock
        if _logger is not None:
            return _logger

        logger = logging.getLogger("cockpitos_hid")
        logger.setLevel(logging.INFO)
        logger.propagate = False

        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        if not logger.handlers:
            file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

            if LOG_STDOUT:
                stream_handler = logging.StreamHandler(stream=sys.stdout)
                stream_handler.setFormatter(formatter)
                logger.addHandler(stream_handler)

        _logger = logger
        return _logger


# Per-device debug log rate limiting
_debug_log_times: Dict[str, float] = {}
_debug_log_lock = threading.Lock()

# UI queue full warning throttle
_ui_queue_full_last_warn: float = 0.0
_ui_queue_full_count: int = 0
UI_QUEUE_FULL_WARN_INTERVAL_S = 10.0  # Warn every 10 seconds max


def log_event(uiq: Optional[queue.Queue], name: str, msg: str, level: str = "info") -> None:
    """
    Log to file/console and enqueue for UI display.

    Args:
        uiq: UI queue for display (can be None to skip UI)
        name: Component/device name for log prefix
        msg: Log message
        level: Log level ('debug', 'info', 'warning', 'error', 'critical')

    Note:
        Debug-level messages are rate-limited per device to prevent log flooding
        when many devices are failing. See DEBUG_LOG_INTERVAL_S constant.
    """
    global _ui_queue_full_last_warn, _ui_queue_full_count

    # Rate-limit debug messages per device
    if level == "debug" and DEBUG_LOG_INTERVAL_S > 0:
        now = time.monotonic()
        with _debug_log_lock:
            last_time = _debug_log_times.get(name, 0)
            if now - last_time < DEBUG_LOG_INTERVAL_S:
                return  # Throttled
            _debug_log_times[name] = now

    logger = get_logger()
    log_fn = getattr(logger, level, logger.info)
    log_fn(f"[{name}] {msg}")
    if uiq is not None:
        try:
            uiq.put_nowait(('log', name, msg))
        except queue.Full:
            # UI queue full - log continues to file, UI display dropped
            # Periodically warn about suppressed UI logs
            _ui_queue_full_count += 1
            now = time.monotonic()
            if now - _ui_queue_full_last_warn >= UI_QUEUE_FULL_WARN_INTERVAL_S:
                logger.warning(f"UI queue full; {_ui_queue_full_count} log(s) not displayed in UI")
                _ui_queue_full_last_warn = now
                _ui_queue_full_count = 0

def read_settings() -> Tuple[int, Optional[int], str, int]:
    """
    Read VID, PID, DCS IP, and report ID from settings.ini.

    Returns:
        Tuple of (vid, pid, dcs_ip, report_id)
    """
    config = configparser.ConfigParser()

    if not os.path.isfile(SETTINGS_PATH):
        config['USB'] = {'VID': '0xCAFE', 'REPORT_ID': '0'}
        config['DCS'] = {'UDP_SOURCE_IP': '127.0.0.1'}
        config['MAIN'] = {'CONSOLE': '1'}
        with open(SETTINGS_PATH, 'w') as f:
            config.write(f)

    config.read(SETTINGS_PATH)

    try:
        vid = int(config.get('USB', 'VID', fallback='0xCAFE'), 0)
    except ValueError:
        vid = 0xCAFE

    try:
        pid_str = config.get('USB', 'PID', fallback='')
        pid = int(pid_str, 0) if pid_str else None
    except ValueError:
        pid = None

    dcs_ip = config.get('DCS', 'UDP_SOURCE_IP', fallback='127.0.0.1')

    # Report ID for HID feature reports (0 = no report ID prefix)
    try:
        report_id = int(config.get('USB', 'REPORT_ID', fallback='0'), 0)
    except ValueError:
        report_id = FEATURE_REPORT_ID

    return vid, pid, dcs_ip, report_id

def write_dcs_ip(ip: str):
    """Update DCS IP in settings.ini"""
    config = configparser.ConfigParser()
    config.read(SETTINGS_PATH)
    if 'DCS' not in config:
        config['DCS'] = {}
    config['DCS']['UDP_SOURCE_IP'] = ip
    with open(SETTINGS_PATH, 'w') as f:
        config.write(f)

def is_valid_ipv4(ip: str) -> bool:
    """
    Validate IPv4 address for use as DCS target.

    Args:
        ip: IP address string to validate

    Returns:
        True if valid unicast IPv4 address, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return (
            isinstance(ip_obj, ipaddress.IPv4Address)
            and not ip_obj.is_multicast
            and not ip_obj.is_unspecified
        )
    except ValueError:
        return False


# Settings cache - loaded lazily on first access
_settings_cache: Optional[Tuple[int, Optional[int], Optional[str], int]] = None
_settings_lock = threading.Lock()


def get_settings() -> Tuple[int, Optional[int], Optional[str], int]:
    """
    Get cached settings (lazy load on first access).
    Thread-safe singleton pattern.

    Returns:
        Tuple of (VID, PID, DCS_IP, REPORT_ID) where PID and DCS_IP may be None
    """
    global _settings_cache
    if _settings_cache is not None:
        return _settings_cache

    with _settings_lock:
        if _settings_cache is not None:
            return _settings_cache

        vid, pid, dcs_ip, report_id = read_settings()

        # Validate DCS IP
        if dcs_ip and not is_valid_ipv4(dcs_ip):
            get_logger().warning("Invalid DCS IP in settings.ini: %s (ignoring)", dcs_ip)
            dcs_ip = None

        _settings_cache = (vid, pid, dcs_ip, report_id)
        return _settings_cache


def get_report_id() -> int:
    """Get the configured HID feature report ID."""
    return get_settings()[3]


def reload_settings() -> Tuple[int, Optional[int], Optional[str], int]:
    """Force reload settings from disk. Returns new settings."""
    global _settings_cache
    with _settings_lock:
        _settings_cache = None
    return get_settings()

# ══════════════════════════════════════════════════════════════════════════════
# DEVICE STATE
# ══════════════════════════════════════════════════════════════════════════════

class DeviceState:
    """
    Thread-safe device state container.
    Uses __slots__ for memory efficiency at scale.
    """

    __slots__ = (
        'dev', 'info', 'name', 'serial', 'path',
        'state', 'status_text', 'lock',
        'last_activity', 'packets_tx', 'packets_rx',
        'reconnections', 'poller_id', 'tx_worker_id',
        'report_id'  # HID feature report ID (configurable per-device)
    )

    # State machine constants
    DISCONNECTED = 0
    HANDSHAKING  = 1
    READY        = 2
    ERROR        = 3

    # Status text mapping
    STATE_TEXT = {
        DISCONNECTED: "DISCONNECTED",
        HANDSHAKING:  "HANDSHAKING",
        READY:        "READY",
        ERROR:        "ERROR",
    }

    def __init__(self, dev, dev_info: dict, report_id: Optional[int] = None):
        self.dev = dev
        self.info = dev_info
        self.serial = dev_info.get('serial_number', '') or ''
        self.path = dev_info.get('path', b'')

        # Derive display name (prefer serial, fallback to product)
        product = dev_info.get('product_string', '') or ''
        self.name = self.serial if self.serial else (product or f"Device-{id(dev) & 0xFFFF:04X}")

        # HID feature report ID (use global setting if not specified)
        self.report_id = report_id if report_id is not None else get_report_id()

        # State
        self.state = self.HANDSHAKING
        self.status_text = "WAIT HANDSHAKE"
        self.lock = threading.Lock()
        self.last_activity = time.monotonic()

        # Stats
        self.packets_tx = 0
        self.packets_rx = 0
        self.reconnections = 0

        # Worker assignments (set by HandshakeManager after handshake)
        self.poller_id: int = -1      # RX poller assignment
        self.tx_worker_id: int = -1   # TX worker assignment (CRITICAL for single-writer)
    
    def is_ready(self) -> bool:
        return self.state == self.READY
    
    def set_state(self, new_state: int, status_text: Optional[str] = None):
        self.state = new_state
        self.status_text = status_text or self.STATE_TEXT.get(new_state, "UNKNOWN")
    
    def mark_activity(self):
        self.last_activity = time.monotonic()

# ══════════════════════════════════════════════════════════════════════════════
# DEVICE REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

class DeviceRegistry:
    """
    Central registry of all connected devices.
    Optimized for frequent reads (snapshot pattern), infrequent writes.
    """
    
    def __init__(self):
        self._devices: Dict[str, DeviceState] = {}
        self._lock = threading.RLock()
        self._snapshot: List[DeviceState] = []
        self._version = 0
    
    def add(self, device: DeviceState) -> bool:
        with self._lock:
            key = device.serial or str(device.path)
            if key in self._devices:
                return False
            self._devices[key] = device
            self._rebuild_snapshot()
            return True
    
    def remove(self, device: DeviceState) -> bool:
        with self._lock:
            key = device.serial or str(device.path)
            if key not in self._devices:
                return False
            del self._devices[key]
            self._rebuild_snapshot()
            return True
    
    def remove_by_key(self, key: str) -> Optional[DeviceState]:
        with self._lock:
            device = self._devices.pop(key, None)
            if device:
                self._rebuild_snapshot()
            return device
    
    def get(self, key: str) -> Optional[DeviceState]:
        with self._lock:
            return self._devices.get(key)
    
    def get_all(self) -> List[DeviceState]:
        """Returns snapshot copy - safe to iterate without lock, prevents mutation."""
        return list(self._snapshot)
    
    def get_ready(self) -> List[DeviceState]:
        """Returns only READY devices."""
        return [d for d in self._snapshot if d.is_ready()]
    
    def get_by_poller(self, poller_id: int) -> List[DeviceState]:
        """Returns devices assigned to a specific RX poller."""
        return [d for d in self._snapshot if d.poller_id == poller_id]
    
    def get_by_tx_worker(self, tx_worker_id: int) -> List[DeviceState]:
        """Returns READY devices assigned to a specific TX worker."""
        return [d for d in self._snapshot if d.is_ready() and d.tx_worker_id == tx_worker_id]
    
    def count(self) -> int:
        return len(self._snapshot)
    
    def count_ready(self) -> int:
        return sum(1 for d in self._snapshot if d.is_ready())
    
    def _rebuild_snapshot(self):
        # Sort by name for consistent display order
        self._snapshot = sorted(self._devices.values(), key=lambda d: d.name)
        self._version += 1

# ══════════════════════════════════════════════════════════════════════════════
# TX DISPATCHER (UDP → HID fan-out with device sharding)
# ══════════════════════════════════════════════════════════════════════════════

class TxDispatcher:
    """
    Receives UDP frames, slices into HID reports, dispatches to worker pool.
    
    CRITICAL DESIGN: Each device is assigned to exactly ONE TX worker.
    This ensures single-writer-per-device, avoiding HID handle race conditions.
    
    Architecture:
    - Each worker has its own queue
    - UDP frames are broadcast to ALL worker queues (same data)
    - Each worker only writes to devices assigned to it (sharding)
    - No two threads ever write to the same HID handle
    """
    
    def __init__(self, registry: DeviceRegistry, ui_queue: queue.Queue,
                 num_workers: int = TX_WORKERS):
        self.registry = registry
        self.uiq = ui_queue
        self.num_workers = num_workers
        
        # One queue per worker for job broadcast
        self.worker_queues: List[queue.Queue] = [
            queue.Queue(maxsize=TX_QUEUE_SIZE) for _ in range(num_workers)
        ]
        self.workers: List[threading.Thread] = []
        self._running = threading.Event()
        self._sequence = 0
        
        # Round-robin counter for TX worker assignment
        self._next_tx_worker = 0
        self._tx_worker_lock = threading.Lock()
        
        # Lock for atomic all-or-nothing broadcast (prevents TOCTOU race)
        self._broadcast_lock = threading.Lock()
        
        # Stats (atomic via GIL)
        self.jobs_dispatched = 0
        self.jobs_dropped = 0
        self.jobs_partial = 0  # Rare: partial enqueue due to queue race
        self.worker_busy = [False] * num_workers
        self._last_drop_log = 0.0
        
        # Start workers
        self._running.set()
        for i in range(num_workers):
            t = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
            t.name = f"TxWorker-{i}"
            self.workers.append(t)
            t.start()
    
    def get_next_tx_worker(self) -> int:
        """Assign next TX worker ID (round-robin). Called by HandshakeManager."""
        with self._tx_worker_lock:
            worker_id = self._next_tx_worker
            self._next_tx_worker = (self._next_tx_worker + 1) % self.num_workers
            return worker_id
    
    def dispatch(self, udp_data: bytes) -> None:
        """
        Called by UDP RX thread - slices data and broadcasts to all workers.

        BACKPRESSURE POLICY (configurable via TX_ALL_OR_NOTHING):
        - TX_ALL_OR_NOTHING=True: Drop entire frame if ANY queue is full (consistency)
        - TX_ALL_OR_NOTHING=False: Best-effort, partial dispatch allowed (faster)

        On Raspberry Pi, all-or-nothing is preferred to prevent desync across devices.

        Thread-safety: Exception-safe broadcast that never crashes UDP RX thread.
        """
        # Bound input size to prevent memory spikes (max ~64 reports per frame)
        MAX_UDP_FRAME_SIZE = 4096  # 64 reports × 64 bytes
        if len(udp_data) > MAX_UDP_FRAME_SIZE:
            self.jobs_dropped += 1
            now = time.monotonic()
            if now - self._last_drop_log >= TX_DROP_LOG_INTERVAL_S:
                log_event(self.uiq, "TX", f"Dropped UDP frame (size={len(udp_data)} bytes)", "warning")
                self._last_drop_log = now
            return

        # Pre-slice into HID reports (done once, shared immutable tuple)
        # Report ID is configurable via settings.ini [USB] REPORT_ID
        report_id = get_report_id()
        reports: List[bytes] = []
        offset = 0
        while offset < len(udp_data):
            chunk = udp_data[offset:offset + DEFAULT_REPORT_SIZE]
            # Report format: [report_id] + [data padded to 64 bytes]
            report = bytes([report_id]) + chunk.ljust(DEFAULT_REPORT_SIZE, b'\x00')
            reports.append(report)
            offset += DEFAULT_REPORT_SIZE

        job = (tuple(reports), time.monotonic(), self._sequence)
        self._sequence += 1

        with self._broadcast_lock:
            if TX_ALL_OR_NOTHING:
                # ALL-OR-NOTHING MODE: Check capacity first, then enqueue all
                # This prevents partial frame delivery which can cause state desync
                can_enqueue_all = all(not wq.full() for wq in self.worker_queues)

                if not can_enqueue_all:
                    self.jobs_dropped += 1
                    now = time.monotonic()
                    if now - self._last_drop_log >= TX_DROP_LOG_INTERVAL_S:
                        log_event(self.uiq, "TX",
                            "Dropped frame (all-or-nothing): at least one queue full", "warning")
                        self._last_drop_log = now
                    return

                # All queues have space - enqueue to all
                for wq in self.worker_queues:
                    try:
                        wq.put_nowait(job)
                    except queue.Full:
                        # Extremely rare race - queue filled between check and put
                        # Already committed to other queues, so this becomes partial
                        self.jobs_partial += 1
                        break

            else:
                # BEST-EFFORT MODE: Enqueue to as many workers as possible
                enqueued_count = 0
                for wq in self.worker_queues:
                    try:
                        wq.put_nowait(job)
                        enqueued_count += 1
                    except queue.Full:
                        now = time.monotonic()
                        if enqueued_count > 0:
                            self.jobs_partial += 1
                            if now - self._last_drop_log >= TX_DROP_LOG_INTERVAL_S:
                                log_event(self.uiq, "TX",
                                    "Partial dispatch: some worker queues full", "warning")
                                self._last_drop_log = now
                        else:
                            self.jobs_dropped += 1
                            if now - self._last_drop_log >= TX_DROP_LOG_INTERVAL_S:
                                log_event(self.uiq, "TX",
                                    "Dropped frame: all worker queues full", "warning")
                                self._last_drop_log = now
                        return

        self.jobs_dispatched += 1
    
    def _worker_loop(self, worker_id: int):
        """
        Worker thread - pulls jobs, writes ONLY to devices assigned to this worker.
        
        CRITICAL: Each device has a tx_worker_id assigned at handshake time.
        This worker ONLY writes to devices where tx_worker_id == worker_id.
        This guarantees single-writer-per-device (no HID handle races).
        
        Per-device lock is held during write burst for cross-platform safety.
        """
        my_queue = self.worker_queues[worker_id]
        
        while self._running.is_set():
            try:
                job = my_queue.get(timeout=0.05)
            except queue.Empty:
                self.worker_busy[worker_id] = False
                continue
            
            self.worker_busy[worker_id] = True
            reports, timestamp, seq = job
            
            # CRITICAL: Only write to MY assigned devices (sharding)
            devices = self.registry.get_by_tx_worker(worker_id)
            for dev_state in devices:
                try:
                    # Lock protects against concurrent HID access from other subsystems
                    with dev_state.lock:
                        for report in reports:
                            dev_state.dev.write(report)
                    dev_state.packets_tx += len(reports)
                    dev_state.mark_activity()
                except Exception as e:
                    dev_state.set_state(DeviceState.ERROR, "TX ERROR")
                    log_event(self.uiq, dev_state.name, f"TX error: {e}", "error")
            
            self.worker_busy[worker_id] = False
    
    def stop(self) -> None:
        """Stop all TX workers with proper timeout handling."""
        self._running.clear()
        for t in self.workers:
            t.join(timeout=THREAD_JOIN_TIMEOUT)
            if t.is_alive() and THREAD_JOIN_WARN:
                log_event(None, "TxDispatcher", f"Worker {t.name} did not stop within timeout", "warning")

    def get_queue_depth(self) -> int:
        """Returns max queue depth across all workers."""
        return max(wq.qsize() for wq in self.worker_queues) if self.worker_queues else 0

# ══════════════════════════════════════════════════════════════════════════════
# RX POLLER (non-blocking HID reads)
# ══════════════════════════════════════════════════════════════════════════════

class RxPoller:
    """
    Polls assigned devices for incoming data using non-blocking reads.
    One poller handles a subset of devices (round-robin assignment).

    The callback is set via set_command_callback() to avoid initialization
    order issues (callback target may not exist at construction time).
    """

    def __init__(self, poller_id: int, registry: DeviceRegistry,
                 ui_queue: queue.Queue):
        self.poller_id = poller_id
        self.registry = registry
        self.uiq = ui_queue

        # Callback is set after construction via set_command_callback()
        # This avoids the lambda placeholder pattern and initialization gaps
        self._on_command: Optional[Callable[[str], None]] = None
        self._callback_lock = threading.Lock()

        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.is_busy = False

    def set_command_callback(self, callback: Callable[[str], None]) -> None:
        """
        Set the callback for sending commands to DCS.
        Thread-safe - can be called before or after start().
        """
        with self._callback_lock:
            self._on_command = callback

    def _send_command(self, cmd: str) -> bool:
        """
        Send command via callback if available.
        Returns True if sent, False if no callback configured.
        """
        with self._callback_lock:
            if self._on_command is not None:
                self._on_command(cmd)
                return True
        return False

    def start(self) -> None:
        self._running.set()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.name = f"RxPoller-{self.poller_id}"
        self._thread.start()

    def stop(self) -> None:
        """Stop the poller with proper timeout handling."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=THREAD_JOIN_TIMEOUT)
            if self._thread.is_alive() and THREAD_JOIN_WARN:
                log_event(None, "RxPoller", f"Poller {self.poller_id} did not stop within timeout", "warning")
    
    def _poll_loop(self):
        """
        Main polling loop - implements trigger-based drain pattern.
        
        CRITICAL: The firmware sends an Input Report as a TRIGGER to signal
        that there's data in the Feature Report buffer to drain. We must
        only call get_feature_report() AFTER receiving this trigger.
        
        Per-device lock protects HID operations for cross-platform safety.
        Network/UI operations happen OUTSIDE the lock to prevent contention.
        """
        while self._running.is_set():
            devices = self.registry.get_by_poller(self.poller_id)
            devices = [d for d in devices if d.is_ready()]
            
            if not devices:
                self.is_busy = False
                time.sleep(0.01)
                continue
            
            self.is_busy = True
            
            for dev_state in devices:
                if dev_state.state != DeviceState.READY:
                    continue
                
                # Collect messages while holding lock, send after releasing
                messages_to_send = []
                
                try:
                    # Lock protects HID operations ONLY
                    with dev_state.lock:
                        # Non-blocking read - check for TRIGGER (Input Report)
                        data = dev_state.dev.read(DEFAULT_REPORT_SIZE, timeout_ms=0)
                        
                        # CRITICAL: Only drain Feature Reports if we received a trigger!
                        if data:
                            messages_to_send = self._drain_feature_reports_locked(dev_state)
                    
                    # OUTSIDE LOCK: Send to network and UI (no contention risk)
                    for msg in messages_to_send:
                        if self._send_command(msg + "\n"):
                            log_event(self.uiq, dev_state.name, f"IN: {msg}")
                        else:
                            # Callback not yet configured - log but don't lose the message
                            log_event(self.uiq, dev_state.name, f"IN (no callback): {msg}", "warning")
                    
                except Exception as e:
                    dev_state.set_state(DeviceState.ERROR, "RX ERROR")
                    log_event(self.uiq, dev_state.name, f"RX error: {e}", "error")
            
            self.is_busy = False
            time.sleep(RX_POLL_INTERVAL_MS / 1000.0)
    
    def _drain_feature_reports_locked(self, dev_state: DeviceState) -> List[str]:
        """
        Read ALL pending Feature Reports. MUST be called with dev_state.lock held.
        Returns list of command strings to send (processed outside lock).

        Note: Logging is done at debug level inside the loop since HID errors
        during drain are expected (indicates buffer is empty).
        """
        MAX_DRAIN_ITERATIONS = 64
        drained_count = 0
        messages: List[str] = []

        for iteration in range(MAX_DRAIN_ITERATIONS):
            try:
                resp = dev_state.dev.get_feature_report(
                    dev_state.report_id,
                    DEFAULT_REPORT_SIZE + 1
                )
                payload = extract_feature_payload(resp, report_id=dev_state.report_id)

                if not any(payload):
                    break

                msg = payload.rstrip(b'\x00').decode(errors='replace').strip()

                if not msg:
                    continue

                if msg == HANDSHAKE_REQ.decode():
                    continue

                # Collect message (will be sent outside lock)
                messages.append(msg)
                dev_state.packets_rx += 1
                dev_state.mark_activity()
                drained_count += 1

            except Exception as e:
                # Expected when buffer is empty or device disconnects during drain
                # Log at debug level to avoid noise during normal operation
                if drained_count == 0 and iteration == 0:
                    # Only log if we didn't get any messages - might indicate issue
                    log_event(self.uiq, dev_state.name, f"Drain interrupted: {e}", "debug")
                break

        if drained_count >= MAX_DRAIN_ITERATIONS:
            log_event(
                self.uiq,
                dev_state.name,
                f"WARNING: Drain hit safety cap ({MAX_DRAIN_ITERATIONS})",
                "warning",
            )

        return messages

# ══════════════════════════════════════════════════════════════════════════════
# HANDSHAKE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class HandshakeManager:
    """
    Handles device handshakes with parallel workers and retry logic.

    Features:
    - Multiple parallel handshake workers (configurable via HANDSHAKE_WORKERS)
    - Staggered initialization on resource-constrained platforms (Pi)
    - Automatic retry with backoff for failed handshakes
    - Queue monitoring with backlog warnings
    """

    def __init__(self, registry: DeviceRegistry, ui_queue: queue.Queue,
                 get_next_poller: Callable[[], int],
                 get_next_tx_worker: Callable[[], int],
                 num_workers: int = HANDSHAKE_WORKERS):
        self.registry = registry
        self.uiq = ui_queue
        self.get_next_poller = get_next_poller
        self.get_next_tx_worker = get_next_tx_worker
        self.num_workers = num_workers

        # Queues: pending for new devices, retry for failed devices
        self.pending: queue.Queue = queue.Queue()
        self.retry_queue: queue.Queue = queue.Queue()

        # Track retry attempts: device_key -> (next_retry_time, attempt_count)
        self._retry_tracker: Dict[str, Tuple[float, int]] = {}
        self._retry_lock = threading.Lock()

        # Stagger control for Pi
        self._last_handshake_time = 0.0
        self._stagger_lock = threading.Lock()

        self._running = threading.Event()
        self._workers: List[threading.Thread] = []
        self._retry_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running.set()

        # Start handshake workers
        for i in range(self.num_workers):
            t = threading.Thread(target=self._handshake_worker, args=(i,), daemon=True)
            t.name = f"Handshake-{i}"
            self._workers.append(t)
            t.start()

        # Start retry scheduler thread
        if HANDSHAKE_RETRY_ENABLED:
            self._retry_thread = threading.Thread(target=self._retry_scheduler, daemon=True)
            self._retry_thread.name = "HandshakeRetry"
            self._retry_thread.start()

        log_event(self.uiq, "Handshake", f"Started {self.num_workers} handshake workers")

    def stop(self) -> None:
        """Stop all handshake workers with proper timeout handling."""
        self._running.clear()

        for t in self._workers:
            t.join(timeout=THREAD_JOIN_TIMEOUT)
            if t.is_alive() and THREAD_JOIN_WARN:
                log_event(None, "HandshakeMgr", f"Worker {t.name} did not stop within timeout", "warning")

        if self._retry_thread:
            self._retry_thread.join(timeout=THREAD_JOIN_TIMEOUT)
            if self._retry_thread.is_alive() and THREAD_JOIN_WARN:
                log_event(None, "HandshakeMgr", "Retry scheduler did not stop within timeout", "warning")

    def enqueue(self, dev_state: DeviceState) -> None:
        """Add a device to the handshake queue."""
        self.pending.put(dev_state)
        qsize = self.pending.qsize()
        if qsize > HANDSHAKE_QUEUE_WARN:
            log_event(
                self.uiq,
                "Handshake",
                f"High handshake backlog ({qsize} pending). Consider parallel handshaking.",
                "warning",
            )

    def _wait_for_stagger(self) -> None:
        """Wait if needed to stagger device initialization (prevents USB bus surge)."""
        if HANDSHAKE_STAGGER_MS <= 0:
            return

        with self._stagger_lock:
            now = time.monotonic()
            elapsed = (now - self._last_handshake_time) * 1000  # ms
            if elapsed < HANDSHAKE_STAGGER_MS:
                wait_time = (HANDSHAKE_STAGGER_MS - elapsed) / 1000.0
                time.sleep(wait_time)
            self._last_handshake_time = time.monotonic()

    def _handshake_worker(self, worker_id: int) -> None:
        """Worker thread that processes handshakes in parallel."""
        while self._running.is_set():
            try:
                dev_state = self.pending.get(timeout=0.1)
            except queue.Empty:
                continue

            # Stagger on Pi to avoid USB bus saturation
            self._wait_for_stagger()

            self._process_handshake(dev_state, is_retry=False)

    def _retry_scheduler(self) -> None:
        """Background thread that re-enqueues failed devices for retry."""
        while self._running.is_set():
            time.sleep(1.0)  # Check every second

            if not HANDSHAKE_RETRY_ENABLED:
                continue

            now = time.monotonic()
            devices_to_retry: List[DeviceState] = []

            # Check retry queue for devices ready to retry
            while True:
                try:
                    dev_state = self.retry_queue.get_nowait()

                    key = dev_state.serial or str(dev_state.path)
                    with self._retry_lock:
                        if key in self._retry_tracker:
                            next_retry, attempts = self._retry_tracker[key]
                            if now >= next_retry:
                                devices_to_retry.append(dev_state)
                            else:
                                # Not ready yet, put back
                                self.retry_queue.put(dev_state)
                        else:
                            # No retry info, skip
                            pass
                except queue.Empty:
                    break

            # Re-enqueue devices ready for retry
            for dev_state in devices_to_retry:
                key = dev_state.serial or str(dev_state.path)
                with self._retry_lock:
                    _, attempts = self._retry_tracker.get(key, (0, 0))
                log_event(self.uiq, dev_state.name,
                    f"Retrying handshake (attempt {attempts + 1}/{HANDSHAKE_RETRY_MAX + 1})")
                self.pending.put(dev_state)

    def _schedule_retry(self, dev_state: DeviceState) -> bool:
        """
        Schedule a device for retry after handshake failure.
        Returns True if retry scheduled, False if max retries exceeded.
        """
        if not HANDSHAKE_RETRY_ENABLED:
            return False

        key = dev_state.serial or str(dev_state.path)
        now = time.monotonic()

        with self._retry_lock:
            if key in self._retry_tracker:
                _, attempts = self._retry_tracker[key]
                attempts += 1
            else:
                attempts = 1

            if attempts > HANDSHAKE_RETRY_MAX:
                # Max retries exceeded
                if key in self._retry_tracker:
                    del self._retry_tracker[key]
                return False

            # Schedule retry
            next_retry = now + HANDSHAKE_RETRY_DELAY
            self._retry_tracker[key] = (next_retry, attempts)

        self.retry_queue.put(dev_state)
        return True

    def clear_retry_state(self, dev_state: DeviceState) -> None:
        """
        Clear retry tracking for a device.

        Call this on:
        - Successful handshake completion
        - Device disconnection (prevents stale retries)
        """
        key = dev_state.serial or str(dev_state.path)
        with self._retry_lock:
            if key in self._retry_tracker:
                del self._retry_tracker[key]

        # Also remove from retry queue if present (drain matching entries)
        # This is O(n) but disconnects are rare, so acceptable
        temp_items = []
        try:
            while True:
                item = self.retry_queue.get_nowait()
                item_key = item.serial or str(item.path)
                if item_key != key:
                    temp_items.append(item)
        except queue.Empty:
            pass

        # Put back non-matching items
        for item in temp_items:
            self.retry_queue.put(item)

    def _process_handshake(self, dev_state: DeviceState, is_retry: bool) -> None:
        """Process a single device handshake."""
        log_event(self.uiq, dev_state.name,
            "Starting handshake..." + (" (retry)" if is_retry else ""))
        self.uiq.put(('status', dev_state.name, None))
        handshake_start = time.monotonic()

        if self._do_handshake(dev_state):
            # Clear any stale data in the Feature Report buffer
            if not self._clear_backlog(dev_state):
                dev_state.set_state(DeviceState.ERROR, "BACKLOG CLEAR FAILED")
                log_event(self.uiq, dev_state.name, "Failed to clear backlog", "error")
                self.uiq.put(('status', dev_state.name, None))
                self._schedule_retry(dev_state)
                return

            # Assign to workers (CRITICAL: must happen before READY state)
            dev_state.poller_id = self.get_next_poller()
            dev_state.tx_worker_id = self.get_next_tx_worker()

            # Enable non-blocking mode BEFORE setting READY
            try:
                dev_state.dev.set_nonblocking(1)
            except Exception as e:
                log_event(self.uiq, dev_state.name, f"Note: set_nonblocking failed ({e})", "warning")

            dev_state.set_state(DeviceState.READY, "READY")
            self.clear_retry_state(dev_state)

            duration = time.monotonic() - handshake_start
            log_event(
                self.uiq,
                dev_state.name,
                f"Handshake complete, ready ({duration:.2f}s)",
            )
            self.uiq.put(('status', dev_state.name, None))
        else:
            duration = time.monotonic() - handshake_start

            # Try to schedule retry
            if self._schedule_retry(dev_state):
                dev_state.set_state(DeviceState.ERROR, "HANDSHAKE FAILED (WILL RETRY)")
                log_event(self.uiq, dev_state.name,
                    f"Handshake failed ({duration:.2f}s), will retry in {HANDSHAKE_RETRY_DELAY}s", "warning")
            else:
                dev_state.set_state(DeviceState.ERROR, "HANDSHAKE FAILED")
                log_event(self.uiq, dev_state.name,
                    f"Handshake failed ({duration:.2f}s), max retries exceeded", "error")

            self.uiq.put(('status', dev_state.name, None))
    
    def _clear_backlog(self, dev_state: DeviceState) -> bool:
        """
        Clear any stale Feature Report data after handshake.
        Lock protects HID operations for cross-platform safety.

        Returns:
            True if backlog cleared successfully, False on error or timeout.
        """
        dev = dev_state.dev
        max_attempts = 100

        for attempt in range(max_attempts):
            if not self._running.is_set():
                return False

            try:
                with dev_state.lock:
                    resp = dev.get_feature_report(dev_state.report_id, DEFAULT_REPORT_SIZE + 1)
                    payload = extract_feature_payload(resp, report_id=dev_state.report_id)

                    # Empty buffer = all zeros
                    if not any(payload):
                        return True

            except Exception as e:
                log_event(self.uiq, dev_state.name, f"Backlog clear error: {e}", "debug")
                return False

        # Timeout - buffer never cleared
        log_event(self.uiq, dev_state.name, f"Backlog clear timeout after {max_attempts} attempts", "warning")
        return False

    def _do_handshake(self, dev_state: DeviceState) -> bool:
        """
        Perform FIFO handshake sequence. Lock protects HID operations.

        Returns:
            True if handshake completed successfully, False on timeout or error.
        """
        dev = dev_state.dev
        report_id = dev_state.report_id
        payload = HANDSHAKE_REQ.ljust(DEFAULT_REPORT_SIZE, b'\x00')
        last_error: Optional[Exception] = None

        for attempt in range(50):  # Max ~10 seconds
            if not self._running.is_set():
                return False

            try:
                with dev_state.lock:
                    # Check if device already echoed handshake
                    resp = dev.get_feature_report(report_id, DEFAULT_REPORT_SIZE + 1)
                    data = extract_feature_payload(resp, report_id=report_id)
                    if data.rstrip(b'\x00') == HANDSHAKE_REQ:
                        return True

                    # Send handshake request
                    dev.send_feature_report(bytes([report_id]) + payload)

                    # Check response
                    resp = dev.get_feature_report(report_id, DEFAULT_REPORT_SIZE + 1)
                    data = extract_feature_payload(resp, report_id=report_id)
                    if data.rstrip(b'\x00') == HANDSHAKE_REQ:
                        return True

            except Exception as e:
                last_error = e
                # Log at debug level - transient errors are expected during handshake
                log_event(self.uiq, dev_state.name, f"Handshake attempt {attempt+1} error: {e}", "debug")

            time.sleep(0.2)

        # Log final error if we exhausted attempts
        if last_error:
            log_event(self.uiq, dev_state.name, f"Handshake failed after 50 attempts, last error: {last_error}", "error")
        return False

# ══════════════════════════════════════════════════════════════════════════════
# HOTPLUG MONITOR
# ══════════════════════════════════════════════════════════════════════════════

class HotplugMonitor:
    """
    Monitors for USB device connect/disconnect events.

    Features:
    - Periodic scanning for device changes
    - Exponential backoff retry for device open failures
    - Reconnection tracking and logging
    """

    def __init__(self, vid: int, pid: Optional[int],
                 registry: DeviceRegistry,
                 handshake_mgr: HandshakeManager,
                 ui_queue: queue.Queue,
                 reconnection_tracker: Dict[str, int]):
        self.vid = vid
        self.pid = pid
        self.registry = registry
        self.handshake_mgr = handshake_mgr
        self.uiq = ui_queue
        self.reconnection_tracker = reconnection_tracker

        # Track devices that failed to open (for retry backoff)
        self._failed_devices: Dict[str, Tuple[float, int]] = {}  # key -> (next_retry_time, attempt_count)

        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running.set()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.name = "HotplugMon"
        self._thread.start()

    def stop(self) -> None:
        """Stop the hotplug monitor with proper timeout handling."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=THREAD_JOIN_TIMEOUT)
            if self._thread.is_alive() and THREAD_JOIN_WARN:
                log_event(None, "HotplugMon", "Hotplug monitor did not stop within timeout", "warning")
    
    def _monitor_loop(self):
        while self._running.is_set():
            try:
                self._scan_devices()
            except Exception as e:
                log_event(self.uiq, 'Hotplug', f"Scan error: {e}", "error")
            
            time.sleep(1.0)
    
    def _scan_devices(self):
        # Build map of currently connected USB devices
        usb_devices: Dict[str, dict] = {}
        for d in hid.enumerate():
            if d['vendor_id'] != self.vid:
                continue
            if self.pid is not None and d['product_id'] != self.pid:
                continue
            
            key = d.get('serial_number', '') or str(d.get('path', b''))
            if key:
                usb_devices[key] = d
        
        # Detect disconnections
        for dev_state in self.registry.get_all():
            key = dev_state.serial or str(dev_state.path)
            if key not in usb_devices:
                self._handle_disconnect(dev_state)
        
        # Detect new connections
        for key, info in usb_devices.items():
            existing = self.registry.get(key)
            if existing is None:
                self._handle_connect(info)
    
    def _handle_connect(self, info: dict) -> None:
        """
        Handle a newly detected device connection.

        Implements exponential backoff retry for transient USB errors.
        """
        key = info.get('serial_number', '') or str(info.get('path', b''))

        if self.registry.count() >= MAX_DEVICES:
            log_event(self.uiq, 'Hotplug', f"Device limit reached ({MAX_DEVICES}); ignoring {key}", "warning")
            return

        # Check if we're in backoff period for this device
        now = time.monotonic()
        if key in self._failed_devices:
            next_retry, attempt_count = self._failed_devices[key]
            if now < next_retry:
                # Still in backoff period - skip this attempt
                return

        # Attempt to open device
        dev: Optional[hid.device] = None
        try:
            dev = hid.device()
            dev.open_path(info['path'])
            # Success - clear any failure tracking
            if key in self._failed_devices:
                del self._failed_devices[key]
        except Exception as e:
            # Track failure and schedule retry with exponential backoff
            if key in self._failed_devices:
                _, attempt_count = self._failed_devices[key]
                attempt_count += 1
            else:
                attempt_count = 1

            if attempt_count <= DEVICE_OPEN_MAX_RETRIES:
                # Calculate exponential backoff delay
                delay = min(
                    DEVICE_OPEN_BASE_DELAY * (2 ** (attempt_count - 1)),
                    DEVICE_OPEN_MAX_DELAY
                )
                self._failed_devices[key] = (now + delay, attempt_count)
                log_event(
                    self.uiq, 'Hotplug',
                    f"Failed to open device (attempt {attempt_count}/{DEVICE_OPEN_MAX_RETRIES}): {e}. "
                    f"Retrying in {delay:.1f}s",
                    "warning"
                )
            else:
                # Max retries exceeded - log error and stop trying
                log_event(
                    self.uiq, 'Hotplug',
                    f"Failed to open device after {DEVICE_OPEN_MAX_RETRIES} attempts: {e}. Giving up.",
                    "error"
                )
                # Keep in failed_devices with very long delay to prevent spam
                self._failed_devices[key] = (now + 60.0, attempt_count)
            return

        dev_state = DeviceState(dev, info)
        dev_state.reconnections = self.reconnection_tracker.get(key, 0)
        self.reconnection_tracker[key] = dev_state.reconnections + 1

        if self.registry.add(dev_state):
            # First connect shows "Connected", subsequent show reconnect count
            if dev_state.reconnections == 0:
                log_event(self.uiq, dev_state.name, "Connected")
            else:
                log_event(self.uiq, dev_state.name, f"Reconnected (#{dev_state.reconnections})")
            self.uiq.put(('status', dev_state.name, None))
            self.handshake_mgr.enqueue(dev_state)
    
    def _handle_disconnect(self, dev_state: DeviceState) -> None:
        """Handle device disconnection - clean up resources and notify."""
        self.registry.remove(dev_state)
        dev_state.set_state(DeviceState.DISCONNECTED)

        # Clean up HID handle
        try:
            dev_state.dev.close()
        except Exception as e:
            # Log at debug - device may already be gone
            log_event(self.uiq, dev_state.name, f"Close during disconnect: {e}", "debug")

        # Clear from failed devices tracker if present
        key = dev_state.serial or str(dev_state.path)
        if key in self._failed_devices:
            del self._failed_devices[key]

        # Clear from handshake retry queue to prevent stale retries
        self.handshake_mgr.clear_retry_state(dev_state)

        log_event(self.uiq, dev_state.name, "Disconnected")
        self.uiq.put(('status', dev_state.name, None))

# ══════════════════════════════════════════════════════════════════════════════
# UDP NETWORK LAYER
# ══════════════════════════════════════════════════════════════════════════════

class UdpNetwork:
    """
    Handles UDP multicast RX (from DCS) and unicast TX (to DCS).

    Features:
    - Thread-safe statistics collection
    - Automatic DCS IP discovery from first packet
    - Multicast group membership management
    """

    def __init__(self, tx_dispatcher: TxDispatcher, ui_queue: queue.Queue,
                 initial_dcs_ip: Optional[str] = None):
        self.tx_dispatcher = tx_dispatcher
        self.uiq = ui_queue

        self.reply_addr: Optional[str] = initial_dcs_ip
        self.rx_sock: Optional[socket.socket] = None
        self.tx_sock: Optional[socket.socket] = None

        self._running = threading.Event()
        self._rx_thread: Optional[threading.Thread] = None
        self._ip_committed = False

        # Thread-safe stats using a lock
        self._stats_lock = threading.Lock()
        self._frames_total = 0
        self._frames_window = 0
        self._bytes_window = 0
        self._window_start = time.monotonic()

    def start(self) -> None:
        self._running.set()

        # TX socket
        self.tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # RX thread
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.name = "UdpRx"
        self._rx_thread.start()

    def stop(self) -> None:
        """Stop the UDP network layer with proper cleanup."""
        self._running.clear()

        # Explicitly leave multicast group (platform-dependent but proper cleanup)
        if self.rx_sock:
            try:
                mreq = struct.pack("=4sl", socket.inet_aton(DEFAULT_MULTICAST_IP), socket.INADDR_ANY)
                self.rx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except Exception as e:
                log_event(self.uiq, 'UDP', f"Multicast leave: {e}", "debug")

        # Close sockets
        for sock in (self.rx_sock, self.tx_sock):
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    log_event(None, 'UDP', f"Socket close: {e}", "debug")

        # Join RX thread for deterministic shutdown
        if self._rx_thread:
            self._rx_thread.join(timeout=THREAD_JOIN_TIMEOUT)
            if self._rx_thread.is_alive() and THREAD_JOIN_WARN:
                log_event(None, "UdpNetwork", "UDP RX thread did not stop within timeout", "warning")
    
    def send_command(self, cmd: str) -> None:
        """Send ASCII command to DCS-BIOS."""
        if self.tx_sock and self.reply_addr:
            try:
                self.tx_sock.sendto(cmd.encode(), (self.reply_addr, DEFAULT_DCS_TX_PORT))
            except Exception as e:
                log_event(self.uiq, 'UDP', f"TX error: {e}", "error")

    def _update_stats(self, data_len: int) -> None:
        """Thread-safe stats update."""
        with self._stats_lock:
            self._frames_total += 1
            self._frames_window += 1
            self._bytes_window += data_len

    def _rx_loop(self) -> None:
        """Receive UDP multicast from DCS-BIOS."""
        try:
            self.rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                self.rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RX_BUFFER_SIZE)
            except Exception as e:
                log_event(self.uiq, 'UDP', f"Could not set receive buffer size: {e}", "debug")

            self.rx_sock.bind(('', DEFAULT_UDP_PORT))

            # CRITICAL: Set timeout for deterministic shutdown
            self.rx_sock.settimeout(0.5)

            mreq = struct.pack("=4sl", socket.inet_aton(DEFAULT_MULTICAST_IP), socket.INADDR_ANY)
            self.rx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            log_event(self.uiq, 'UDP', f"Listening on {DEFAULT_MULTICAST_IP}:{DEFAULT_UDP_PORT}")

            while self._running.is_set():
                try:
                    data, addr = self.rx_sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._running.is_set():
                        log_event(self.uiq, 'UDP', f"Socket error: {e}", "error")
                    break

                # Learn DCS address from first packet
                if not self._ip_committed and addr and is_valid_ipv4(addr[0]):
                    if self.reply_addr != addr[0]:
                        self.reply_addr = addr[0]
                        write_dcs_ip(addr[0])
                        self._ip_committed = True
                        self.uiq.put(('data_source', None, addr[0]))
                        log_event(self.uiq, 'UDP', f"DCS detected at {addr[0]}")

                # Thread-safe stats update
                self._update_stats(len(data))

                # Dispatch to HID devices
                self.tx_dispatcher.dispatch(data)

        except Exception as e:
            log_event(self.uiq, 'UDP', f"RX fatal error: {e}", "error")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current stats and reset window counters.
        Thread-safe - can be called from UI thread while RX thread updates stats.
        """
        with self._stats_lock:
            now = time.monotonic()
            duration = max(now - self._window_start, 0.001)

            hz = self._frames_window / duration
            kbps = (self._bytes_window / 1024.0) / duration
            avg_size = self._bytes_window / max(self._frames_window, 1)

            stats = {
                'frames': self._frames_total,
                'hz': f"{hz:.1f}",
                'kbps': f"{kbps:.1f}",
                'avg_size': f"{avg_size:.1f}",
            }

            # Reset window (atomic with read)
            self._frames_window = 0
            self._bytes_window = 0
            self._window_start = now

            return stats

# ══════════════════════════════════════════════════════════════════════════════
# CURSES CONSOLE UI
# ══════════════════════════════════════════════════════════════════════════════

class ConsoleUI:
    """
    Professional curses-based console interface.
    Matches original CockpitOS HID Manager aesthetic.

    Features:
    - Color-coded device status display
    - Rolling log display with bounded memory (using deque)
    - Live statistics from UDP network layer
    """

    # Color pair IDs
    COLOR_RED    = 1
    COLOR_GREEN  = 2
    COLOR_YELLOW = 3
    COLOR_CYAN   = 4
    COLOR_DIM    = 5

    def __init__(self, registry: DeviceRegistry, udp_network: 'UdpNetwork',
                 tx_dispatcher: TxDispatcher, rx_pollers: List[RxPoller],
                 ui_queue: Optional[queue.Queue] = None,
                 initial_dcs_ip: Optional[str] = None):
        self.registry = registry
        self.udp = udp_network
        self.tx_dispatcher = tx_dispatcher
        self.rx_pollers = rx_pollers

        # Use provided queue or create new one
        self.uiq: queue.Queue = ui_queue if ui_queue is not None else queue.Queue()
        self._running = threading.Event()

        # UI state - use deque for O(1) bounded append (no list slicing needed)
        self._log: Deque[str] = deque(maxlen=LOG_HISTORY_SIZE)
        self._stats = {
            'frames': '0',
            'hz': '0.0',
            'kbps': '0.0',
            'avg_size': '0.0',
            'src': initial_dcs_ip or '(waiting...)',
        }
    
    def post(self, event):
        """Thread-safe event posting."""
        self.uiq.put(event)
    
    def run(self):
        """Main entry point - runs curses wrapper."""
        curses.wrapper(self._main_loop)
    
    def stop(self):
        self._running.clear()
    
    def _main_loop(self, stdscr):
        """Main curses loop."""
        # Initialize curses
        curses.curs_set(0)  # Hide cursor
        curses.use_default_colors()
        
        # Initialize color pairs
        curses.init_pair(self.COLOR_RED, curses.COLOR_RED, -1)
        curses.init_pair(self.COLOR_GREEN, curses.COLOR_GREEN, -1)
        curses.init_pair(self.COLOR_YELLOW, curses.COLOR_YELLOW, -1)
        curses.init_pair(self.COLOR_CYAN, curses.COLOR_CYAN, -1)
        curses.init_pair(self.COLOR_DIM, curses.COLOR_WHITE, -1)
        
        stdscr.timeout(UI_REFRESH_MS)
        self._running.set()
        
        last_stats_update = 0
        
        while self._running.is_set():
            # Process events
            self._consume_events()
            
            # Update stats periodically
            now = time.monotonic()
            if now - last_stats_update >= 1.0:
                stats = self.udp.get_stats()
                self._stats['frames'] = str(stats['frames'])
                self._stats['hz'] = stats['hz']
                self._stats['kbps'] = stats['kbps']
                self._stats['avg_size'] = stats['avg_size']
                last_stats_update = now
            
            # Render
            self._paint(stdscr)
            
            # Handle input (drain buffer, but only 'q' quits)
            ch = stdscr.getch()
            if ch == ord('q') or ch == 27:  # 'q' or ESC
                self._running.clear()
            
            time.sleep(0.01)
    
    def _consume_events(self) -> None:
        """Process all pending UI events."""
        while True:
            try:
                event = self.uiq.get_nowait()
            except queue.Empty:
                break

            typ, *rest = event

            if typ == 'data_source':
                # Event format: ('data_source', None, ip_address)
                self._stats['src'] = rest[-1]  # Explicitly use last element

            elif typ == 'log':
                dev_name, msg = rest
                timestamp = datetime.now().strftime("%H:%M:%S")
                line = f"[{timestamp}] [{dev_name}] {msg}"
                # deque with maxlen auto-discards old entries - no manual slicing needed
                self._log.append(line)

            elif typ == 'status':
                # Status updates are pulled directly from registry
                pass
    
    def _paint(self, stdscr):
        """Render the entire screen."""
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        
        y = 0
        
        # === HEADER: Stats bar ===
        header = (
            f"Frames: {self._stats['frames']}   "
            f"Hz: {self._stats['hz']}   "
            f"kB/s: {self._stats['kbps']}   "
            f"Avg UDP Frame size (Bytes): {self._stats['avg_size']}   "
            f"Data Source: {self._stats['src']}"
        )
        self._addstr(stdscr, y, 0, header, w, curses.A_BOLD)
        y += 2
        
        # === DEVICE TABLE ===
        # Header row
        col_device = 38
        col_status = 16
        col_reconn = 14
        
        table_header = f"{'Device':<{col_device}} {'Status':<{col_status}} {'Reconnections':<{col_reconn}}"
        self._addstr(stdscr, y, 0, table_header, w, curses.A_NORMAL)
        y += 1
        
        # Device rows
        devices = self.registry.get_all()
        for dev in devices:
            if y >= h - 2:  # Leave room for log and status bar
                break
            
            # Determine color based on status
            status = dev.status_text
            attr = curses.A_NORMAL
            status_lower = status.lower()
            
            if 'ready' in status_lower:
                attr = curses.color_pair(self.COLOR_GREEN)
            elif 'handshak' in status_lower or 'wait' in status_lower:
                attr = curses.color_pair(self.COLOR_YELLOW)
            elif 'error' in status_lower or 'disconnect' in status_lower or 'off' in status_lower:
                attr = curses.color_pair(self.COLOR_RED)
            
            # Truncate device name if needed
            name = dev.name[:col_device-1] if len(dev.name) >= col_device else dev.name
            
            row = f"{name:<{col_device}} {status:<{col_status}} {dev.reconnections:<{col_reconn}}"
            self._addstr(stdscr, y, 0, row, w, attr)
            y += 1
        
        # === EVENT LOG ===
        y += 1  # Blank line separator

        # Calculate available space for log
        log_start = y
        log_end = h - 1  # Last line is status bar
        log_lines = max(0, log_end - log_start)

        # Show most recent log entries that fit
        # deque doesn't support slicing, so we iterate from the end
        if log_lines > 0 and self._log:
            # Get last N entries efficiently from deque
            log_len = len(self._log)
            start_idx = max(0, log_len - log_lines)
            for i, idx in enumerate(range(start_idx, log_len)):
                self._addstr(stdscr, log_start + i, 0, self._log[idx], w, curses.A_NORMAL)
        
        # === STATUS BAR ===
        device_count = self.registry.count()
        ready_count = self.registry.count_ready()
        
        status_bar = f"{device_count} device(s) connected ({ready_count} ready).  Press 'q' to quit."
        self._addstr(stdscr, h - 1, 0, status_bar, w, curses.A_DIM)
        
        # Refresh
        stdscr.noutrefresh()
        curses.doupdate()
    
    def _addstr(self, stdscr, y: int, x: int, text: str, max_width: int, attr: int):
        """Safe addstr that handles boundaries."""
        h, w = stdscr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        
        # Truncate text to fit
        available = w - x - 1
        if available <= 0:
            return
        
        text = text[:available]
        
        try:
            stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass  # Ignore curses errors at screen edges

# ══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class CockpitHidBridge:
    """
    Main application - orchestrates all components.

    Coordinates the lifecycle of all subsystems:
    - Device registry and tracking
    - TX dispatcher (UDP -> HID)
    - RX pollers (HID -> UDP)
    - Handshake management
    - Hotplug monitoring
    - Console UI
    """

    def __init__(self, vid: int, pid: Optional[int], dcs_ip: Optional[str] = None):
        self.vid = vid
        self.pid = pid
        self.dcs_ip = dcs_ip

        # Core state
        self.registry = DeviceRegistry()
        self.reconnection_tracker: Dict[str, int] = {}

        # Poller round-robin
        self._next_poller = 0
        self._poller_lock = threading.Lock()

        # Will be initialized in start()
        self.ui_queue: Optional[queue.Queue] = None
        self.ui: Optional[ConsoleUI] = None
        self.tx_dispatcher: Optional[TxDispatcher] = None
        self.udp: Optional[UdpNetwork] = None
        self.handshake_mgr: Optional[HandshakeManager] = None
        self.hotplug: Optional[HotplugMonitor] = None
        self.rx_pollers: List[RxPoller] = []

    def _get_next_poller(self) -> int:
        with self._poller_lock:
            poller_id = self._next_poller
            self._next_poller = (self._next_poller + 1) % RX_POLLERS
            return poller_id

    def start(self) -> None:
        """Initialize and start all components."""
        # Create shared UI queue FIRST - all components use the same queue
        self.ui_queue = queue.Queue()

        self.rx_pollers = []

        # TX dispatcher (with shared queue from start)
        self.tx_dispatcher = TxDispatcher(
            self.registry,
            self.ui_queue,
            num_workers=TX_WORKERS
        )

        # UDP network (with shared queue and initial DCS IP)
        self.udp = UdpNetwork(
            self.tx_dispatcher,
            self.ui_queue,
            initial_dcs_ip=self.dcs_ip
        )

        # RX pollers (with shared queue, callback set after UDP creation)
        for i in range(RX_POLLERS):
            poller = RxPoller(i, self.registry, self.ui_queue)
            self.rx_pollers.append(poller)

        # Wire RX pollers to UDP send using the safe callback setter
        for poller in self.rx_pollers:
            poller.set_command_callback(self.udp.send_command)

        # Create UI with the same shared queue
        self.ui = ConsoleUI(
            self.registry,
            self.udp,
            self.tx_dispatcher,
            self.rx_pollers,
            ui_queue=self.ui_queue,
            initial_dcs_ip=self.dcs_ip
        )

        # Handshake manager (with shared queue from start)
        self.handshake_mgr = HandshakeManager(
            self.registry,
            self.ui_queue,
            self._get_next_poller,
            self.tx_dispatcher.get_next_tx_worker
        )

        # Hotplug monitor (with shared queue from start)
        self.hotplug = HotplugMonitor(
            self.vid, self.pid,
            self.registry,
            self.handshake_mgr,
            self.ui_queue,
            self.reconnection_tracker
        )

        # Start all subsystems
        log_event(self.ui_queue, 'System', 'Starting CockpitOS HID Bridge (Production Edition v3)...')

        # Log platform info
        platform_name = "Raspberry Pi" if IS_RASPBERRY_PI else ("ARM" if IS_ARM else "x86/x64")
        log_event(self.ui_queue, 'System', f'Platform: {platform_name} ({sys.platform})')

        log_event(
            self.ui_queue,
            'System',
            f'VID: 0x{self.vid:04X}, PID: {"Any" if self.pid is None else f"0x{self.pid:04X}"}',
        )
        log_event(self.ui_queue, 'System',
            f'Thread pool: {TX_WORKERS} TX + {RX_POLLERS} RX + {HANDSHAKE_WORKERS} HS workers')

        # Log Pi-specific tuning if applicable
        if IS_RASPBERRY_PI:
            log_event(self.ui_queue, 'System',
                f'Pi tuning: poll={RX_POLL_INTERVAL_MS}ms, stagger={HANDSHAKE_STAGGER_MS}ms, '
                f'all-or-nothing={TX_ALL_OR_NOTHING}')
            log_event(self.ui_queue, 'System',
                f'Device limit: {MAX_DEVICES} (Pi USB bandwidth/power constraint)')

        # Log USB diagnostics on Linux
        log_usb_diagnostics(self.ui_queue)

        self.udp.start()
        self.handshake_mgr.start()
        self.hotplug.start()

        for poller in self.rx_pollers:
            poller.start()

        log_event(self.ui_queue, 'System', 'All subsystems started')
    
    def run(self) -> None:
        """Run the application (blocks until quit)."""
        self.start()

        try:
            self.ui.run()
        finally:
            self.stop()

    def stop(self) -> None:
        """Shutdown all components gracefully."""
        if self.ui_queue:
            log_event(self.ui_queue, 'System', 'Shutting down...')

        # Stop in reverse order of startup for clean shutdown
        if self.hotplug:
            self.hotplug.stop()
        if self.handshake_mgr:
            self.handshake_mgr.stop()
        for poller in self.rx_pollers:
            poller.stop()
        if self.tx_dispatcher:
            self.tx_dispatcher.stop()
        if self.udp:
            self.udp.stop()

        if self.ui_queue:
            log_event(self.ui_queue, 'System', 'Shutdown complete')


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """
    Main entry point for CockpitOS HID Bridge.

    Handles:
    - Single-instance lock acquisition
    - Settings loading
    - Application lifecycle
    - Clean shutdown
    """
    # Acquire single-instance lock (moved from module level for importability)
    acquire_instance_lock()

    try:
        # Load settings (lazy initialization)
        vid, pid, dcs_ip, _ = get_settings()  # report_id used via get_report_id()

        print("CockpitOS HID Bridge - Production Edition v3")
        print(f"VID: 0x{vid:04X}, PID: {'Any' if pid is None else f'0x{pid:04X}'}")
        print(f"Architecture: {TX_WORKERS} TX workers + {RX_POLLERS} RX pollers (fixed)")
        print(f"Logging to: {LOG_PATH}")
        if dcs_ip:
            print(f"Stored DCS IP: {dcs_ip}")
        print("Starting curses interface...")
        print()

        bridge = CockpitHidBridge(vid, pid, dcs_ip)

        try:
            bridge.run()
        except KeyboardInterrupt:
            print("\nInterrupted by user")

        print("Goodbye!")

    finally:
        # Always release the instance lock
        release_instance_lock()


if __name__ == "__main__":
    main()
