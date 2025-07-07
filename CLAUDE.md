# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WiFiSniffer is an ESP32-based packet sniffer that captures WiFi probe requests. It's designed for the M5Stack Stamp S3 device and logs probe request data to an SD card with SHA256 fingerprinting.

## Development Commands

```bash
# Build the project
pio run

# Upload to device
pio run --target upload

# Monitor serial output
pio run --target monitor

# Upload and monitor in one command
pio run --target upload --target monitor

# Clean build files
pio run --target clean
```

## Architecture & Key Components

### Single-File Design
The entire application logic is contained in `src/main.cpp` (544 lines). This monolithic approach keeps all functionality in one place for an embedded system.

### Core Features

1. **Packet Capture**: Uses ESP32 promiscuous mode to capture WiFi probe requests
2. **SHA256 Fingerprinting**: Creates unique hashes of packet payloads for identification
3. **Async SD Writing**: Implements circular buffer to prevent blocking during SD card writes
4. **NTP Time Sync**: Connects to WiFi initially to synchronize time for accurate timestamps
5. **Channel Hopping**: Scans all 14 Japanese WiFi channels (1-14)

### Key Functions

- `promiscuous_callback()`: Processes captured packets, extracts probe requests
- `write_sd_task()`: Async task that writes buffered data to SD card
- `getClientSSID()`: Extracts SSID from probe request frames
- `getHash()`: Generates SHA256 hash of packet payload

### Data Flow

1. Boot → Connect to WiFi → Sync NTP time → Initialize SD card
2. Enter promiscuous mode → Start channel hopping
3. Capture packets → Filter probe requests → Extract data
4. Buffer data → Async write to SD card in CSV format

### Output Format

CSV file on SD card with columns:
- Timestamp (unix epoch)
- SHA256 hash of packet
- RSSI (signal strength)
- Source MAC address
- Hex-encoded packet payload

### Hardware Configuration

- **SD Card**: CS on pin 1, SPI bus (SCK:5, MISO:6, MOSI:4)
- **LED**: Pin 3 for status indication
  - Slow blink: Normal operation
  - Fast blink: NTP sync in progress
  - Solid: WiFi connection active

### Important Notes

- Filters out Microsoft-specific vendor data (OUI starting with 00:50:f2)
- Watchdog timer disabled on Core 0 to prevent resets during packet processing
- Supports both WPA2 Personal and Enterprise probe requests
- Creates new log file each boot with timestamp in filename