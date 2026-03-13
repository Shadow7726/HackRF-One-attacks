# 📡 Complete Cellular Network Penetration Testing Guide
### GSM (2G) · UMTS (3G) · LTE (4G) · Quectel Chipset Focus
**A comprehensive, end-to-end reference for authorized security researchers and telecom engineers**

---

> ⚠️ **LEGAL & ETHICAL DISCLAIMER**  
> This document is intended **exclusively** for authorized penetration testing, security research, academic study, and defensive purposes. All testing described here **must** be performed:
> - With **explicit written authorization** from the network operator and/or device owner
> - Inside an **RF-shielded Faraday cage** or isolated lab environment (to prevent interference with live networks)
> - In compliance with your country's telecommunications law (e.g., India's Indian Wireless Telegraphy Act 1933, IT Act 2000; USA's CFAA, FCC Part 15/97; EU's GDPR and national equivalents)
> - Unauthorized interception of cellular communications is a criminal offense globally
> 
> The author(s) accept no liability for misuse of this material.

---

## Table of Contents

1. [Understanding Cellular Network Architecture](#1-understanding-cellular-network-architecture)
2. [Protocol Stack Deep Dive](#2-protocol-stack-deep-dive)
3. [Quectel Chipset Overview & Attack Surface](#3-quectel-chipset-overview--attack-surface)
4. [Hardware Tools & SDR Platforms](#4-hardware-tools--sdr-platforms)
5. [Software Tools & Frameworks](#5-software-tools--frameworks)
6. [Lab Environment Setup](#6-lab-environment-setup)
7. [GSM (2G) Penetration Testing](#7-gsm-2g-penetration-testing)
8. [UMTS (3G) Penetration Testing](#8-umts-3g-penetration-testing)
9. [LTE (4G) Penetration Testing](#9-lte-4g-penetration-testing)
10. [AT Command Interface Testing (Quectel-Specific)](#10-at-command-interface-testing-quectel-specific)
11. [Firmware & Supply Chain Security](#11-firmware--supply-chain-security)
12. [SS7 / Diameter / GTP Protocol Testing](#12-ss7--diameter--gtp-protocol-testing)
13. [Test Case Catalogue](#13-test-case-catalogue)
14. [Reporting & Evidence Collection](#14-reporting--evidence-collection)
15. [Defensive Mitigations](#15-defensive-mitigations)
16. [Reference Resources](#16-reference-resources)

---

## 1. Understanding Cellular Network Architecture

### 1.1 The Evolution: 2G → 3G → 4G

| Generation | Standard | Air Interface | Core Network | Key Security Feature |
|------------|----------|--------------|--------------|----------------------|
| 2G | GSM / GPRS / EDGE | TDMA | BSS + NSS | A5/1 encryption (breakable), one-way auth |
| 3G | UMTS / HSPA | WCDMA | UTRAN + CN | Mutual auth (AKA), 128-bit KASUMI cipher |
| 4G | LTE / LTE-A | OFDMA | EPC (SAE) | EPS-AKA, NAS/AS security, USIM mandatory |

### 1.2 GSM Network Components

```
Mobile Station (MS)
      │
   Um Interface (Radio)
      │
Base Transceiver Station (BTS)
      │
   Abis Interface
      │
Base Station Controller (BSC)
      │
   A Interface
      │
Mobile Switching Center (MSC) ─── VLR (Visitor Location Register)
      │
   MAP (SS7)
      │
Home Location Register (HLR) / AuC (Authentication Center)
      │
   Gi Interface (GPRS)
      │
SGSN ─── GGSN ─── Internet
```

**Key Interfaces and Protocols:**
- **Um** – MS ↔ BTS (GSM radio, A5/x encrypted)
- **Abis** – BTS ↔ BSC (PCM circuits)
- **A** – BSC ↔ MSC (BSSAP over SS7 MTP)
- **MAP** – MSC ↔ HLR (Mobile Application Part over SS7)
- **Gn/Gp** – SGSN ↔ GGSN (GTP-C / GTP-U)

### 1.3 LTE / EPC Architecture

```
UE (User Equipment / Quectel Modem)
      │
   LTE-Uu (NAS + AS)
      │
eNodeB (eNB)
      │
   S1-MME (SCTP/S1AP) ─── MME (Mobility Management Entity)
   S1-U (GTP-U)       ─── SGW (Serving Gateway)
                              │
                             PGW (PDN Gateway) ─── Internet
                              │
                            HSS (Home Subscriber Server)
                              │
                            PCRF (Policy)
```

**Critical LTE Interfaces:**
- **S1-MME** – eNB ↔ MME (S1AP, control plane)
- **S1-U** – eNB ↔ SGW (GTP-U, user plane)
- **S6a** – MME ↔ HSS (Diameter)
- **Gx** – PGW ↔ PCRF (Diameter, policy)
- **SGi** – PGW ↔ Internet

---

## 2. Protocol Stack Deep Dive

### 2.1 GSM Layer Stack

```
Application Layer
─────────────────
L3 NAS:  MM (Mobility Management)
         CC (Call Control)
         SS (Supplementary Services)
         SMS (Short Message Service)
─────────────────
L3 RR:   Radio Resource Management
─────────────────
L2:      LAPDm (Link Access Protocol on Dm channel)
─────────────────
L1:      TDMA physical layer, BCCH/SDCCH/TCH channels
```

### 2.2 LTE Layer Stack (UE Side)

```
NAS (Non-Access Stratum)  ← EMM + ESM protocols, runs between UE and MME
──────────────────────────
RRC (Radio Resource Control) ← Signaling between UE and eNB
──────────────────────────
PDCP (Packet Data Convergence Protocol) ← Encryption / Integrity
──────────────────────────
RLC (Radio Link Control) ← Segmentation, ARQ
──────────────────────────
MAC (Medium Access Control) ← Scheduling
──────────────────────────
PHY (Physical Layer) ← OFDMA, MIMO
```

### 2.3 Key Identifiers (Attack Surface Fundamentals)

| Identifier | Full Name | Layer | Privacy Risk |
|------------|-----------|-------|-------------|
| IMSI | International Mobile Subscriber Identity | SIM | High – uniquely identifies subscriber |
| IMEI | International Mobile Equipment Identity | Device | High – uniquely identifies hardware |
| TMSI | Temporary Mobile Subscriber Identity | L3 NAS | Medium – temporary alias for IMSI |
| GUTI | Globally Unique Temporary ID | LTE NAS | Medium – replaces IMSI in LTE |
| RNTI | Radio Network Temporary ID | L2 MAC | Low – air interface scheduling |
| Cell ID | eNodeB + Cell ID | RRC | Low – location approximation |

---

## 3. Quectel Chipset Overview & Attack Surface

### 3.1 Quectel Module Families

| Module | Generation | Chipset | Key Features |
|--------|------------|---------|--------------|
| MC60 / M26 | 2G | MediaTek MT6260 | GPRS, GNSS |
| UC15 / UC20 | 3G | Qualcomm MDM9x15 | HSPA+, GNSS |
| EC21 / EC25 | 4G Cat 1/4 | Qualcomm MDM9x07 | LTE, GNSS |
| EG91 / EG95 | 4G Cat 1/4 | Qualcomm MDM9x07 | Multi-band LTE |
| BG95 / BG96 | LTE-M/NB-IoT | Qualcomm MDM9205 | LPWA, PSM, eDRX |
| RG500Q / RG520N | 5G | Qualcomm SDX55/SDX65 | Sub-6GHz / mmWave |
| RM500Q / RM520N | 5G | Qualcomm SDX55/SDX65 | M.2 form factor |

### 3.2 Quectel Attack Surface Map

```
┌─────────────────────────────────────────────────────────────┐
│                    QUECTEL MODULE                           │
│                                                             │
│  ┌─────────────┐  ┌────────────┐  ┌──────────────────────┐ │
│  │ AT Command  │  │  Diag Port │  │  Firmware Update     │ │
│  │ Interface   │  │  (QCDM)    │  │  (USB DFU / FOTA)    │ │
│  │ /dev/ttyUSB0│  │ /dev/ttyUSB│  │                      │ │
│  └──────┬──────┘  └─────┬──────┘  └──────────┬───────────┘ │
│         │               │                    │              │
│  ┌──────▼───────────────▼────────────────────▼───────────┐ │
│  │              Qualcomm Baseband Processor               │ │
│  │  (MDM9x07/MDM9205/SDX55) + TrustZone + ARM Cortex-A   │ │
│  └────────────────────────────────────────────────────────┘ │
│         │                                    │              │
│  ┌──────▼──────┐                    ┌────────▼───────────┐  │
│  │  Radio/RF   │                    │  Application MCU   │  │
│  │  (2G/3G/4G) │                    │  (UART/SPI/I2C)    │  │
│  └─────────────┘                    └────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 USB Interface Enumeration (Typical Quectel)

When a Quectel module is connected via USB:

```bash
# Enumerate USB interfaces
lsusb -v | grep -A5 Quectel

# Typical port layout (varies by module):
# /dev/ttyUSB0  – Diag (QCDM) port
# /dev/ttyUSB1  – NMEA GPS
# /dev/ttyUSB2  – AT Command port
# /dev/ttyUSB3  – Modem (PPP)
# /dev/ttyUSB4  – AT Command (secondary)

# Or as network interface (MBIM / ECM / RNDIS / NCM):
# /dev/cdc-wdm0  – QMI/MBIM control
# wwanX / usbX   – Network interface
```

---

## 4. Hardware Tools & SDR Platforms

### 4.1 Software Defined Radios (SDR)

#### Entry-Level / Receive-Only

| Device | Chipset | Frequency | Cost (USD) | Use Case |
|--------|---------|-----------|-----------|----------|
| RTL-SDR V4 | RTL2832U + R828D | 500 kHz – 1.75 GHz | ~$30 | GSM/UMTS passive scanning |
| NooElec NESDR | RTL2832U | 25 MHz – 1.75 GHz | ~$25 | Passive monitoring |
| Airspy Mini | Si5351C + ATSAMD21 | 24 – 1800 MHz | ~$99 | Better sensitivity, RX only |

#### Mid-Range / Full-Duplex TX+RX

| Device | Chipset | Frequency | Cost (USD) | Use Case |
|--------|---------|-----------|-----------|----------|
| HackRF One | MAX2837 | 1 MHz – 6 GHz | ~$300 | GSM/LTE TX, half-duplex |
| LimeSDR Mini 2.0 | LMS7002M | 10 MHz – 3.5 GHz | ~$200 | Full-duplex, OpenBTS |
| LimeSDR USB | LMS7002M | 100 kHz – 3.8 GHz | ~$300 | MIMO, OpenBTS/srsRAN |
| bladeRF 2.0 micro | AD9361 | 47 MHz – 6 GHz | ~$480 | MIMO, LTE base station |

#### Professional / Research-Grade

| Device | Chipset | Frequency | Cost (USD) | Use Case |
|--------|---------|-----------|-----------|----------|
| USRP B210 | AD9361 | 70 MHz – 6 GHz | ~$1,900 | srsRAN, OAI, MIMO LTE |
| USRP B205mini | AD9364 | 70 MHz – 6 GHz | ~$900 | Compact MIMO |
| USRP X310 | 2× AD9371 | 10 MHz – 6 GHz | ~$5,000 | Multi-band, high throughput |
| Ettus USRP N310 | AD9371 | 10 MHz – 6 GHz | ~$8,000 | 4×4 MIMO, production testing |

#### Recommended for Cellular Pentest Lab

```
Minimum viable lab:
  - RTL-SDR V4 (passive scanning)     ~$30
  - HackRF One (active testing)       ~$300
  - Raspberry Pi 4 (control node)     ~$80
  - Faraday cage / RF shield bag      ~$50-200

Intermediate lab:
  - USRP B210                         ~$1,900
  - LimeSDR USB                       ~$300
  - Server-class Ubuntu workstation   ~$500-1000

Professional lab:
  - USRP X310 (2× daughter boards)   ~$5,000+
  - Amarisoft LTEENB license          Commercial
  - RF shielded enclosure             ~$2,000+
```

### 4.2 Cellular Modems / UE Hardware for Testing

| Device | Chipset | Generations | Interface | Notes |
|--------|---------|-------------|-----------|-------|
| Quectel EC25 (EVB kit) | Qualcomm MDM9x07 | 2G/3G/4G | USB/UART | Exposes QCDM Diag |
| Quectel BG95-M3 (EVB) | Qualcomm MDM9205 | 2G/LTE-M/NB1 | USB/UART | LPWA focused |
| Sierra Wireless EM7455 | Qualcomm MDM9230 | 4G | M.2/USB | Widely tested |
| Huawei ME909s | HiSilicon Balong | 4G | M.2 | Common in IoT gateways |
| SIM7600 (SIMCOM) | Qualcomm MDM9225 | 4G | USB | Popular IoT module |
| ZTE MF833V | Qualcomm | 4G | USB dongle | Exposed Diag port |

### 4.3 SIM Card Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| Sysmocom SIM cards | Programmable SIMs | USRPs-compatible, test network use |
| sysmoISIM-SJA5 | Programmable USIM | LTE AKA support |
| Proxmark3 | RFID/SIM analysis | Can read SIM filesystems |
| PC/SC-compatible reader | SIM filesystem access | Used with pyscard |
| OsmoSIM-Harness | SIM testing | Part of Osmocom suite |

### 4.4 Supporting Hardware

```
┌─────────────────────────────────────────────────────┐
│ Recommended Supporting Hardware                      │
│                                                     │
│  • Faraday cage / RF shielded box (mandatory!)       │
│  • Variable RF attenuators (30dB-60dB range)        │
│  • SMA cables and adapters (male/female, N-type)    │
│  • Directional antennas (Yagi, patch for 700/850/   │
│    1800/2100/2600 MHz bands)                        │
│  • Spectrum analyzer (TinySA Ultra ~$120)           │
│  • Oscilloscope (Rigol DS1054Z ~$350)               │
│  • USB hub (powered, for multiple modem testing)    │
│  • Raspberry Pi CM4 / Jetson Nano (edge testing)    │
└─────────────────────────────────────────────────────┘
```

---

## 5. Software Tools & Frameworks

### 5.1 Core Open-Source Frameworks

#### srsRAN (formerly srsLTE)

```bash
# GitHub: https://github.com/srsran/srsRAN_4G
# Purpose: Complete 4G LTE stack (eNB + EPC + UE)
# Supports: USRP, LimeSDR, bladeRF, ZMQ (virtual)

# Install dependencies (Ubuntu 22.04)
sudo apt install cmake libfftw3-dev libmbedtls-dev libboost-all-dev \
  libconfig++-dev libsctp-dev libuhd-dev libzmq3-dev

# Clone and build
git clone https://github.com/srsran/srsRAN_4G.git
cd srsRAN_4G && mkdir build && cd build
cmake ../ -DENABLE_UHD=ON -DENABLE_ZEROMQ=ON
make -j$(nproc)
sudo make install
sudo ldconfig

# Generate config files
srsran_install_configs.sh user
# Configs go to ~/.config/srsran/
```

#### OpenAirInterface (OAI)

```bash
# GitHub: https://gitlab.eurecom.fr/oai/openairinterface5g
# Purpose: 4G/5G RAN + Core, 3GPP compliant
# Heavy but very feature complete

git clone https://gitlab.eurecom.fr/oai/openairinterface5g.git
cd openairinterface5g
source oaienv
cd cmake_targets
./build_oai -w USRP --eNB --UE --nrUE --gNB -C --ninja
```

#### OpenBTS

```bash
# GitHub: https://github.com/RangeNetworks/openbts
# Purpose: GSM 2G base station using SDR
# Updated fork: https://github.com/kneedeepbts/obts-smqueue

# Dependencies
sudo apt install autoconf libtool pkg-config libosip2-dev \
  libusrp-dev libuhd-dev libzmq3-dev

git clone https://github.com/RangeNetworks/openbts.git
cd openbts
./autogen.sh && ./configure --with-uhd
make -j$(nproc)
```

#### OsmocomBB

```bash
# Project: https://osmocom.org/projects/baseband/wiki
# Purpose: Open-source GSM baseband (L1/L2/L3)
# Hardware: Motorola C1xx phones with Calypso chipset

git clone https://gitea.osmocom.org/phone-side/osmocom-bb.git
cd osmocom-bb/src
make

# Key programs:
# osmocon    – connects to Calypso via serial
# mobile     – GSM mobile application
# trxcon     – connects to osmo-trx for SDR
```

### 5.2 Quectel-Specific & Qualcomm Diagnostic Tools

#### QCSuper

```bash
# GitHub: https://github.com/P1sec/QCSuper
# Purpose: Capture 2G/3G/4G radio frames via Qualcomm QCDM/Diag protocol
# Compatible: Quectel EC25, BG95, RG500Q, etc.

# Install
git clone https://github.com/P1sec/QCSuper.git
cd QCSuper
sudo apt install python3-pip wireshark
pip3 install --upgrade pyserial crcmod \
  "https://github.com/P1sec/pycrate/archive/master.zip"

# Usage: Capture via USB modem (Quectel EC25 example)
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --wireshark-live

# Capture to PCAP file
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --pcap-dump /tmp/capture.pcap

# Capture via ADB (rooted Android with Qualcomm SoC)
./qcsuper.py --adb --wireshark-live

# What it captures:
# - NAS (MM/CC/SMS for 2G, RRC/NAS for 3G/4G)
# - Layer 3 signaling in GSMTAP format → Wireshark readable
```

#### SCAT (Smartphone Chipset Analysis Toolkit)

```bash
# GitHub: https://github.com/fgsect/scat
# Purpose: Parse Qualcomm + Samsung baseband diagnostic messages
# Generates GSMTAP stream → Wireshark

git clone https://github.com/fgsect/scat.git
cd scat
pip3 install -r requirements.txt

# For Qualcomm (Quectel modules):
python3 scat.py -t qc --qdl-modem /dev/ttyUSB0 -W

# For Samsung:
python3 scat.py -t sec --serial /dev/ttyACM0 -W
```

#### diag-parser

```bash
# GitHub: https://github.com/moiji-mobile/diag-parser
# Purpose: Decode Qualcomm DIAG protocol frames
# Useful for understanding raw Quectel Diag output

git clone https://github.com/moiji-mobile/diag-parser.git
cd diag-parser && make
```

### 5.3 GSM Tools

#### gr-gsm

```bash
# GitHub: https://github.com/ptrkrysik/gr-gsm
# Purpose: Decode GSM bursts, capture BCH/CCCH/SDCCH

sudo apt install gr-gsm  # Ubuntu with GNU Radio
# Or build from source:
git clone https://github.com/ptrkrysik/gr-gsm.git
cd gr-gsm && mkdir build && cd build
cmake .. && make -j$(nproc) && sudo make install

# Scan for GSM cells
grgsm_scanner

# Decode channel (replace FREQ with actual cell frequency in MHz)
grgsm_livemon_headless -f 947.2M -g 40
# Then open Wireshark on loopback, filter: gsmtap
```

#### Kalibrate-RTL

```bash
# GitHub: https://github.com/steve-m/kalibrate-rtl
# Purpose: Calibrate RTL-SDR frequency offset using GSM beacons

git clone https://github.com/steve-m/kalibrate-rtl.git
cd kalibrate-rtl && ./bootstrap && ./configure && make

# Scan GSM-900 band
./kal -s GSM900 -g 40

# Output example: chan: 1 (935.2MHz + 14.499kHz) → offset ppm
```

#### OsmoSDR + Wireshark

```bash
# GSM SIM analysis
sudo apt install python3-pyscard pcscd pcsc-tools

# List SIM readers
pcsc_scan

# Read SIM files with pySIM
git clone https://github.com/osmocom/pysim.git
cd pysim
pip3 install -r requirements.txt
./pySim-read.py -p 0  # Read SIM on reader 0
```

### 5.4 LTE Tools

#### LTE-Cell-Scanner

```bash
# GitHub: https://github.com/Evrytania/LTE-Cell-Scanner
# Purpose: Scan and decode LTE cells using SDR

git clone https://github.com/Evrytania/LTE-Cell-Scanner.git
cd LTE-Cell-Scanner && mkdir build && cd build
cmake .. -DUSE_BLADERF=0 && make -j$(nproc)

# Scan LTE cells (replace FREQ with LTE band center frequency)
./CellSearch --freq-start 806000000 --freq-end 826000000
```

#### LTESniffer

```bash
# GitHub: https://github.com/SysSec-KAIST/LTESniffer
# Purpose: Passive LTE uplink/downlink sniffer
# Captures IMSI via paging messages (passive, no TX)

git clone https://github.com/SysSec-KAIST/LTESniffer.git
cd LTESniffer && mkdir build && cd build
cmake .. && make -j$(nproc)

# Run downlink sniffer
sudo ./src/LTESniffer -A 2 -W 4 -f 806e6 -m 0

# Run uplink + downlink
sudo ./src/LTESniffer -A 2 -W 4 -f 806e6 -m 1
```

#### Open5GS (EPC Core for Testing)

```bash
# GitHub: https://github.com/open5gs/open5gs
# Purpose: Full 4G/5G core network for lab testing

sudo apt install open5gs
# Configure subscriber in WebUI
open5gs-dbctl add <IMSI> <KEY> <OPc>

# Start components
sudo systemctl start open5gs-mmed
sudo systemctl start open5gs-sgwcd
sudo systemctl start open5gs-pgwd
sudo systemctl start open5gs-hssd
```

### 5.5 SS7 / Diameter / Signaling Tools

#### SiGploit

```bash
# GitHub: https://github.com/SigPloiter/SigPloit
# Purpose: Telecom signaling security testing (SS7, Diameter, GTP, SIP)

git clone https://github.com/SigPloiter/SigPloit.git
cd SigPloit
pip3 install -r requirements.txt
python3 sigploit.py

# Module categories:
# SS7     - MAP protocol attacks
# Diameter- LTE signaling attacks
# GTP     - GPRS Tunneling Protocol
# SIP     - VoIP attacks
```

#### MAP Tester (Osmocom)

```bash
# Part of Osmocom project
# https://osmocom.org/projects/osmocombb

# Test MAP protocol
osmo-stp --config-file stp.cfg  # Signal Transfer Point
```

### 5.6 Fuzzing Tools

#### Baseband Fuzzing with Boofuzz

```bash
# GitHub: https://github.com/jtpereyda/boofuzz
pip3 install boofuzz

# AT Command fuzzer example
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=SerialConnection("/dev/ttyUSB2", baudrate=115200)
        )
    )
    s_initialize("AT_CMD")
    s_string("AT+CIMI", fuzzable=True)
    s_static("\r\n")
    session.connect(s_get("AT_CMD"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

#### 5GBaseChecker

```bash
# GitHub: https://github.com/SyNSec-den/5GBaseChecker
# Purpose: Automated 5G baseband protocol security analysis
# Research tool from Pennsylvania State University (USENIX Security 2024)

git clone https://github.com/SyNSec-den/5GBaseChecker.git
# Requires: Open5GS core + OAI gNB or srsRAN gNB
# Follow detailed README for FSM extraction setup
```

### 5.7 Analysis & Monitoring Tools

| Tool | Purpose | Install |
|------|---------|---------|
| Wireshark | Protocol analysis (GSM/LTE/SS7 dissectors) | `sudo apt install wireshark` |
| tshark | CLI Wireshark | `sudo apt install tshark` |
| GNU Radio | SDR signal processing | `sudo apt install gnuradio` |
| DragonOS | Ubuntu SDR distro with pre-installed tools | ISO from GitHub |
| GQRX | SDR spectrum viewer | `sudo apt install gqrx-sdr` |
| Universal Radio Hacker | RF signal analysis | `pip3 install urh` |
| Scapy | Packet crafting (GTP/Diameter) | `pip3 install scapy` |
| pycrate | Telecom protocol encode/decode | `pip3 install pycrate` |
| FreeDiameter | Diameter protocol stack | Build from source |

---

## 6. Lab Environment Setup

### 6.1 Mandatory Safety: RF Isolation

**NEVER run cellular base stations without RF isolation. It is illegal in most countries to operate unlicensed transmitters on cellular frequencies.**

```
Options for RF Isolation:
  
  1. Faraday Cage (Build or Buy)
     - DIY: Line a wooden box with copper mesh or aluminum sheet
     - Commercial: RF shielded test enclosures (Ramsey STE series)
     - Target: >60 dB attenuation across cellular bands
  
  2. Coaxial Cable Connection (Best for lab)
     - SDR TX → Attenuator (30-60 dB) → UE antenna port
     - Eliminates over-the-air transmission entirely
     - Use SMA splitters/combiners for multi-device setups
  
  3. RF Shield Bag
     - Cheap option (~$20-50)
     - Place device under test inside bag
     - Connect via SMA feedthrough
```

### 6.2 Isolated Lab Stack Setup

```
Recommended Lab Setup (srsRAN + Open5GS):

┌──────────────────────────────────────────────────────┐
│                  Ubuntu 22.04 Host                    │
│                                                      │
│  ┌─────────────┐    ┌──────────────┐                 │
│  │  srsENB     │    │   Open5GS    │                 │
│  │  (eNodeB)   ├────┤   (EPC)      │                 │
│  │             │    │  MME/HSS/SGW │                 │
│  └──────┬──────┘    └──────────────┘                 │
│         │ ZMQ (virtual) or UHD (USRP)               │
│  ┌──────▼──────┐                                     │
│  │  srsUE      │  ← simulated UE (no SDR needed)     │
│  │  (UE)       │                                     │
│  └─────────────┘                                     │
└──────────────────────────────────────────────────────┘
```

### 6.3 ZMQ Virtual Radio (No SDR Required)

```bash
# Run full LTE lab in software using ZMQ

# Terminal 1: Start EPC
sudo open5gs-mmed &
sudo open5gs-sgwcd &
sudo open5gs-pgwd &
sudo open5gs-hssd &

# Terminal 2: Start eNB
srsenb ~/.config/srsran/enb.conf

# Terminal 3: Start UE
srsue ~/.config/srsran/ue.conf

# Terminal 4: Monitor
sudo ip netns exec ue1 bash  # Enter UE namespace
ping 8.8.8.8                 # Test connectivity
```

### 6.4 Quectel Module Lab Setup

```bash
# Physical setup:
# PC → USB → Quectel Module (e.g., EC25 EVB kit)
# Quectel antenna → Attenuator → Lab eNB antenna (or Faraday cage)

# Verify ports
ls /dev/ttyUSB*
# → /dev/ttyUSB0 (Diag), /dev/ttyUSB1 (NMEA), /dev/ttyUSB2 (AT)

# Test AT interface
sudo apt install minicom
minicom -D /dev/ttyUSB2 -b 115200
AT          # → OK
AT+GMR      # → Firmware version
AT+CGSN     # → IMEI
AT+CIMI     # → IMSI (SIM required)
AT+CREG?    # → Registration status
AT+COPS?    # → Current operator
AT+QNWINFO  # → Quectel: current network info
AT+QRSRP    # → Quectel: signal strength (LTE)
```

---

## 7. GSM (2G) Penetration Testing

### 7.1 GSM Security Weaknesses (Background)

GSM was designed in the late 1980s with several known cryptographic limitations:

1. **One-way authentication only**: Network authenticates UE, but UE cannot verify network identity → IMSI catcher attacks possible
2. **Weak A5/1 cipher**: 64-bit key, broken via rainbow tables (Karsten Nohl, 2010); A5/2 completely broken
3. **No integrity protection** on control plane in GSM (GPRS has GEA0/GEA1/GEA2, all broken)
4. **IMSI transmitted in plaintext** during initial attach before TMSI assigned
5. **SMS transmitted via signaling channels** with minimal protection

### 7.2 GSM Test Cases

---

#### TC-2G-01: Cell Discovery and Passive Monitoring

**Category:** Reconnaissance  
**Risk Level:** Informational  
**Tools:** RTL-SDR, gr-gsm, Wireshark  
**Description:** Identify nearby GSM cells, capture BCCH/CCCH/SDCCH traffic passively without transmitting.

**Steps:**

```bash
# Step 1: Scan for GSM cells
grgsm_scanner -b GSM900 -s 2e6
# Output: Lists all detected cells with ARFCN, frequency, BSIC, LAC, Cell ID

# Step 2: Pick a target cell and decode
# Replace 947.2M with detected BCCH frequency
grgsm_livemon_headless -f 947.2M -g 40 -s 2e6

# Step 3: Open Wireshark on loopback
wireshark -k -i lo -f "udp port 4729"

# Step 4: Apply Wireshark display filter
# gsmtap    → all GSM traffic
# gsm_a.dtap → Call control/mobility management
# gsm_sms   → SMS messages (usually ciphertext)

# Step 5: Look for SYSTEM INFORMATION messages
# SI1-SI4: Contain cell parameters, LAC, Cell ID, neighbor cells
# TMSI allocation: gsmtap && gsm_a.rr.msg_type == 0x1a

# Expected findings:
# - Cell identity (MCC, MNC, LAC, CI)
# - Neighboring cell list
# - Ciphering algorithm in use (A5/x)
# - IMSI paging (before TMSI assigned to subscriber)
```

**What to document:**
- MCC (Mobile Country Code), MNC (Mobile Network Code)
- LAC (Location Area Code), Cell ID
- BCCH ARFCN
- A5 algorithm in use (from cipher mode command)
- Presence of unencrypted identity requests

---

#### TC-2G-02: IMSI Harvesting via Passive Paging Analysis

**Category:** Privacy / Subscriber Tracking  
**Risk Level:** Medium  
**Tools:** gr-gsm, Wireshark, Python  
**Description:** Extract TMSIs and IMSIs from paging messages on CCCH channel.

```bash
# Run gr-gsm decoder
grgsm_livemon_headless -f 947.2M -g 50 -s 2e6

# In Wireshark, filter for identity requests:
# gsm_a.rr.msg_type == 0x18  (Paging Request Type 1)

# Python extraction script
from scapy.all import *
from scapy.layers.gsm import *

def extract_tmsi(pkt):
    if pkt.haslayer(Raw):
        # Parse GSMTAP packets from loopback
        data = pkt[Raw].load
        if len(data) > 4 and data[2] == 0x06:  # RR layer
            print(f"Paging: {data.hex()}")

sniff(iface="lo", filter="udp port 4729", prn=extract_tmsi)

# Expected findings:
# - TMSI values being paged (normal, expected)
# - IMSI values in plaintext (vulnerability if present)
# - Paging frequency → approximate subscriber count in cell
```

---

#### TC-2G-03: A5/1 Cipher Detection and Downgrade Test

**Category:** Cryptographic Security  
**Risk Level:** High  
**Tools:** gr-gsm, OsmocomBB (with Calypso phone), srsRAN  
**Description:** Determine which A5 cipher variant the network uses, test for downgrade to A5/0 (no encryption).

```bash
# Using OsmocomBB (requires Motorola C123/C118 phone):
# 1. Flash OsmocomBB firmware
cd osmocom-bb/src
# Flash phone via serial adapter

# 2. Use mobile application with sniffing
# In OsmocomBB apps/mobile:
osmocon -m c123xor -p /dev/ttyUSB0 ../../target/firmware/board/compal_e88/layer1.compalram.bin

# 3. Monitor cipher mode from captured logs
# Look for: "Cipher Mode Command" → cipher = A5/0 (no encryption!)

# Using srsRAN eNB (authorized lab environment only):
# Configure enb.conf to test cipher negotiation:
# [security]
# encryption_algo = EEA0  # Force no encryption

# Expected findings:
# - Network accepting A5/0 downgrade = HIGH vulnerability
# - A5/1 only (no A5/3) = MEDIUM vulnerability
# - A5/3 enforced = PASS
```

---

#### TC-2G-04: False Base Station Detection Test (Rogue BTS Susceptibility)

**Category:** Authentication / Man-in-the-Middle  
**Risk Level:** Critical  
**Tools:** srsRAN + USRP (lab only, Faraday cage mandatory), programmable SIMs  
**Description:** Test whether a device connects to a rogue base station presenting a stronger signal. This is a lab-environment test on authorized devices only.

```bash
# Lab Setup (FARADAY CAGE REQUIRED):
# USRP B210 → srsRAN eNB → Open5GS EPC
# Target UE (authorized device) inside Faraday cage

# 1. Configure rogue eNB matching real network parameters
# ~/.config/srsran/enb.conf:
[enb]
mcc = 404          # Same MCC as real network
mnc = 10           # Same MNC
mme_addr = 127.0.1.1
gtp_bind_addr = 127.0.1.1
s1c_bind_addr = 127.0.1.1
n_prb = 25
tm = 1
nof_ports = 1

[rf]
dl_earfcn = 3400    # Choose appropriate EARFCN
tx_gain = 40
rx_gain = 40

# 2. Monitor whether UE connects to lab eNB
# Check: Does UE send IMSI in NAS Attach Request?
# (Should send GUTI/TMSI instead if properly implemented)

# 3. Test authentication rejection behavior
# In lab MME, send Auth Reject → UE should not retry on same PLMN

# Expected pass criteria:
# - UE sends GUTI instead of IMSI in attach
# - UE rejects NAS Security Mode Command without valid MAC
# - UE does NOT downgrade to 2G/3G when 4G is available (if configured)
```

---

#### TC-2G-05: GPRS / GTP Security Assessment

**Category:** Data Plane Security  
**Risk Level:** Medium-High  
**Tools:** Wireshark, Scapy, SiGploit  
**Description:** Analyze GPRS tunneling security, test for GTP-C injection.

```bash
# Capture GTP traffic (requires access to Gn interface in authorized test)
sudo tcpdump -i eth0 -w gtp_capture.pcap port 2123 or port 2152

# Analyze with Wireshark
# Filter: gtp

# Test GTP-C injection with Scapy (authorized lab only)
from scapy.all import *
from scapy.contrib.gtp import *

# Craft GTP-C Echo Request
pkt = IP(dst="<GGSN_IP>") / UDP(dport=2123) / \
      GTPHeader(version=1, PT=1, teid=0) / \
      GTPEchoRequest()
send(pkt)

# Expected findings:
# - GTP-C accessible without authentication = vulnerability
# - No rate limiting on GTP-C = DoS risk
# - Missing GTP version validation
```

---

## 8. UMTS (3G) Penetration Testing

### 8.1 UMTS Security Improvements over GSM

- **Mutual authentication** via AKA (Authentication and Key Agreement)
- **128-bit KASUMI cipher** (f8 algorithm) for encryption
- **Integrity protection** (f9 algorithm) on RRC signaling
- **USIM** instead of SIM (stronger key derivation)

**Remaining Weaknesses:**
- KASUMI has theoretical weaknesses (related-key attacks)
- **Bidding-down attack**: 3G → 2G forced downgrade still possible in mixed networks
- UTRAN interfaces (Iub, Iur, Iu-CS, Iu-PS) unencrypted by default in many deployments
- No protection against false base station if UE connects to GSM

### 8.2 UMTS Test Cases

---

#### TC-3G-01: UTRAN Interface Traffic Analysis

**Category:** Reconnaissance / Confidentiality  
**Risk Level:** Medium  
**Tools:** Wireshark, tcpdump, QCSuper  
**Description:** Analyze Iub/Iur interface traffic in authorized network access.

```bash
# Capture on Iub interface (authorized telco lab)
sudo tcpdump -i eth0 -w utran_capture.pcap

# Wireshark filters:
# rnsap    → Radio Network Subsystem Application Part
# nbap     → Node B Application Part
# ranap    → Radio Access Network Application Part
# s1ap     → (for LTE, but common to confuse)

# QCSuper capture from Quectel module (3G mode)
# Force module to 3G only:
# AT+QCFG="nwscanmode",2  → UMTS only
AT+QCFG="nwscanmode",2,1   # Quectel: set UMTS only mode

# Then capture:
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --wireshark-live

# Expected findings:
# - RRC Connection Setup messages
# - Security Mode Command (check ciphering/integrity algorithms)
# - UE identity (IMSI vs TMSI in Initial UE Message)
```

---

#### TC-3G-02: 3G Authentication Vector Testing

**Category:** Authentication Security  
**Risk Level:** High  
**Tools:** pySim, OsmocomBB, custom AKA tester  
**Description:** Test AKA protocol implementation for vulnerabilities.

```bash
# Read USIM with pySim (requires PC/SC reader)
cd pysim
./pySim-read.py -p 0

# Extract relevant files:
# EF.IMSI  → 2FF07 → IMSI
# EF.Kc    → 2F20  → Current session key (2G)
# EF.CK    → 6F08  → Cipher Key (3G)
# EF.IK    → 6F09  → Integrity Key (3G)

# Test SQN replay attack:
# AKA uses Sequence Numbers (SQN) to prevent replay attacks
# Send Authentication Request with old/invalid AUTN
# UE should respond with SYNC_FAILURE (SQN out of range)

# Python AKA tester
import struct
from Crypto.Cipher import AES

def test_aka_sqn_replay(old_rand, old_autn):
    """Test if modem properly rejects replayed authentication vectors"""
    # Send old RAND + AUTN via AT command
    # AT+CSIM: APDU-based SIM access
    pass
```

---

#### TC-3G-03: 3G-to-2G Bidding Down Attack

**Category:** Protocol Downgrade  
**Risk Level:** High  
**Tools:** srsRAN (2G), OpenBTS (lab environment, Faraday cage)  
**Description:** Test if device can be forced from 3G to 2G by disabling 3G in lab eNB.

```bash
# Authorized lab test procedure:

# Step 1: Establish UE connection on 3G lab network
# Step 2: Gradually reduce 3G signal strength (using attenuator)
# Step 3: Bring up 2G (GSM) base station (OpenBTS) in same lab
# Step 4: Observe if UE falls back to 2G

# Monitor fallback via QCSuper:
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --pcap-dump /tmp/fallback.pcap

# Expected behavior:
# PASS: UE refuses to connect to unencrypted 2G network
# FAIL: UE silently downgrades without user notification
# FAIL: UE accepts A5/0 (no cipher) after downgrade

# Quectel AT commands to monitor:
AT+CREG?        # Registration status
AT+QNWINFO      # Current network type (should show 3G/2G)
AT+QBAND?       # Current band
```

---

## 9. LTE (4G) Penetration Testing

### 9.1 LTE Security Architecture

LTE introduces significantly stronger security:

- **EPS-AKA**: Extended AKA with 128-bit keys (AES/SNOW 3G)
- **NAS Security**: Encryption (EEA1/EEA2/EEA3) + Integrity (EIA1/EIA2/EIA3)
- **AS Security**: RRC + User Plane encryption and integrity
- **USIM mandatory**: No legacy SIM support
- **GUTI**: Temporary identity to protect IMSI

**Remaining Vulnerabilities:**
- **IMSI Catchers** still possible via Tracking Area Update Reject / Service Reject attacks
- **NAS Attach with IMSI** required on first attach (no GUTI assigned yet)
- **RRC unprotected early messages** (before security activation)
- **Physical layer DoS** (jamming, pilot contamination)
- **SS7/Diameter** backend still vulnerable
- **GTP-U** user plane not encrypted between eNB and SGW in many deployments

### 9.2 LTE Test Cases

---

#### TC-4G-01: LTE Cell Discovery and Signal Analysis

**Category:** Reconnaissance  
**Risk Level:** Informational  
**Tools:** LTE-Cell-Scanner, srsRAN, RTL-SDR  
**Description:** Map LTE cells, decode SIB (System Information Block) messages.

```bash
# Scan LTE Band 3 (1800 MHz)
./CellSearch --freq-start 1805000000 --freq-end 1880000000 --correction 0

# Or using rtl_sdr + LTE decoder
# First scan: identify EARFCN
gqrx  # Use spectrum view to find LTE downlink carriers

# Decode SIB with srsRAN RRC decoder
srsenb --log.all_level=info 2>&1 | grep SIB

# Using QCSuper on attached Quectel modem:
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --wireshark-live
# Filter in Wireshark: lte_rrc

# What to extract from SIBs:
# SIB1: PLMN, TAC, Cell ID, scheduling info
# SIB2: Radio config, RACH parameters
# SIB3: Cell reselection parameters
# SIB4: Neighbor cell list (intra-freq)
# SIB5: Neighbor cell list (inter-freq)

# Document:
# - Supported ciphering algorithms (from SIB2 or SecurityModeCommand)
# - Cell barred status
# - TAC (Tracking Area Code)
# - Physical Cell ID (PCI)
```

---

#### TC-4G-02: NAS Security Mode Analysis

**Category:** Cryptographic Security  
**Risk Level:** High  
**Tools:** QCSuper, Wireshark, srsRAN lab  
**Description:** Analyze NAS Security Mode Command to determine negotiated algorithms.

```bash
# Capture NAS traffic during attach procedure
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --pcap-dump /tmp/nas_attach.pcap

# Wireshark filter for NAS Security Mode:
# nas_eps.nas_msg_emm_type == 0x5d  (Security Mode Command)
# nas_eps.nas_msg_emm_type == 0x5e  (Security Mode Complete)

# Check negotiated algorithms in Security Mode Command:
# EEA0 = No encryption (NULL)  ← FAIL
# EEA1 = SNOW 3G              ← Acceptable
# EEA2 = AES-128-CTR          ← Best
# EEA3 = ZUC                  ← Acceptable

# EIA0 = No integrity (NULL)  ← CRITICAL FAIL on NAS
# EIA1 = SNOW 3G              ← Acceptable
# EIA2 = AES-128-CMAC         ← Best
# EIA3 = ZUC                  ← Acceptable

# Automated extraction with tshark:
tshark -r nas_attach.pcap \
  -Y "nas_eps.nas_msg_emm_type == 0x5d" \
  -T fields \
  -e nas_eps.emm.toc \
  -e nas_eps.emm.eea \
  -e nas_eps.emm.eia
```

---

#### TC-4G-03: IMSI Leakage Detection

**Category:** Privacy  
**Risk Level:** High  
**Tools:** QCSuper, Wireshark, LTESniffer (passive)  
**Description:** Determine if IMSI is transmitted in plaintext during attach/paging.

```bash
# Method 1: QCSuper capture during first attach
# (Remove SIM, insert fresh, reattach)

AT+CFUN=0    # Power off radio
# Remove and reinsert SIM
AT+CFUN=1    # Power on radio (forces fresh attach with IMSI)

# Simultaneously capture:
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --pcap-dump /tmp/first_attach.pcap

# Wireshark filter:
# nas_eps.emm.type_of_id == 1  → IMSI (vulnerability!)
# nas_eps.emm.type_of_id == 6  → GUTI (expected, pass)

# Method 2: Passive LTESniffer (Downlink paging channel)
# LTESniffer passively captures TMSIs from paging messages
# IMSI appears only in specific attack scenarios

# Method 3: Lab test with srsRAN
# Configure MME to NOT have GUTI for subscriber
# → UE must send IMSI in Attach Request
# Test: Does UE send IMSI over unprotected channel? YES (expected/required)
# Test: Is IMSI visible before security mode activation? YES (vulnerability by design in LTE)
# Standard improvement: 5G uses SUCI (Concealed SUPI) to fix this
```

---

#### TC-4G-04: eNB S1 Interface Security Assessment

**Category:** Network Interface Security  
**Risk Level:** High  
**Tools:** Wireshark, Scapy, OpenSCTP  
**Description:** Assess security of S1-MME interface (SCTP/S1AP).

```bash
# S1AP runs over SCTP port 36412
# In authorized lab:
sudo tcpdump -i eth0 -w s1ap.pcap sctp

# Wireshark filter: s1ap
# Key message types to analyze:
# S1AP Initial UE Message   → First UE NAS message
# S1AP Downlink NAS Transp  → MME → UE NAS messages
# S1AP UE Context Setup     → Bearer establishment

# Test S1AP injection (lab/authorized only):
from scapy.all import *
from scapy.contrib.sctp import *

# Test: Can unauthorized eNB connect to MME?
pkt = IP(dst="<MME_IP>") / SCTP(dport=36412) / SCTPChunkInit()
send(pkt)
# PASS: MME rejects unauthenticated connection
# FAIL: MME accepts any eNB without IPsec/certificate validation

# S1AP fuzzing with Boofuzz
# See: https://github.com/jtpereyda/boofuzz/tree/master/examples
```

---

#### TC-4G-05: GTP-U User Plane Integrity Test

**Category:** Data Plane Security  
**Risk Level:** Medium  
**Tools:** Scapy, Wireshark  
**Description:** Test whether GTP-U tunnel between eNB and SGW can be injected.

```bash
# GTP-U runs on UDP port 2152
# Capture GTP-U in authorized lab environment:
sudo tcpdump -i eth0 -w gtpu.pcap udp port 2152

# Analyze GTP-U headers:
# - TEID (Tunnel Endpoint ID) → if guessable, injection possible

# Test GTP-U TEID predictability:
from scapy.contrib.gtp import *
from scapy.all import *

# Send crafted GTP-U packet with guessed TEID
teid = 0x00000001  # Example TEID

pkt = IP(src="<ENB_IP>", dst="<SGW_IP>") / \
      UDP(sport=2152, dport=2152) / \
      GTP_U_Header(teid=teid) / \
      IP(src="10.0.0.1", dst="8.8.8.8") / \
      ICMP()
send(pkt)

# Expected:
# PASS: TEID not guessable, injection dropped
# FAIL: Sequential TEID, injection accepted → user data manipulation
```

---

#### TC-4G-06: VoLTE (IMS) Security Testing

**Category:** Voice/Multimedia Security  
**Risk Level:** Medium-High  
**Tools:** SIPp, Wireshark, Nmap  
**Description:** Test IMS/VoLTE signaling security.

```bash
# Scan IMS ports (authorized only)
nmap -sU -sT -p 5060,5061,4060 <IMS_IP>

# SIP OPTIONS probe (SIPp)
sipp -sn uac -d 1000 -s <IMPU> <IMS_IP>:5060

# Capture SIP/RTP with Wireshark:
# Filter: sip or rtp

# Check for:
# - SIP without TLS (SIP over UDP/TCP instead of SIPS)
# - SRTP not enforced
# - SIP Digest authentication strength
# - Missing SIP identity headers (call spoofing possible)

# AT command to initiate VoLTE test call (Quectel):
AT+QCFG="volte_disable",0   # Enable VoLTE
AT+CLCC                      # List current calls
```

---

## 10. AT Command Interface Testing (Quectel-Specific)

### 10.1 AT Command Security Overview

The AT command interface is the primary management plane for Quectel modules. It represents a significant attack surface in IoT devices:

- **UART interface**: Physical access to device → AT commands
- **USB Modem port**: Virtual serial over USB
- **Remote AT (QFTP/QMTCONN)**: Network-accessible AT commands in some configurations

### 10.2 AT Command Test Cases

---

#### TC-AT-01: AT Command Interface Enumeration

**Category:** Reconnaissance  
**Risk Level:** Informational  
**Tools:** minicom, screen, Python pyserial  

```bash
# Connect to AT port
minicom -D /dev/ttyUSB2 -b 115200

# Basic enumeration commands:
AT              # Check interface alive → OK
ATI             # Manufacturer info
AT+GMR          # Firmware revision
AT+CGMI         # Manufacturer ID
AT+CGMM         # Model ID
AT+CGMR         # Firmware revision
AT+CGSN         # IMEI
AT+CIMI         # IMSI (requires SIM)
AT+ICCID        # ICCID
AT+CREG?        # Network registration status
AT+COPS?        # Operator info
AT+CSQ          # Signal quality
AT+QNWINFO      # Quectel: network info
AT+QGMR         # Quectel: firmware version (detailed)
AT+QCFG=?       # List all Quectel config options

# Security relevant:
AT+CLCK="SC",2  # Check SIM PIN lock status
AT+CLCK="FD",2  # Check Fixed Dialing Number lock
AT+CPWD=?       # Check available password types
AT+QSECBOOT?    # Quectel: Secure Boot status
```

---

#### TC-AT-02: PIN Protection Testing

**Category:** Access Control  
**Risk Level:** High  

```bash
# Check PIN status
AT+CPIN?
# +CPIN: READY     → SIM unlocked (no PIN or already entered)
# +CPIN: SIM PIN   → PIN required
# +CPIN: SIM PUK   → PUK required (PIN locked)

# Test PIN enforcement:
# 1. Set a PIN
AT+CLCK="SC",1,"0000"   # Enable SIM PIN lock with PIN=0000
AT+CFUN=0               # Power off
AT+CFUN=1               # Power on
AT+CPIN?                # Should now require PIN

# 2. Test PIN bypass attempts
AT+CPIN=""              # Empty PIN → should fail
AT+CPIN="0000"          # Correct PIN

# 3. Test brute force protection (PUK after 3 wrong attempts)
AT+CPIN="9999"          # Wrong 1
AT+CPIN="8888"          # Wrong 2
AT+CPIN="7777"          # Wrong 3 → Module should lock SIM

# Expected: AT+CPIN? → +CPIN: SIM PUK (locked after 3 attempts)

# Vulnerability: Some IoT deployments disable SIM PIN entirely
# Check via: AT+CLCK="SC",2 → 0 = disabled (vulnerability)
```

---

#### TC-AT-03: SIM Access Command Testing

**Category:** SIM Security  
**Risk Level:** High  

```bash
# AT+CSIM: Generic SIM access (APDU level)
# AT+CRSM: Restricted SIM access

# Read IMSI from SIM filesystem
AT+CRSM=176,28423,0,0,9  
# 176 = READ BINARY, 28423 = EF.IMSI (6F07), 9 bytes

# Read SIM service table
AT+CRSM=176,28542,0,0,16
# 28542 = EF.SST (6F38)

# Test: Can arbitrary APDU be sent?
AT+CSIM=14,"A0B00000090000000000000000"
# If unguarded, attacker with physical access can:
# - Read encryption keys (Kc)
# - Clone SIM parameters
# - Modify phonebook/SMS entries

# Check USIM authentication (test AKA):
# APDU for AUTHENTICATE command
AT+CSIM=44,"008800812110<RAND_32HEX>1016<AUTN_32HEX>"

# Expected: Authentication response (SRES, Kc) or SYNC_FAILURE
```

---

#### TC-AT-04: AT Command Injection / Fuzzing

**Category:** Input Validation  
**Risk Level:** Medium-High  

```python
#!/usr/bin/env python3
"""
AT Command Fuzzer for Quectel Modules
Authorized testing only.
"""
import serial
import time
import itertools

DEVICE = "/dev/ttyUSB2"
BAUDRATE = 115200
TIMEOUT = 2

# Fuzz payloads
FUZZ_PAYLOADS = [
    "A" * 1024,                    # Buffer overflow
    "A" * 4096,                    # Large buffer overflow
    "%s%s%s%s%s%s%s%s%s%s",        # Format string
    "\x00\x01\x02\x03\x04\x05",    # Binary injection
    "$(reboot)",                    # Command injection
    "'; DROP TABLE users; --",      # SQL-like injection
    "\r\nAT+CIMI\r\n",              # CRLF injection
    "AT" + "+"*100,                 # Excessive special chars
    "\xff\xfe" * 100,               # Unicode/encoding
]

# AT commands to fuzz
COMMANDS_TO_FUZZ = [
    "AT+COPS=0,0,",
    "AT+CGDCONT=1,\"IP\",",
    "AT+QCFG=\"nwscanmode\",",
    "AT+CLCK=\"SC\",0,",
    "AT+CPWD=\"SC\",\"0000\",",
    "AT+QFTP=\"PUT\",",
]

def send_at(port, cmd, timeout=TIMEOUT):
    port.write((cmd + "\r\n").encode())
    time.sleep(timeout)
    resp = port.read_all().decode(errors="replace")
    return resp

def fuzz():
    with serial.Serial(DEVICE, BAUDRATE, timeout=TIMEOUT) as port:
        for base_cmd in COMMANDS_TO_FUZZ:
            for payload in FUZZ_PAYLOADS:
                full_cmd = base_cmd + payload
                resp = send_at(port, full_cmd)
                
                # Detect anomalies
                if "REBOOT" in resp.upper() or "CRASH" in resp.upper():
                    print(f"[CRASH] Cmd: {full_cmd[:100]}")
                elif resp == "" and len(full_cmd) > 100:
                    print(f"[TIMEOUT] Possible hang: {full_cmd[:100]}")
                elif "ERROR" not in resp and "OK" not in resp:
                    print(f"[UNEXPECTED] Cmd: {full_cmd[:100]} → {resp[:100]}")

if __name__ == "__main__":
    print("AT Command Fuzzer - Authorized Testing Only")
    fuzz()
```

---

#### TC-AT-05: Quectel File System Access (QFTP / EFS)

**Category:** Data Security  
**Risk Level:** High  

```bash
# Quectel modules expose an embedded filesystem via AT commands
# (Useful for storing certificates, scripts, configs)

# List files in UFS (User File System)
AT+QFLST="*"              # List all files
AT+QFLST="*.pem"          # List certificates

# Read file content
AT+QFDWL="config.txt"     # Download file from module

# Write file (potential for malicious config)
AT+QFUPL="evil.cfg",100,10  # Upload 100-byte file, 10s timeout
# Then send file data

# Delete file
AT+QFDEL="config.txt"

# Security test: Can arbitrary files be read?
AT+QFDWL="/security/certs/root.pem"    # CA certificate
AT+QFDWL="/nvram/imei"                 # IMEI storage

# Check for sensitive files:
AT+QFLST="*.key"    # Private keys
AT+QFLST="*.pem"    # Certificates
AT+QFLST="*.cfg"    # Configuration files (may contain credentials)

# Vulnerability: If APN credentials stored in module filesystem
# without encryption, physical access = credential theft
```

---

#### TC-AT-06: Quectel MQTT/HTTP Client Security

**Category:** Application Protocol Security  
**Risk Level:** High  

```bash
# Quectel modules have built-in MQTT and HTTP clients
# Test TLS validation:

# HTTP client (should use HTTPS)
AT+QHTTPCFG="contextid",1
AT+QHTTPCFG="sslctxid",1
AT+QHTTPCFG="contenttype",0

# Test: Does module validate TLS certificate?
AT+QHTTPCFG="sslctxid",1
AT+QSSLCFG="sslversion",1,4    # TLS 1.2 minimum
AT+QSSLCFG="ciphersuite",1,0xFFFF  # All ciphers
AT+QSSLCFG="seclevel",1,2      # 2 = verify server cert (PASS)
AT+QSSLCFG="seclevel",1,0      # 0 = no verification (FAIL = vulnerable!)

# MQTT client
AT+QMTOPEN=0,"broker.example.com",8883  # Should be TLS port 8883
AT+QMTCONN=0,"client_id","user","pass"  # Check: credentials in plaintext?

# Vulnerability: Default seclevel=0 (no cert validation) in many IoT deployments
# = susceptible to MITM attacks
```

---

## 11. Firmware & Supply Chain Security

### 11.1 Firmware Analysis

```bash
# Extract Quectel firmware (from update file or dump)
# Quectel firmware files typically: *.zip containing .img / .mbn files

# Identify file format
file firmware.img
binwalk firmware.img

# Extract filesystem
binwalk -e firmware.img
# or
dd if=firmware.img of=extracted.bin bs=1 skip=<offset>

# Look for:
strings firmware.img | grep -i "password\|key\|secret\|token\|api_key"
strings firmware.img | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"  # IP addresses
strings firmware.img | grep -i "http\|ftp\|mqtt"  # Endpoints

# Check for hardcoded credentials:
grep -r "admin\|root\|password" extracted/ 2>/dev/null

# Analyze Qualcomm MBN (Modem Binary) files:
# GitHub: https://github.com/andychu666/mbn-mcfg-tools
git clone https://github.com/mobile-atlas/mbn-mcfg-tools.git
python3 mbn_mcfg_tools.py parse <file>.mbn
```

### 11.2 Secure Boot Verification

```bash
# Check Quectel Secure Boot status via AT
AT+QSECBOOT?
# +QSECBOOT: 1  → Secure Boot enabled (PASS)
# +QSECBOOT: 0  → Secure Boot disabled (FAIL - firmware can be replaced)

# Check firmware signature
AT+QGMR   # Get firmware version
# Verify against Quectel's official release notes

# Test FOTA (Firmware Over The Air) security:
# Is FOTA server authenticated?
# Is firmware download over HTTPS?
# Is firmware signature verified before flashing?
AT+QFOTADL="http://example.com/firmware.zip"
# → Should FAIL if not HTTPS and not signed
```

### 11.3 NVRAM / Configuration Security

```bash
# Qualcomm NVRAM stores sensitive configuration
# QCSuper can read NVRAM items (Diag port)

sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 --nvitem-read 550
# NV item 550 = IMEI

# Test: Are NVRAM items protected?
# Diag port should require authentication in production devices
# Many Quectel modules expose Diag without authentication = vulnerability

# Reading NVRAM via AT (if supported):
AT+QNVFR="/nv/item_files/modem/mmode/sms_domain_pref"

# Secure configuration items to check:
# - IMEI changeability (should be locked)
# - Network lock (SIM lock)  
# - Debug port enablement
```

---

## 12. SS7 / Diameter / GTP Protocol Testing

> **Note:** SS7 and Diameter attacks require access to the telecom signaling network (SS7 nodes). This is only applicable to authorized telecom operators, interconnect partners, and accredited testing labs. Unauthorized SS7 access is illegal worldwide.

### 12.1 SS7 MAP Attack Categories (Reference)

| Attack Type | MAP Operation | Impact | Mitigation |
|-------------|---------------|--------|------------|
| Location Tracking | SendRoutingInfo, AnyTimeInterrogation | User location | SS7 firewall |
| Call Interception | UpdateLocation + ProvideRoamingNumber | Call forwarding | Firewall + monitoring |
| SMS Interception | SendRoutingInfoForSM | SMS redirect | GSMA FS.11 |
| DoS | CancelLocation | Service denial | Rate limiting |
| Subscriber Profiling | InsertSubscriberData | Data disclosure | Firewall rules |

### 12.2 SiGploit Test Framework

```bash
# SiGploit: https://github.com/SigPloiter/SigPloit

cd SigPloit
python3 sigploit.py

# Available test modules (authorized lab use):
# 1. SS7
#    - Location tracking via SRI
#    - IMSI disclosure
#    - Call redirection
# 2. Diameter (LTE S6a/Gx/Gy)
#    - AIR/AIA spoofing
#    - PUR manipulation
#    - CLR injection
# 3. GTP
#    - Create Session Request injection
#    - GTP flooding
# 4. SIP/IMS
#    - Register spoofing
#    - INVITE flooding

# Example: Test HSS Diameter S6a interface (authorized telco lab)
# Configure in config.py:
# target_ip = "<HSS_IP>"
# target_port = 3868
# origin_host = "test.lab.local"
```

### 12.3 Diameter Testing (LTE Core)

```bash
# FreeDiameter: https://www.freediameter.net
# Purpose: Implement Diameter peers for testing

# Test S6a authentication:
# Send Authentication-Information-Request (AIR)
# with crafted IMSI → should return Authentication-Information-Answer (AIA)

# Python diameter test with pycrate:
from pycrate_mobile.NAS import *
from pycrate_diameter.Diameter import *

# Build AIR message
air = DiameterMsg()
air['Header']['Application-ID'].set_val(16777251)  # S6a
# Add AVPs: Session-Id, Auth-Application-Id, Destination-Host, etc.
```

---

## 13. Test Case Catalogue

### 13.1 Complete Test Case Index

| ID | Category | Generation | Title | Risk | Priority |
|----|----------|------------|-------|------|----------|
| TC-2G-01 | Recon | GSM | Cell Discovery & Passive Monitoring | Info | P3 |
| TC-2G-02 | Privacy | GSM | IMSI Harvesting via Paging | Medium | P2 |
| TC-2G-03 | Crypto | GSM | A5 Cipher Detection & Downgrade | High | P1 |
| TC-2G-04 | Auth | GSM | False Base Station Test | Critical | P1 |
| TC-2G-05 | Data | GPRS | GTP Security Assessment | Medium | P2 |
| TC-3G-01 | Recon | UMTS | UTRAN Interface Analysis | Medium | P2 |
| TC-3G-02 | Auth | UMTS | AKA Vector Testing | High | P1 |
| TC-3G-03 | Protocol | UMTS | 3G-to-2G Bidding Down | High | P1 |
| TC-4G-01 | Recon | LTE | LTE Cell Discovery & SIB Analysis | Info | P3 |
| TC-4G-02 | Crypto | LTE | NAS Security Mode Analysis | High | P1 |
| TC-4G-03 | Privacy | LTE | IMSI Leakage Detection | High | P1 |
| TC-4G-04 | Network | LTE | S1 Interface Security | High | P1 |
| TC-4G-05 | Data | LTE | GTP-U Integrity Test | Medium | P2 |
| TC-4G-06 | Voice | LTE | VoLTE/IMS Security | Medium | P2 |
| TC-AT-01 | Recon | All | AT Interface Enumeration | Info | P3 |
| TC-AT-02 | Auth | All | PIN Protection Testing | High | P1 |
| TC-AT-03 | SIM | All | SIM APDU Access Testing | High | P1 |
| TC-AT-04 | Fuzzing | All | AT Command Fuzzing | Medium | P2 |
| TC-AT-05 | Files | All | Module Filesystem Access | High | P1 |
| TC-AT-06 | AppSec | All | MQTT/HTTP TLS Validation | High | P1 |
| TC-FW-01 | Firmware | All | Firmware Analysis | High | P1 |
| TC-FW-02 | Boot | All | Secure Boot Verification | Critical | P1 |
| TC-FW-03 | Config | All | NVRAM Security | High | P1 |
| TC-SS7-01 | Signaling | 2G/3G | SS7 MAP Location Tracking | Critical | P1 |
| TC-SS7-02 | Signaling | 4G | Diameter S6a Testing | Critical | P1 |
| TC-SS7-03 | Data | All | GTP Protocol Testing | High | P1 |

### 13.2 Test Execution Checklist

```
Pre-Testing Checklist:
  □ Written authorization obtained and signed
  □ Scope clearly defined (which devices, frequencies, interfaces)
  □ Faraday cage / RF isolation verified (>60 dB attenuation)
  □ Legal review completed (country-specific regulations)
  □ Emergency stop procedure documented
  □ Test environment isolated from production
  □ Baseline capture taken (normal operation)
  □ All tools and versions documented

During Testing:
  □ All actions logged with timestamps
  □ PCAP captures saved for each test case
  □ Screenshots taken of tool output
  □ Unexpected behavior documented immediately
  □ No RF transmission outside Faraday cage
  □ No testing outside authorized scope

Post-Testing:
  □ All test configurations reverted
  □ Lab environment sanitized
  □ PCAP files encrypted and stored securely
  □ Raw findings documented before analysis
  □ CVE research for discovered vulnerabilities
  □ Draft report prepared within 5 business days
```

---

## 14. Reporting & Evidence Collection

### 14.1 Evidence Collection Standards

```bash
# 1. PCAP capture (all network traffic)
sudo tcpdump -i any -w evidence_$(date +%Y%m%d_%H%M%S).pcap

# 2. AT command session logs (minicom)
minicom -C /tmp/at_session_$(date +%Y%m%d_%H%M%S).log -D /dev/ttyUSB2 -b 115200

# 3. QCSuper logs
sudo ./qcsuper.py --usb-modem /dev/ttyUSB0 \
  --pcap-dump /tmp/qcsuper_$(date +%Y%m%d_%H%M%S).pcap

# 4. Screenshot with metadata
import-im6.q16 -window root screenshot_$(date +%Y%m%d_%H%M%S).png

# 5. Hash all evidence files
sha256sum evidence_*.pcap > evidence_hashes.txt

# 6. Encrypt sensitive captures
gpg --recipient <analyst@company.com> --encrypt evidence.pcap
```

### 14.2 Vulnerability Severity Classification (CVSS-based)

| Severity | CVSS Score | Examples |
|----------|-----------|---------|
| Critical | 9.0-10.0 | Unauthenticated firmware update, Secure Boot disabled, remote command injection |
| High | 7.0-8.9 | Cleartext credentials, IMSI exposure, cipher downgrade possible |
| Medium | 4.0-6.9 | Information disclosure, weak PIN, unencrypted local traffic |
| Low | 0.1-3.9 | Verbose error messages, deprecated algorithms (still functional) |
| Informational | N/A | Configuration notes, hardening recommendations |

### 14.3 Report Structure Template

```markdown
# Cellular Module Penetration Test Report

## Executive Summary
- Engagement scope
- Key findings (count by severity)
- Risk rating
- Top 3 recommendations

## Methodology
- Standards: GSMA NESAS, 3GPP TS 33.102/33.401
- Testing phases: Recon → Scanning → Exploitation → Reporting

## Findings

### FINDING-001: [Title]
- **Severity:** Critical / High / Medium / Low
- **CVSS Score:** X.X (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Affected Component:** [Module/Interface/Protocol]
- **Description:** [Detailed description]
- **Evidence:** [PCAP reference, screenshot, AT log]
- **Reproduction Steps:** [Step by step]
- **Impact:** [Business/security impact]
- **Recommendation:** [Specific remediation]
- **References:** [CVE/GSMA/3GPP standard]

## Conclusion
## Appendices: Raw tool output, PCAP extracts
```

---

## 15. Defensive Mitigations

### 15.1 Quectel Module Hardening Checklist

```
Hardware Security:
  □ Enable Secure Boot (AT+QSECBOOT)
  □ Physically secure Diag/UART ports (epoxy, case)
  □ Disable unused USB interfaces (QCDM port if not needed)
  □ Enable SIM PIN lock on all deployed devices
  □ Store device private keys in TrustZone (hardware security)

AT Command Security:
  □ Disable AT access if not required in production
  □ Rate-limit AT commands on application MCU
  □ Validate all AT command responses (don't trust blindly)
  □ Use allowlist of permitted AT commands

Network Security:
  □ Use SIM-lock to authorized PLMNs only
  □ Prefer LTE-only mode (disable 2G/3G fallback if possible)
  □ Enable NAS ciphering (EEA2 AES preferred)
  □ Enable NAS integrity (EIA2 AES preferred)

Application Security:
  □ TLS certificate validation enforced (seclevel=2)
  □ Use certificate pinning for MQTT/HTTPS
  □ Minimum TLS 1.2 (TLS 1.3 preferred)
  □ Rotate APN credentials regularly
  □ Never hardcode credentials in firmware

Firmware:
  □ Signed firmware updates only
  □ FOTA over HTTPS with certificate validation
  □ Regular firmware updates (subscribe to Quectel security advisories)
  □ Disable debug interfaces before production deployment
```

### 15.2 Network Operator Mitigations

```
Radio Access Network:
  □ Enforce A5/3 (GSM) / KASUMI (3G) / AES (4G) encryption
  □ Disable A5/0 (null cipher) 
  □ Enable EIA2 (AES-CMAC) NAS integrity in LTE
  □ Implement 5G SA for SUCI identity protection

Core Network:
  □ Deploy SS7 Firewall (GSMA FS.11 compliant)
  □ Deploy Diameter Firewall (FS.19)
  □ Deploy GTP Firewall (FS.20)
  □ Enable S1AP TLS/IPsec (TS 33.401)
  □ Implement network anomaly detection

Monitoring:
  □ Real-time IMSI catcher detection
  □ Abnormal paging pattern detection
  □ SS7 MAP message anomaly detection
  □ Log all NAS Attach/Detach events
```

---

## 16. Reference Resources

### 16.1 Key GitHub Repositories

| Repository | URL | Purpose |
|------------|-----|---------|
| Awesome-Cellular-Hacking | https://github.com/W00t3k/Awesome-Cellular-Hacking | Curated resource list |
| srsRAN 4G | https://github.com/srsran/srsRAN_4G | LTE/4G software stack |
| Open5GS | https://github.com/open5gs/open5gs | 4G/5G core network |
| QCSuper | https://github.com/P1sec/QCSuper | Qualcomm diagnostic capture |
| SCAT | https://github.com/fgsect/scat | Baseband diagnostic parser |
| gr-gsm | https://github.com/ptrkrysik/gr-gsm | GSM decoding |
| SiGploit | https://github.com/SigPloiter/SigPloit | Telecom signaling pentest |
| pySim | https://github.com/osmocom/pysim | SIM card tools |
| LTESniffer | https://github.com/SysSec-KAIST/LTESniffer | LTE passive sniffer |
| 5GBaseChecker | https://github.com/SyNSec-den/5GBaseChecker | 5G baseband security |
| kalibrate-rtl | https://github.com/steve-m/kalibrate-rtl | SDR frequency calibration |
| awesome-telco | https://github.com/ravens/awesome-telco | Curated telco tools |
| boofuzz | https://github.com/jtpereyda/boofuzz | Protocol fuzzing |
| OsmocomBB | https://osmocom.org/projects/baseband | GSM baseband OS |

### 16.2 Key Standards Documents

| Standard | Title | Relevance |
|----------|-------|-----------|
| 3GPP TS 33.102 | Security Architecture (3G) | UMTS security |
| 3GPP TS 33.401 | SAE Security Architecture (4G) | LTE security |
| 3GPP TS 33.501 | Security Architecture (5G) | 5G security |
| 3GPP TS 24.301 | NAS Protocol for EPS | LTE NAS messages |
| 3GPP TS 36.331 | RRC Protocol | LTE RRC messages |
| GSMA FS.11 | SS7 Security Baseline | SS7 firewall requirements |
| GSMA FS.19 | Diameter Roaming Security | Diameter security |
| GSMA FS.20 | GTP Security | GPRS tunneling security |
| GSMA NESAS | Network Equipment Security Assurance | Device security testing |
| NIST SP 800-187 | 4G LTE Cybersecurity Guide | LTE hardening |

### 16.3 Learning Resources

- **Online Courses:** 
  - SANS SEC617 (Wireless Ethical Hacking)
  - Hak5 SDR YouTube channel
  - TechMinds YouTube (SDR tutorials)
  
- **Research Papers:**
  - "LTE Security Disabled - Misconfiguration in Commercial Networks" (NDSS 2019)
  - "Touching the Untouchables: Dynamic Security Analysis of the LTE Control Plane" (IEEE S&P 2019)
  - "IMSI Catchers in the Wild: A Real World 4G/5G Assessment" (ScienceDirect 2021)
  - "Logic Gone Astray: Security Analysis of 5G Basebands" (USENIX 2024)

- **Communities:**
  - r/RTLSDR (Reddit)
  - Osmocom mailing lists
  - DEF CON Wireless Village
  - Black Hat Arsenal (cellular tools)

### 16.4 Legal Frameworks by Country

| Country | Primary Legislation | Regulator |
|---------|---------------------|-----------|
| India | Indian Wireless Telegraphy Act 1933, IT Act 2000, Telecom Act 2023 | DoT, TRAI |
| USA | CFAA, ECPA, FCC regulations (47 CFR) | FCC, DOJ |
| UK | Computer Misuse Act, Wireless Telegraphy Act 2006 | Ofcom |
| EU | GDPR, NIS2 Directive, national telecoms laws | BEREC, national regulators |
| Germany | Telekommunikationsgesetz (TKG), StGB §202a | BNetzA |

---

## Appendix A: Quick Reference – Quectel AT Commands for Security Testing

```
=== Identity & Registration ===
AT+CGSN         → IMEI
AT+CIMI         → IMSI
AT+ICCID        → ICCID
AT+CREG?        → GSM registration
AT+CEREG?       → LTE registration  
AT+COPS?        → Operator + access technology
AT+QNWINFO      → Network type, band, ARFCN

=== Security ===
AT+CPIN?        → SIM PIN status
AT+CLCK="SC",2  → SIM PIN lock query
AT+QSECBOOT?    → Secure Boot status
AT+QCFG="nwscanmode",?  → Network scan mode

=== Modem Mode Control ===
AT+QCFG="nwscanmode",0  → Auto (all)
AT+QCFG="nwscanmode",1  → GSM only
AT+QCFG="nwscanmode",2  → UMTS only  
AT+QCFG="nwscanmode",3  → LTE only
AT+CFUN=0               → Minimum functionality
AT+CFUN=1               → Full functionality

=== Diagnostics ===
AT+CSQ          → RSSI signal quality
AT+QRSRP        → LTE RSRP
AT+QSINR        → LTE SINR
AT+QTEMP        → Module temperature
AT+QGDCNT?      → Data counter

=== TLS/SSL Configuration ===
AT+QSSLCFG="seclevel",<n>,0  → No verification (vulnerable!)
AT+QSSLCFG="seclevel",<n>,2  → Full cert verification (secure)
AT+QSSLCFG="sslversion",<n>,4 → TLS 1.2 minimum
```

---

## Appendix B: Environment Variables for Scripts

```bash
# Create ~/.pentest_cellular_env
export QUECTEL_AT_PORT="/dev/ttyUSB2"
export QUECTEL_DIAG_PORT="/dev/ttyUSB0"
export QUECTEL_BAUDRATE="115200"
export SDR_DEVICE="uhd"                    # or "lime", "bladerf"
export SDR_ARGS="num_recv_frames=512"
export CAPTURE_DIR="/tmp/cellular_captures"
export LAB_MME_IP="127.0.1.1"
export LAB_ENB_IP="127.0.1.2"
export TEST_IMSI="001010000000001"          # Test IMSI (not real)
export TEST_KEY="465B5CE8B199B49FAA5F0A2EE238A6BC"  # Test K (not real)

# Source before testing:
source ~/.pentest_cellular_env
mkdir -p $CAPTURE_DIR
```

---

*Last Updated: March 2026 | Maintained for educational and authorized security research purposes only.*  
*All testing must comply with applicable laws and regulations. Obtain written authorization before any testing.*
