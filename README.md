# NetWatch — Network Anomaly Detection System
### Cyber Intelligence Portfolio · Phase 2 of 4

![Python](https://img.shields.io/badge/Python-3.10+-00ffee?style=flat-square&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.x-00c8bc?style=flat-square)
![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-aa00ff?style=flat-square&logo=scikitlearn&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-00c832?style=flat-square&logo=flask&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Platform-Kali%20Linux-268bd2?style=flat-square&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-007a75?style=flat-square)

---

## Overview

**NetWatch** is a real-time network anomaly detection system that captures live
traffic, extracts packet features, and runs three parallel detection engines —
a machine learning Isolation Forest model, a statistical Z-score analyser, and
a signature-based port scan detector. Alerts are stored in SQLite and rendered
on a military-aesthetic live dashboard.

This is **Phase 2** of a 4-phase cyber portfolio project targeting a career in
Army Intelligence / Military Cyber Operations.

> Successfully detected a live nmap port scan (101 ports, 5 hosts) and 15 ML
> anomalies from 296 captured packets in initial testing on Kali Linux.

---

## What It Does

| Capability | Description |
|---|---|
| **Live packet capture** | Scapy-based sniffer on any network interface |
| **Feature extraction** | 12 numeric features per packet: size, ports, TTL, TCP flags |
| **Isolation Forest** | Unsupervised ML model flags statistical outliers in traffic |
| **Z-score detection** | Flags packets with size > 3 std deviations from session mean |
| **Port scan detection** | Detects any source IP probing 15+ unique ports |
| **Alert engine** | Classifies every finding as HIGH / MEDIUM / LOW |
| **Live dashboard** | Cyan-on-black Flask UI at port 5001, live alert feed |
| **REST API** | `/api/alerts` returns JSON for external consumers |

---

## Live Detection Results

From initial test run on Kali Linux:

```
Total alerts    : 17
High severity   : 1   → port scan (nmap -p 1-100 scanme.nmap.org)
ML anomalies    : 15  → Isolation Forest detections
Packets captured: 296 → wlan0 interface, mixed traffic
```

The system correctly identified a deliberate nmap scan as a HIGH severity
port scan — 101 unique ports probed across 5 hosts.

---

## Project Structure

```
network-anomaly-detector/
│
├── capture/
│   ├── sniffer.py         # Live packet capture via Scapy
│   └── features.py        # 12-feature extractor from raw packets
│
├── ml/
│   ├── trainer.py         # Trains Isolation Forest on captured data
│   └── detector.py        # Runs all 3 detection engines in sequence
│
├── alerts/
│   └── engine.py          # Alert creation and DB persistence
│
├── dashboard2/
│   └── app.py             # Flask dashboard + /api/alerts REST endpoint
│
├── database/
│   └── traffic_models.py  # SQLAlchemy models: TrafficRecord, Alert
│
├── main2.py               # CLI menu — capture / train / detect / dashboard
├── config2.py             # Central config: thresholds, interface, DB URL
└── .env                   # Secrets (never committed)
```

---

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/muhammadsaadahmad-ai/network-anomaly-detector.git
cd network-anomaly-detector
sudo pip install -r requirements.txt --break-system-packages
```

### 2. Set your network interface

```bash
ip link show   # find your active interface
nano config2.py
# set CAPTURE_INTERFACE = "wlan0"
```

### 3. Run

```bash
sudo python3 main2.py
```

Choose option `[5]` for full pipeline. Then open `http://127.0.0.1:5001`.

### 4. Generate interesting traffic while capturing

```bash
ping -c 30 8.8.8.8 &
curl google.com &
sudo nmap -p 1-100 scanme.nmap.org   # triggers port scan alert
```

---

## Detection Engines

### 1. Isolation Forest (ML)
Unsupervised anomaly detection trained on captured traffic vectors.
Packets scoring below the contamination threshold (default 5%) are flagged
as medium-severity ML anomalies with exact anomaly scores in the description.

### 2. Z-Score Statistical Detection
Calculates mean and standard deviation of packet sizes across the capture
session. Packets beyond 3 standard deviations from the mean are flagged.
Effective for detecting flood attacks and oversized payload anomalies.

### 3. Port Scan Signature Detection
Tracks unique destination ports per source IP. Any source exceeding 15 unique
ports within the capture window is immediately flagged as HIGH severity with
the full port list included in the alert description.

---

## Feature Vector (12 dimensions)

| Feature | Description |
|---|---|
| `packet_size` | Total packet size in bytes |
| `src_port` | Source port number |
| `dst_port` | Destination port number |
| `ttl` | IP Time-To-Live value |
| `is_tcp` | Binary: TCP protocol |
| `is_udp` | Binary: UDP protocol |
| `is_icmp` | Binary: ICMP protocol |
| `flag_syn` | TCP SYN flag |
| `flag_ack` | TCP ACK flag |
| `flag_fin` | TCP FIN flag |
| `flag_rst` | TCP RST flag |
| `flag_psh` | TCP PSH flag |

---

## API Reference

### `GET /api/alerts`

```json
[
  {
    "type": "port_scan",
    "src": "192.168.1.212",
    "dst": "5 hosts",
    "port": 0,
    "severity": "high",
    "desc": "Port scan detected: 192.168.1.212 probed 101 unique ports...",
    "time": "2026-03-15 18:43:54"
  }
]
```

---

## Configuration

| Parameter | Default | Description |
|---|---|---|
| `CAPTURE_INTERFACE` | `"wlan0"` | Network interface to sniff |
| `PACKET_LIMIT` | `500` | Max packets per capture batch |
| `ISOLATION_CONTAMINATION` | `0.05` | Fraction of traffic flagged as anomalous |
| `ZSCORE_THRESHOLD` | `3.0` | Standard deviations threshold |
| `PORT_SCAN_THRESHOLD` | `15` | Unique ports before scan alert fires |

---

## Roadmap

- [x] **Phase 1** — OSINT + Threat Intelligence Platform
- [x] **Phase 2** — Network Anomaly Detection System *(this repo)*
- [ ] **Phase 3** — Red Team Automation Toolkit *(private repo)*
- [ ] **Phase 4** — Integrated Cyber Intel & Ops Platform (capstone)

---

## Legal & Ethical Notice

Captures traffic only on interfaces you own or have permission to monitor.
The nmap test target (`scanme.nmap.org`) is a publicly designated test host
provided by the nmap project for this exact purpose. Do not capture on
networks you do not own or administer.

---

## Author

**Muhammad Saad Ahmad**
Cybersecurity Student · Aspiring Army Intelligence Cyber Analyst
GitHub: [@muhammadsaadahmad-ai](https://github.com/muhammadsaadahmad-ai)

---

*"The best defence is knowing the attack before it completes."*
