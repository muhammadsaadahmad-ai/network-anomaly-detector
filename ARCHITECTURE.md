# Architecture — NetWatch Network Anomaly Detection System

## System Overview

NetWatch follows a **four-stage pipeline**: capture raw packets → extract
features → run detection engines → store and present alerts. Each stage is
a self-contained module that can be tested and replaced independently.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    NETWATCH — ANOMALY DETECTION                      │
│               Network Intelligence · Phase 2 · ML-Powered           │
└──────────────────────────────────────────────────────────────────────┘

  CAPTURE LAYER              FEATURE LAYER
  ──────────────             ─────────────────────────────
  ┌────────────┐             ┌──────────────────────────┐
  │   Scapy    │────────────▶│     Feature Extractor    │
  │  Sniffer   │             │                          │
  │            │             │  packet_size  src_port   │
  │  wlan0 /   │             │  dst_port     ttl        │
  │  eth0 /    │             │  is_tcp       is_udp     │
  │  any iface │             │  is_icmp      flag_syn   │
  └────────────┘             │  flag_ack     flag_fin   │
                             │  flag_rst     flag_psh   │
                             └────────────┬─────────────┘
                                          │
                             ┌────────────▼─────────────┐
                             │      Traffic DB           │
                             │   (SQLite via ORM)        │
                             │   TrafficRecord table     │
                             └────────────┬─────────────┘
                                          │
  DETECTION LAYER            ┌────────────▼─────────────┐
  ──────────────             │    Detection Orchestrator │
                             │      ml/detector.py       │
                             └──────┬──────┬──────┬──────┘
                                    │      │      │
                        ┌───────────▼┐ ┌───▼───┐ ┌▼──────────────┐
                        │ Isolation  │ │Z-Score│ │  Port Scan    │
                        │  Forest    │ │ Stat  │ │  Detector     │
                        │            │ │       │ │               │
                        │ Unsupervised│ │ Mean +│ │ Tracks unique │
                        │ ML model   │ │ Std   │ │ ports per IP  │
                        │ 100 trees  │ │ dev   │ │ threshold: 15 │
                        │ 5% contam. │ │ z > 3 │ │               │
                        └─────┬──────┘ └───┬───┘ └──────┬────────┘
                              │            │             │
                              └────────────▼─────────────┘
                                           │
  ALERT LAYER                ┌─────────────▼────────────┐
  ──────────────             │      Alert Engine         │
                             │    alerts/engine.py       │
                             │                           │
                             │  HIGH   → port_scan       │
                             │  MEDIUM → anomaly_ml      │
                             │  MEDIUM → anomaly_stat    │
                             │  LOW    → unusual_port    │
                             └─────────────┬────────────┘
                                           │
                             ┌─────────────▼────────────┐
                             │       Alerts DB           │
                             │   Alert table — SQLite    │
                             └──────┬──────────┬─────────┘
                                    │          │
  PRESENTATION LAYER     ┌──────────▼─┐  ┌─────▼──────────┐
  ──────────────────     │  Dashboard │  │   REST API     │
                         │  GET /     │  │  GET /api/     │
                         │  port 5001 │  │  alerts        │
                         │  HTML+CSS  │  │  JSON feed     │
                         └────────────┘  └────────────────┘
```

---

## Component Breakdown

### 1. Capture Layer (`capture/`)

#### `sniffer.py`
- Uses `scapy.sniff()` with an IP filter to ignore non-IP traffic
- Configurable interface via `CAPTURE_INTERFACE` in `config2.py`
- Flushes captured packets to SQLite in batches of 50 for memory efficiency
- Falls back gracefully on `PermissionError` with a clear sudo prompt
- Reports progress every 50 packets

#### `features.py`
- `extract_features(packet)` — returns a dict of all 12 features from a raw Scapy packet
- `features_to_vector(f)` — converts the dict to a flat numeric list for ML input
- Handles TCP, UDP, ICMP separately; unknown protocols get zeros for protocol-specific fields
- TCP flag extraction uses bitwise AND on the flags integer field

---

### 2. Storage Layer (`database/`)

#### `traffic_models.py`

```
TrafficRecord table
────────────────────────────────────────────────
id            INTEGER  PRIMARY KEY
timestamp     DATETIME Auto-set on insert
src_ip        TEXT     Source IP address
dst_ip        TEXT     Destination IP address
src_port      INTEGER  Source port
dst_port      INTEGER  Destination port
protocol      TEXT     TCP / UDP / ICMP / OTHER
packet_size   INTEGER  Total packet length in bytes
flags         TEXT     Raw TCP flags string
is_anomaly    BOOLEAN  Set to True by ML detector

Alert table
────────────────────────────────────────────────
id            INTEGER  PRIMARY KEY
timestamp     DATETIME Auto-set on insert
alert_type    TEXT     port_scan / anomaly_ml / anomaly_stat
src_ip        TEXT     Source of the suspicious traffic
dst_ip        TEXT     Destination (may be "N hosts" for port scan)
dst_port      INTEGER  Destination port (0 for port scans)
severity      TEXT     high / medium / low
description   TEXT     Human-readable explanation (max 490 chars)
packet_count  INTEGER  Number of packets in this alert
```

---

### 3. Detection Layer (`ml/`)

#### `trainer.py` — Isolation Forest Training

The Isolation Forest algorithm works by randomly partitioning the feature
space. Anomalous points — which are rare and different — require fewer
partitions to isolate. The anomaly score is the average path length across
all trees; short paths = anomalous.

Training parameters:
```
n_estimators    = 100     (number of trees)
contamination   = 0.05    (5% of data expected to be anomalous)
random_state    = 42      (reproducible results)
```

The trained model is serialised to `ml/model.pkl` via pickle. On subsequent
runs, the model is loaded from disk without retraining unless explicitly
triggered.

Minimum training requirement: 50 packets. Below this threshold the model
would have insufficient variance to be meaningful.

#### `detector.py` — Detection Orchestration

Runs three independent detectors in sequence on unanalysed traffic records:

**ML Detection (`_ml_detection`)**
- Loads or trains the Isolation Forest model
- Constructs a feature matrix from all unanalysed TrafficRecord rows
- Calls `model.predict()` — returns +1 (normal) or -1 (anomaly) per row
- Calls `model.decision_function()` — returns the raw anomaly score
- Marks anomalous records with `is_anomaly = True` in the DB
- Creates an Alert with the score embedded in the description

**Statistical Detection (`_statistical_detection`)**
- Computes `mean` and `std` of all packet sizes in the batch
- Calculates Z-score: `z = |size - mean| / std`
- Any packet with `z > ZSCORE_THRESHOLD` (default 3.0) creates an Alert
- Guards against zero standard deviation (all packets same size)

**Port Scan Detection (`_port_scan_detection`)**
- Builds a dict: `{ src_ip → set(dst_ports) }`
- Also tracks unique destination hosts per source
- Any source with `len(ports) >= PORT_SCAN_THRESHOLD` (default 15) fires HIGH alert
- Alert description includes the first 10 ports detected

---

### 4. Alert Layer (`alerts/`)

#### `engine.py`
- Single `create_alert()` function — all detectors call this
- Enforces 490-char description cap to prevent DB overflow
- Opens and closes its own SQLAlchemy session per call (thread-safe)

Severity mapping:
```
port_scan    → HIGH    (active reconnaissance)
anomaly_ml   → MEDIUM  (ML-flagged outlier)
anomaly_stat → MEDIUM  (statistical outlier)
unusual_port → LOW     (informational)
```

---

### 5. Presentation Layer (`dashboard2/`)

#### `app.py` — Flask Web Application

**Routes:**
```
GET /            → Full HTML dashboard (human-readable)
GET /api/alerts  → JSON feed of latest 50 alerts (machine-readable)
```

**Dashboard features:**
- Live UTC clock updating every second via JavaScript
- 4 stat cards: Total alerts / High severity / ML anomalies / Packets captured
- Alert feed table with type badges, severity badges, description column
- Cyan-on-black military terminal aesthetic (scanline, Orbitron font)
- Distinct badge colours: PORT SCAN (pink), ML ANOMALY (cyan), STAT (teal)
- Runs on port 5001 (separate from Phase 1 dashboard on 5000)

---

## Data Flow (Step by Step)

```
Step 1: sudo python3 main2.py → user selects option

Step 2: sniffer.py captures packets from wlan0
        └─ Scapy sniff() with IP filter
        └─ features.py extracts 12 numeric features per packet
        └─ TrafficRecord rows inserted in batches of 50

Step 3: trainer.py reads TrafficRecord table
        └─ Builds 12-dimensional feature matrix
        └─ Fits IsolationForest(n_estimators=100, contamination=0.05)
        └─ Saves model to ml/model.pkl

Step 4: detector.py loads model, reads unanalysed records
        └─ ML: predict() + decision_function() → anomaly flags
        └─ Stat: z-score on packet sizes → outlier flags
        └─ Port scan: port count per IP → scan flags
        └─ alerts/engine.py creates Alert rows for each finding

Step 5: Flask dashboard reads Alert table
        └─ Renders HTML with severity badges and descriptions
        └─ /api/alerts serves JSON for external integrations

Step 6: User opens http://127.0.0.1:5001
        └─ Sees live alert feed with real detections
```

---

## Security Considerations

- Requires `sudo` for packet capture — principle of least privilege
- Dashboard binds to `127.0.0.1` only — not exposed on the network
- `ml/model.pkl` is in `.gitignore` — binary blobs don't belong in git
- `database/*.db` excluded from git — contains potentially sensitive traffic data
- No user input reaches the database — all writes go through the ORM

---

## Performance Notes

- Batch flush of 50 packets minimises DB write overhead during capture
- Isolation Forest with 100 trees runs in under 1 second on 1000 records
- Flask runs in single-threaded mode — sufficient for local portfolio use
- For production: swap SQLite for PostgreSQL, add Celery for async detection

---

## Future Phases

| Phase | Project | Key Addition |
|---|---|---|
| Phase 3 | Red Team Toolkit | Recon automation, C2 simulation *(private)* |
| Phase 4 | Integrated Platform | Unified dashboard, threat hunting, tabletop sim |

---

## Author

Muhammad Saad Ahmad — Cybersecurity Student
Portfolio: [github.com/muhammadsaadahmad-ai](https://github.com/muhammadsaadahmad-ai)
