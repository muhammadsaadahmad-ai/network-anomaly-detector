import os
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL     = "sqlite:///database/traffic.db"
CAPTURE_INTERFACE = "wlan0"          # None = auto-detect
CAPTURE_TIMEOUT   = 30            # seconds per capture batch
PACKET_LIMIT      = 500           # packets per batch

# Anomaly thresholds
ISOLATION_CONTAMINATION = 0.05    # 5% of traffic flagged as anomalous
ZSCORE_THRESHOLD        = 3.0     # standard deviations from mean
PORT_SCAN_THRESHOLD     = 15      # unique ports from one IP = port scan

ALERT_SEVERITIES = {
    "port_scan":    "high",
    "flood":        "high",
    "anomaly_ml":   "medium",
    "anomaly_stat": "medium",
    "unusual_port": "low",
}
