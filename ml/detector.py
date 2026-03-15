import numpy as np
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.trainer import load_model, train_model
from database.traffic_models import Session, TrafficRecord, Alert
from config2 import ZSCORE_THRESHOLD, PORT_SCAN_THRESHOLD, ALERT_SEVERITIES
from alerts.engine import create_alert
from rich.console import Console
from collections import defaultdict

console = Console()

def run_detection():
    """Run all detection methods on stored traffic."""
    console.print("[cyan][*] Running anomaly detection...[/cyan]")

    session   = Session()
    records   = session.query(TrafficRecord)\
                       .filter_by(is_anomaly=False)\
                       .order_by(TrafficRecord.timestamp.desc())\
                       .limit(1000).all()
    session.close()

    if not records:
        console.print("[yellow][!] No unanalyzed traffic records found.[/yellow]")
        return

    alerts_created = 0
    alerts_created += _ml_detection(records)
    alerts_created += _port_scan_detection(records)
    alerts_created += _statistical_detection(records)

    console.print(f"[green][+] Detection complete. {alerts_created} alerts generated.[/green]")

def _ml_detection(records):
    """Isolation Forest anomaly detection."""
    model = load_model()
    if model is None:
        console.print("[yellow][!] No trained model found. Training now...[/yellow]")
        model = train_model()
        if model is None:
            return 0

    vectors = []
    for r in records:
        v = [
            r.packet_size or 0, r.src_port or 0, r.dst_port or 0, 64,
            1 if r.protocol=="TCP"  else 0,
            1 if r.protocol=="UDP"  else 0,
            1 if r.protocol=="ICMP" else 0,
            1 if r.flags and "S" in r.flags else 0,
            1 if r.flags and "A" in r.flags else 0,
            1 if r.flags and "F" in r.flags else 0,
            1 if r.flags and "R" in r.flags else 0,
            1 if r.flags and "P" in r.flags else 0,
        ]
        vectors.append(v)

    X           = np.array(vectors)
    predictions = model.predict(X)   # -1 = anomaly, 1 = normal
    scores      = model.decision_function(X)

    session     = Session()
    alert_count = 0

    for i, (record, pred, score) in enumerate(zip(records, predictions, scores)):
        if pred == -1:
            record.is_anomaly = True
            create_alert(
                alert_type  = "anomaly_ml",
                src_ip      = record.src_ip,
                dst_ip      = record.dst_ip,
                dst_port    = record.dst_port,
                severity    = ALERT_SEVERITIES["anomaly_ml"],
                description = (f"ML anomaly detected (score: {score:.3f}) — "
                               f"{record.protocol} {record.src_ip}:{record.src_port} "
                               f"-> {record.dst_ip}:{record.dst_port} "
                               f"size={record.packet_size}b")
            )
            alert_count += 1

    session.commit()
    session.close()
    console.print(f"  [red][+] ML detector: {alert_count} anomalies[/red]")
    return alert_count

def _port_scan_detection(records):
    """Detect port scans: one IP hitting many ports."""
    src_to_ports = defaultdict(set)
    src_to_dsts  = defaultdict(set)

    for r in records:
        if r.src_ip and r.dst_port:
            src_to_ports[r.src_ip].add(r.dst_port)
            src_to_dsts[r.src_ip].add(r.dst_ip)

    alert_count = 0
    for src_ip, ports in src_to_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            create_alert(
                alert_type  = "port_scan",
                src_ip      = src_ip,
                dst_ip      = f"{len(src_to_dsts[src_ip])} hosts",
                dst_port    = 0,
                severity    = ALERT_SEVERITIES["port_scan"],
                description = (f"Port scan detected: {src_ip} probed "
                               f"{len(ports)} unique ports across "
                               f"{len(src_to_dsts[src_ip])} hosts. "
                               f"Ports: {sorted(list(ports))[:10]}...")
            )
            alert_count += 1

    console.print(f"  [red][+] Port scan detector: {alert_count} scans[/red]")
    return alert_count

def _statistical_detection(records):
    """Z-score detection on packet sizes."""
    sizes = np.array([r.packet_size for r in records if r.packet_size])
    if len(sizes) < 10:
        return 0

    mean  = np.mean(sizes)
    std   = np.std(sizes)
    if std == 0:
        return 0

    alert_count = 0
    for r in records:
        if not r.packet_size:
            continue
        z = abs((r.packet_size - mean) / std)
        if z > ZSCORE_THRESHOLD:
            create_alert(
                alert_type  = "anomaly_stat",
                src_ip      = r.src_ip,
                dst_ip      = r.dst_ip,
                dst_port    = r.dst_port,
                severity    = ALERT_SEVERITIES["anomaly_stat"],
                description = (f"Statistical anomaly: packet size {r.packet_size}b "
                               f"is {z:.1f} std devs from mean ({mean:.0f}b). "
                               f"Protocol: {r.protocol}")
            )
            alert_count += 1

    console.print(f"  [amber][+] Statistical detector: {alert_count} outliers[/amber]")
    return alert_count
