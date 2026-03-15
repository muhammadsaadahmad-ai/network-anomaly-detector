import numpy as np
import pickle, os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sklearn.ensemble import IsolationForest
from database.traffic_models import Session, TrafficRecord
from capture.features import features_to_vector
from config2 import ISOLATION_CONTAMINATION
from rich.console import Console

console  = Console()
MODEL_PATH = "ml/model.pkl"

def train_model():
    """Train Isolation Forest on stored traffic data."""
    session = Session()
    records = session.query(TrafficRecord).all()
    session.close()

    if len(records) < 50:
        console.print("[yellow][!] Need at least 50 packets to train. "
                      "Run capture first.[/yellow]")
        return None

    console.print(f"[cyan][*] Training on {len(records)} traffic records...[/cyan]")

    vectors = []
    for r in records:
        v = [
            r.packet_size or 0,
            r.src_port    or 0,
            r.dst_port    or 0,
            64,           # default TTL placeholder
            1 if r.protocol == "TCP"  else 0,
            1 if r.protocol == "UDP"  else 0,
            1 if r.protocol == "ICMP" else 0,
            1 if r.flags and "S" in r.flags else 0,
            1 if r.flags and "A" in r.flags else 0,
            1 if r.flags and "F" in r.flags else 0,
            1 if r.flags and "R" in r.flags else 0,
            1 if r.flags and "P" in r.flags else 0,
        ]
        vectors.append(v)

    X = np.array(vectors)
    model = IsolationForest(
        contamination=ISOLATION_CONTAMINATION,
        random_state=42,
        n_estimators=100
    )
    model.fit(X)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    console.print(f"[green][+] Model trained and saved to {MODEL_PATH}[/green]")
    console.print(f"    Contamination rate: {ISOLATION_CONTAMINATION*100:.0f}%")
    console.print(f"    Estimators: 100")
    return model

def load_model():
    if not os.path.exists(MODEL_PATH):
        return None
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)
