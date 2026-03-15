import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.traffic_models import Session, Alert
from datetime import datetime

def create_alert(alert_type, src_ip, dst_ip, dst_port,
                 severity, description, packet_count=1):
    session = Session()
    alert   = Alert(
        alert_type   = alert_type,
        src_ip       = src_ip,
        dst_ip       = str(dst_ip),
        dst_port     = dst_port,
        severity     = severity,
        description  = description[:490],
        packet_count = packet_count,
    )
    session.add(alert)
    session.commit()
    session.close()
