import sys, os, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import sniff, IP, get_if_list
from capture.features import extract_features
from database.traffic_models import Session, TrafficRecord
from config2 import CAPTURE_INTERFACE, PACKET_LIMIT
from rich.console import Console

console = Console()

def get_interface():
    if CAPTURE_INTERFACE:
        return CAPTURE_INTERFACE
    ifaces = [i for i in get_if_list() if i != "lo"]
    return ifaces[0] if ifaces else "eth0"

def capture_and_store(packet_limit=PACKET_LIMIT, iface=None):
    """Capture live packets and store features in the database."""
    if iface is None:
        iface = get_interface()

    console.print(f"[cyan][*] Capturing on interface: {iface} "
                  f"(limit: {packet_limit} packets)[/cyan]")
    console.print("[dim]    Press Ctrl+C to stop early[/dim]")

    captured = []

    def handle_packet(pkt):
        if IP not in pkt:
            return
        features = extract_features(pkt)
        captured.append(features)

        # Save to DB in batches of 50
        if len(captured) % 50 == 0:
            _flush_to_db(captured[-50:])
            console.print(f"  [green][+] {len(captured)} packets captured...[/green]")

    try:
        sniff(iface=iface, prn=handle_packet,
              count=packet_limit, store=False, timeout=60)
    except PermissionError:
        console.print("[red][-] Permission denied. Run with sudo:[/red]")
        console.print("[yellow]    sudo python3 main2.py[/yellow]")
        return []
    except Exception as e:
        console.print(f"[red][-] Capture error: {e}[/red]")

    # Flush remaining
    remainder = len(captured) % 50
    if remainder:
        _flush_to_db(captured[-remainder:])

    console.print(f"[green][+] Capture complete: {len(captured)} packets saved.[/green]")
    return captured

def _flush_to_db(features_list):
    session = Session()
    for f in features_list:
        record = TrafficRecord(
            src_ip      = f["src_ip"],
            dst_ip      = f["dst_ip"],
            src_port    = f["src_port"],
            dst_port    = f["dst_port"],
            protocol    = f["protocol"],
            packet_size = f["packet_size"],
            flags       = f["flags"],
        )
        session.add(record)
    session.commit()
    session.close()
