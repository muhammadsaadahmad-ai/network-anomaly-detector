from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    console.print(Panel.fit(
        "[bold cyan]NetWatch — Network Anomaly Detection[/bold cyan]\n"
        "[dim]Army Intelligence Cyber Portfolio — Phase 2[/dim]",
        border_style="cyan"
    ))

    from database.traffic_models import init_db
    init_db()

    console.print("\n[bold yellow]Select operation:[/bold yellow]")
    console.print("  [1] Capture live traffic (requires sudo)")
    console.print("  [2] Train ML model on captured data")
    console.print("  [3] Run anomaly detection")
    console.print("  [4] Launch dashboard (port 5001)")
    console.print("  [5] Full pipeline (capture → train → detect → dashboard)\n")

    choice = input("Enter choice [1-5]: ").strip()

    if choice in ["1", "5"]:
        try:
            limit = int(input("Packet limit (press Enter for 200): ").strip() or "200")
        except ValueError:
            limit = 200
        from capture.sniffer import capture_and_store
        capture_and_store(packet_limit=limit)

    if choice in ["2", "5"]:
        from ml.trainer import train_model
        train_model()

    if choice in ["3", "5"]:
        from ml.detector import run_detection
        run_detection()

    if choice in ["4", "5"]:
        console.print("\n[green][+] Dashboard at http://127.0.0.1:5001[/green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")
        from dashboard2.app import run_dashboard
        run_dashboard()

if __name__ == "__main__":
    main()
