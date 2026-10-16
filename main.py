"""
Network Security Monitoring System
For defensive learning on localhost or an authorized private lab host only.

Features:
- Host reachability check
- Limited TCP port checks
- CSV report export
- Console summary

No exploit code, credential collection, or stealth scanning.
"""
import csv
import ipaddress
import socket
from datetime import datetime
from pathlib import Path

# A deliberately small list of common service ports.
DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
}

REPORT_DIR = Path("reports")
TIMEOUT_SECONDS = 0.6


def validate_authorized_target(target: str) -> str:
    """Accept localhost or an IP address in a private/loopback range only."""
    target = target.strip()

    if target.lower() in {"localhost"}:
        return "127.0.0.1"

    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(
            "Enter 'localhost' or a private/loopback IP address (for example 127.0.0.1 or 192.168.1.10)."
        ) from exc

    if not (ip.is_private or ip.is_loopback):
        raise ValueError(
            "For safety, this learning tool only checks private or loopback IP addresses."
        )
    return str(ip)


def check_host_reachability(target: str, port: int = 80) -> bool:
    """Try one short TCP connection to see if the host responds on a port."""
    try:
        with socket.create_connection((target, port), timeout=TIMEOUT_SECONDS):
            return True
    except (OSError, TimeoutError):
        return False


def check_tcp_port(target: str, port: int) -> dict:
    """Perform a single, time-limited TCP connection check."""
    service = DEFAULT_PORTS.get(port, "Unknown")
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        with socket.create_connection((target, port), timeout=TIMEOUT_SECONDS):
            status = "OPEN"
            details = "TCP connection succeeded; verify whether this service should be exposed."
    except ConnectionRefusedError:
        status = "CLOSED"
        details = "Host responded but refused the TCP connection."
    except (socket.timeout, TimeoutError):
        status = "NO RESPONSE"
        details = "Connection timed out; this does not prove the port is closed."
    except OSError as exc:
        status = "ERROR"
        details = f"Connection error: {exc.__class__.__name__}"

    return {
        "timestamp": timestamp,
        "target": target,
        "port": port,
        "service": service,
        "status": status,
        "details": details,
    }


def save_csv(rows: list[dict]) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    filename = REPORT_DIR / f"network_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    fieldnames = ["timestamp", "target", "port", "service", "status", "details"]
    with filename.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return filename


def main() -> None:
    print("=" * 58)
    print("      NETWORK SECURITY MONITORING SYSTEM")
    print("=" * 58)
    print("Use only on your own computer or a lab host you are authorized to test.")
    print("The tool accepts localhost or private/loopback IP addresses only.\n")

    raw_target = input("Target host [localhost]: ").strip() or "localhost"
    try:
        target = validate_authorized_target(raw_target)
    except ValueError as error:
        print(f"\nInput error: {error}")
        return

    print(f"\nTarget: {target}")
    print("\nChoose ports:")
    print("1. Common web ports (80, 443, 8080)")
    print("2. Selected common service ports")
    print("3. Enter a small custom list (max 10 ports)")
    choice = input("Choice [1]: ").strip() or "1"

    if choice == "1":
        ports = [80, 443, 8080]
    elif choice == "2":
        ports = sorted(DEFAULT_PORTS)
    elif choice == "3":
        raw = input("Enter port numbers separated by commas (example: 22,80,443): ")
        try:
            ports = sorted(set(int(part.strip()) for part in raw.split(",") if part.strip()))
        except ValueError:
            print("Invalid port list. Use numbers separated by commas.")
            return
        if not ports or len(ports) > 10:
            print("Enter between 1 and 10 ports.")
            return
        if any(port < 1 or port > 65535 for port in ports):
            print("Ports must be between 1 and 65535.")
            return
    else:
        print("Invalid choice.")
        return

    print("\nChecking TCP ports... (this may take a few seconds)\n")
    rows = []
    for port in ports:
        row = check_tcp_port(target, port)
        rows.append(row)
        print(f"{row['port']:>5}  {row['service']:<12} {row['status']:<12} {row['details']}")

    open_ports = [row for row in rows if row["status"] == "OPEN"]
    closed_ports = [row for row in rows if row["status"] == "CLOSED"]
    no_response = [row for row in rows if row["status"] == "NO RESPONSE"]

    print("\n" + "-" * 58)
    print("SUMMARY")
    print(f"Target checked : {target}")
    print(f"Ports checked  : {len(rows)}")
    print(f"Open           : {len(open_ports)}")
    print(f"Closed         : {len(closed_ports)}")
    print(f"No response    : {len(no_response)}")
    if open_ports:
        print("\nReview these open ports and confirm that each service is required:")
        for row in open_ports:
            print(f" - Port {row['port']} ({row['service']})")
    else:
        print("\nNo open ports were found in the selected list.")
    print("Note: results are limited observations, not a full security audit.")

    report = save_csv(rows)
    print(f"\nCSV report saved to: {report.resolve()}")


if __name__ == "__main__":
    main()
