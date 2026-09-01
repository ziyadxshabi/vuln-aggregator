#!/usr/bin/env python3
"""
================================================================================
                    EDUCATIONAL PORT SCANNER - LEARNING EDITION
================================================================================

A comprehensive, well-commented port scanner designed for learning networking
and cybersecurity fundamentals.

⚠️  ETHICAL USE ONLY: Only scan systems you OWN or have EXPLICIT WRITTEN
   PERMISSION to test. Unauthorized scanning may violate laws.

WHAT YOU'LL LEARN FROM THIS CODE:
---------------------------------
1. TCP Three-Way Handshake (the foundation of connect scanning)
2. SYN Half-Open Scanning (raw packets with Scapy)
3. Service Banner Grabbing (identifying what's running on open ports)
4. Socket programming in Python
5. Multithreading for performance
6. Packet crafting with Scapy

================================================================================
"""

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. SYN scanning will be unavailable.")
    print("    Install with: pip install scapy")
    print("    TCP Connect scanning will still work.\n")


# ==============================================================================
# SECTION 1: TERMINAL COLORS
# ==============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def color(text: str, color_code: str) -> str:
    return f"{color_code}{text}{Colors.END}"


# ==============================================================================
# SECTION 2: PORT DATABASE
# ==============================================================================

COMMON_PORTS: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
}

TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 32768, 49152, 49153,
    49154, 49155, 49156, 49157, 50000,
]

REFUSED_ERRNOS = {111, 10061, 61, 113}  # Linux, Windows, macOS variants


# ==============================================================================
# SECTION 3: SHARED UTILITIES
# ==============================================================================

def resolve_target(target: str) -> Tuple[str, str]:
    """Resolve hostname to IP and attempt reverse DNS."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(color(f"[!] Error: Could not resolve {target}", Colors.RED))
        sys.exit(1)

    hostname = target
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        pass

    return ip, hostname


def parse_ports(port_arg: str) -> List[int]:
    """
    Parse port specification.

    Supports: "80", "80,443,22", "1-1000", "top100"
    """
    if port_arg.lower() == "top100":
        return TOP_PORTS.copy()

    ports: List[int] = []
    for part in port_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    validated: List[int] = []
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"Port {port} out of range (1-65535)")
        validated.append(port)

    return sorted(set(validated))


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


def is_host_reachable(ip: str, timeout: float = 2.0) -> bool:
    """Quick TCP reachability check against common ports."""
    probe_ports = (443, 80, 22, 445, 3389)
    for port in probe_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


# ==============================================================================
# SECTION 4: BANNER GRABBING
# ==============================================================================

def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """
    Try to read a service banner using protocol-aware probes.
    Many services send data immediately (SSH/FTP/SMTP); HTTP needs a request.
    """
    probes: List[bytes] = []

    if port in (80, 8080, 8000, 8008, 8443, 8888):
        probes.append(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    elif port == 443:
        probes.append(b"")  # TLS services rarely expose plain-text banners
    else:
        probes.append(b"")

    for probe in probes:
        try:
            sock.settimeout(2.0)
            if probe:
                sock.send(probe)
            banner = sock.recv(2048)
            if not banner:
                continue
            text = banner.decode("utf-8", errors="replace").strip()
            if text:
                return text[:200] + ("..." if len(text) > 200 else "")
        except OSError:
            continue

    return None


# ==============================================================================
# SECTION 5: TCP CONNECT SCANNER
# ==============================================================================

class TCPConnectScanner:
    """Full TCP connect scan using Python sockets."""

    def __init__(
        self,
        target: str,
        ports: List[int],
        timeout: float = 1.0,
        threads: int = 100,
        grab_banners: bool = True,
        verbose: bool = True,
    ):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = max(1, min(threads, 500))
        self.grab_banners = grab_banners
        self.verbose = verbose

        self.target_ip, self.hostname = resolve_target(target)
        self.open_ports: List[int] = []
        self.closed_ports: List[int] = []
        self.filtered_ports: List[int] = []
        self.banners: Dict[int, str] = {}
        self._results_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._completed = 0

    def _scan_port(self, port: int) -> Tuple[int, str, Optional[str]]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        status = "filtered"
        banner: Optional[str] = None

        try:
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                status = "open"
                if self.grab_banners:
                    banner = grab_banner(sock, port)
            elif result in REFUSED_ERRNOS:
                status = "closed"
            else:
                status = "filtered"
        except socket.timeout:
            status = "filtered"
        except OSError:
            status = "filtered"
        finally:
            sock.close()

        return port, status, banner

    def _record_result(self, port: int, status: str, banner: Optional[str]) -> None:
        with self._results_lock:
            if status == "open":
                self.open_ports.append(port)
                if banner:
                    self.banners[port] = banner
            elif status == "closed":
                self.closed_ports.append(port)
            else:
                self.filtered_ports.append(port)

            self._completed += 1
            completed = self._completed

        if self.verbose and status == "open":
            with self._print_lock:
                svc = service_name(port)
                banner_str = f" | {banner[:60]}" if banner else ""
                print(color(f"[+] Port {port}/tcp OPEN ({svc}){banner_str}", Colors.GREEN))

        if self.verbose and completed % 25 == 0:
            with self._print_lock:
                print(color(f"    Progress: {completed}/{len(self.ports)} ports scanned...", Colors.BLUE), end="\r")

    def scan(self) -> Dict:
        print(color("=" * 60, Colors.CYAN))
        print(color("    TCP CONNECT SCAN", Colors.BOLD + Colors.CYAN))
        print(color(f"    Target: {self.target} ({self.target_ip})", Colors.CYAN))
        if self.hostname != self.target:
            print(color(f"    Hostname: {self.hostname}", Colors.CYAN))
        print(color(
            f"    Ports: {len(self.ports)} | Threads: {self.threads} | "
            f"Timeout: {self.timeout}s | Banners: {self.grab_banners}",
            Colors.CYAN,
        ))
        print(color("=" * 60, Colors.CYAN))
        print()

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                port, status, banner = future.result()
                self._record_result(port, status, banner)

        if self.verbose:
            print()

        duration = time.time() - start_time
        return self._build_results(duration)

    def _build_results(self, duration: float) -> Dict:
        return {
            "scan_type": "tcp_connect",
            "target": self.target,
            "target_ip": self.target_ip,
            "hostname": self.hostname,
            "open_ports": sorted(self.open_ports),
            "closed_count": len(self.closed_ports),
            "filtered_count": len(self.filtered_ports),
            "banners": dict(sorted(self.banners.items())),
            "duration": duration,
            "total_ports": len(self.ports),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ==============================================================================
# SECTION 6: SYN SCANNER (requires root/admin + Scapy)
# ==============================================================================

class SYNScanner:
    """Half-open SYN scan using Scapy. Requires elevated privileges."""

    def __init__(
        self,
        target: str,
        ports: List[int],
        timeout: float = 2.0,
        threads: int = 50,
        verbose: bool = True,
    ):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = max(1, min(threads, 200))
        self.verbose = verbose

        self.target_ip, self.hostname = resolve_target(target)
        self.open_ports: List[int] = []
        self.closed_ports: List[int] = []
        self.filtered_ports: List[int] = []
        self._results_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._completed = 0
        self._permission_checked = False

    def _syn_scan_port(self, port: int) -> Tuple[int, str]:
        try:
            syn_packet = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if response is None:
                return port, "filtered"

            tcp_layer = response.getlayer(TCP)
            if tcp_layer is None:
                return port, "filtered"

            flags = int(tcp_layer.flags)
            if flags & 0x12 == 0x12:  # SYN-ACK
                rst_packet = IP(dst=self.target_ip) / TCP(
                    dport=port,
                    sport=int(tcp_layer.dport),
                    seq=int(tcp_layer.ack),
                    flags="R",
                )
                sr1(rst_packet, timeout=1, verbose=0)
                return port, "open"
            if flags & 0x04:  # RST
                return port, "closed"
            return port, "filtered"

        except PermissionError:
            if not self._permission_checked:
                self._permission_checked = True
                print(color(
                    "[!] Permission denied. SYN scanning requires root/admin privileges.",
                    Colors.RED,
                ))
                sys.exit(1)
            return port, "error"
        except OSError:
            return port, "filtered"

    def _record_result(self, port: int, status: str) -> None:
        with self._results_lock:
            if status == "open":
                self.open_ports.append(port)
            elif status == "closed":
                self.closed_ports.append(port)
            elif status == "error":
                self.filtered_ports.append(port)
            else:
                self.filtered_ports.append(port)

            self._completed += 1
            completed = self._completed

        if self.verbose and status == "open":
            with self._print_lock:
                svc = service_name(port)
                print(color(f"[+] Port {port}/tcp OPEN ({svc})", Colors.GREEN))

        if self.verbose and completed % 25 == 0:
            with self._print_lock:
                print(color(f"    Progress: {completed}/{len(self.ports)} ports scanned...", Colors.BLUE), end="\r")

    def scan(self) -> Dict:
        if not SCAPY_AVAILABLE:
            print(color("[!] Scapy not available. Cannot perform SYN scan.", Colors.RED))
            return {}

        print(color("=" * 60, Colors.MAGENTA))
        print(color("    SYN HALF-OPEN SCAN", Colors.BOLD + Colors.MAGENTA))
        print(color(f"    Target: {self.target} ({self.target_ip})", Colors.MAGENTA))
        print(color(f"    Ports: {len(self.ports)} | Threads: {self.threads} | Timeout: {self.timeout}s", Colors.MAGENTA))
        print(color("    Note: Requires root/admin privileges", Colors.YELLOW))
        print(color("=" * 60, Colors.MAGENTA))
        print()

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._syn_scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                port, status = future.result()
                self._record_result(port, status)

        if self.verbose:
            print()

        duration = time.time() - start_time
        return {
            "scan_type": "syn",
            "target": self.target,
            "target_ip": self.target_ip,
            "hostname": self.hostname,
            "open_ports": sorted(self.open_ports),
            "closed_count": len(self.closed_ports),
            "filtered_count": len(self.filtered_ports),
            "banners": {},
            "duration": duration,
            "total_ports": len(self.ports),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ==============================================================================
# SECTION 7: REPORTING
# ==============================================================================

def print_results(results: Dict, scan_type: str = "TCP Connect") -> None:
    if not results:
        return

    print()
    print(color("=" * 60, Colors.BOLD))
    print(color(f"    SCAN RESULTS - {scan_type.upper()}", Colors.BOLD))
    print(color("=" * 60, Colors.BOLD))
    print()

    print(color(f"Target:        {results['target']} ({results['target_ip']})", Colors.CYAN))
    if results.get("hostname") and results["hostname"] != results["target"]:
        print(color(f"Hostname:      {results['hostname']}", Colors.CYAN))
    print(color(f"Scan Duration: {results['duration']:.2f} seconds", Colors.CYAN))
    print(color(f"Ports Scanned: {results['total_ports']}", Colors.CYAN))
    print(color(f"Timestamp:     {results.get('timestamp', 'n/a')}", Colors.CYAN))
    print()

    if results["open_ports"]:
        print(color("OPEN PORTS:", Colors.BOLD + Colors.GREEN))
        print(color("-" * 60, Colors.GREEN))
        print(color(f"{'PORT':<8} {'SERVICE':<18} {'BANNER'}", Colors.BOLD))
        print(color("-" * 60, Colors.GREEN))

        banners = results.get("banners", {})
        for port in results["open_ports"]:
            svc = service_name(port)
            banner = banners.get(port, "")
            banner_display = banner[:45] if banner else "-"
            print(color(f"{port:<8} {svc:<18} {banner_display}", Colors.GREEN))
    else:
        print(color("No open ports found.", Colors.YELLOW))

    print()
    print(color(f"Closed ports:   {results.get('closed_count', 0)}", Colors.RED))
    print(color(f"Filtered ports: {results.get('filtered_count', 0)}", Colors.YELLOW))
    print()
    print(color("=" * 60, Colors.BOLD))


def save_results(results: Dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    print(color(f"[+] Results saved to {output_path}", Colors.GREEN))


# ==============================================================================
# SECTION 8: CLI
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Educational Port Scanner - Learn Networking & Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 -p 80,443,22
  %(prog)s scanme.nmap.org -p top100 -t 50
  %(prog)s 192.168.1.1 -p 1-1000 --syn
  %(prog)s 10.0.0.5 -p 22,80,443 --no-banner -o results.json

Ethical Notice:
  Only scan systems you own or have explicit permission to test.
        """,
    )

    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="top100", help='Ports: "80,443", "1-1000", or "top100"')
    parser.add_argument("-t", "--threads", type=int, default=100, help="Worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
    parser.add_argument("--syn", action="store_true", help="Use SYN half-open scan (requires root/admin)")
    parser.add_argument("--banner", action="store_true", help="Force banner grabbing on connect scan")
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    parser.add_argument("--skip-ping", action="store_true", help="Skip host reachability check")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only show summary results")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith("_"):
                setattr(Colors, attr, "")

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(color(f"[!] Invalid port specification: {exc}", Colors.RED))
        sys.exit(1)

    if not ports:
        print(color("[!] No ports to scan.", Colors.RED))
        sys.exit(1)

    grab_banners = not args.no_banner
    if args.banner:
        grab_banners = True

    if not args.quiet:
        print()
        print(color("╔" + "═" * 58 + "╗", Colors.CYAN))
        print(color("║" + " " * 14 + "EDUCATIONAL PORT SCANNER" + " " * 20 + "║", Colors.BOLD + Colors.CYAN))
        print(color("║" + " " * 10 + "Learning Network Security Fundamentals" + " " * 10 + "║", Colors.CYAN))
        print(color("╚" + "═" * 58 + "╝", Colors.CYAN))
        print()

    target_ip, _ = resolve_target(args.target)

    if not args.skip_ping and not is_host_reachable(target_ip, timeout=args.timeout):
        print(color(f"[!] Warning: {args.target} ({target_ip}) did not respond on common probe ports.", Colors.YELLOW))
        print(color("    The host may be down, firewalled, or blocking probes. Continuing anyway...", Colors.YELLOW))
        print()

    if args.syn:
        if not SCAPY_AVAILABLE:
            print(color("[!] Scapy required for SYN scanning. Install: pip install scapy", Colors.RED))
            sys.exit(1)
        scanner = SYNScanner(
            args.target,
            ports,
            timeout=args.timeout,
            threads=args.threads,
            verbose=not args.quiet,
        )
        results = scanner.scan()
        scan_label = "SYN Half-Open"
    else:
        scanner = TCPConnectScanner(
            args.target,
            ports,
            timeout=args.timeout,
            threads=args.threads,
            grab_banners=grab_banners,
            verbose=not args.quiet,
        )
        results = scanner.scan()
        scan_label = "TCP Connect"

    print_results(results, scan_label)

    if args.output and results:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
