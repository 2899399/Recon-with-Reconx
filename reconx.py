#!/usr/bin/env python3
# ============================================================
#   Reconx - Full Reconnaissance Tool
#   Works on: Kali Linux | Windows CMD
#   Author  : Parveen Kumar
#   Version : 1.0
# ============================================================
#
#   USAGE:
#     python3 reconx.py -t example.com
#     python3 reconx.py -t 8.8.8.8
#     python3 reconx.py -t example.com --full
#     python3 reconx.py --help
#
# ============================================================

import socket
import urllib.request
import urllib.error
import json
import sys
import argparse
import datetime
import concurrent.futures

# ── Terminal Colors ──────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── Common ports to scan ─────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle DB",
    3000: "Node.js / Dev Server",
    3306: "MySQL / MariaDB",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate / Tomcat",
    8443: "HTTPS Alternate",
    8888: "Jupyter Notebook",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

BANNER = f"""
{CYAN}{BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{RESET}
{DIM}  Full Reconnaissance Tool | v1.0
  For authorized use only{RESET}
{CYAN}{'─'*55}{RESET}
"""


# ════════════════════════════════════════════════════════════
#  SECTION 1 — DNS & IP Info
# ════════════════════════════════════════════════════════════

def resolve_target(target):
    """Resolve domain to IP or return IP as-is."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


def get_dns_records(domain):
    """Get basic DNS info via socket."""
    print(f"\n{CYAN}{BOLD}[1/5] DNS & IP Information{RESET}")
    print(f"{CYAN}{'─'*45}{RESET}")

    ip = resolve_target(domain)
    if not ip:
        print(f"  {RED}[-] Could not resolve: {domain}{RESET}")
        return None

    print(f"  {GREEN}[+] Target     : {domain}{RESET}")
    print(f"  {GREEN}[+] Resolved IP: {ip}{RESET}")

    # Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"  {GREEN}[+] Reverse DNS: {hostname}{RESET}")
    except Exception:
        print(f"  {YELLOW}[-] Reverse DNS: Not found{RESET}")

    # All IPs (if multiple A records)
    try:
        all_ips = socket.getaddrinfo(domain, None)
        unique = list(set([x[4][0] for x in all_ips]))
        if len(unique) > 1:
            print(f"  {GREEN}[+] All IPs    : {', '.join(unique)}{RESET}")
    except Exception:
        pass

    return ip


# ════════════════════════════════════════════════════════════
#  SECTION 2 — GeoIP & ISP Info
# ════════════════════════════════════════════════════════════

def get_geoip(ip):
    """Fetch GeoIP info from ip-api.com."""
    print(f"\n{CYAN}{BOLD}[2/5] GeoIP & Network Info{RESET}")
    print(f"{CYAN}{'─'*45}{RESET}")

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read().decode())

        if data.get("status") == "success":
            print(f"  {GREEN}[+] IP Address : {data.get('query', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] Country    : {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')}){RESET}")
            print(f"  {GREEN}[+] Region     : {data.get('regionName', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] City       : {data.get('city', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] ZIP        : {data.get('zip', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] Timezone   : {data.get('timezone', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] ISP        : {data.get('isp', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] Organization: {data.get('org', 'N/A')}{RESET}")
            print(f"  {GREEN}[+] AS Number  : {data.get('as', 'N/A')}{RESET}")
            return data
        else:
            print(f"  {YELLOW}[-] GeoIP lookup failed{RESET}")
    except Exception as e:
        print(f"  {RED}[-] GeoIP error: {e}{RESET}")
    return {}


# ════════════════════════════════════════════════════════════
#  SECTION 3 — Port Scan & Service Detection
# ════════════════════════════════════════════════════════════

def scan_port(ip, port):
    """Check if a single port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False


def banner_grab(ip, port):
    """Try to grab service banner."""
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:100] if banner else None
    except Exception:
        return None


def scan_ports(ip):
    """Scan common ports using threading."""
    print(f"\n{CYAN}{BOLD}[3/5] Port Scan & Service Detection{RESET}")
    print(f"{CYAN}{'─'*45}{RESET}")
    print(f"  {YELLOW}Scanning {len(COMMON_PORTS)} common ports...{RESET}\n")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "Unknown")
                open_ports.append((port, service))
                print(f"  {GREEN}[+] Port {port:<6} OPEN   -> {service}{RESET}")

    if not open_ports:
        print(f"  {YELLOW}[-] No common ports found open{RESET}")
    else:
        print(f"\n  {BOLD}Total open ports: {len(open_ports)}{RESET}")

    return open_ports


# ════════════════════════════════════════════════════════════
#  SECTION 4 — HTTP Headers (OS, Server, Tech Stack)
# ════════════════════════════════════════════════════════════

def get_http_info(target):
    """Fetch HTTP headers to detect OS, server, and tech stack."""
    print(f"\n{CYAN}{BOLD}[4/5] Web Server & Technology Stack{RESET}")
    print(f"{CYAN}{'─'*45}{RESET}")

    results = {}

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{target}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                headers = dict(r.headers)
                status  = r.status

            print(f"  {GREEN}[+] URL         : {url}{RESET}")
            print(f"  {GREEN}[+] Status Code : {status}{RESET}")

            # Server
            server = headers.get("Server", headers.get("server", None))
            if server:
                print(f"  {GREEN}[+] Web Server  : {server}{RESET}")
                results["server"] = server
                # OS hint from server header
                if "ubuntu" in server.lower():
                    print(f"  {MAGENTA}[+] OS Hint     : Ubuntu Linux{RESET}")
                elif "debian" in server.lower():
                    print(f"  {MAGENTA}[+] OS Hint     : Debian Linux{RESET}")
                elif "centos" in server.lower():
                    print(f"  {MAGENTA}[+] OS Hint     : CentOS Linux{RESET}")
                elif "win" in server.lower():
                    print(f"  {MAGENTA}[+] OS Hint     : Windows Server{RESET}")

            # Powered By (PHP, ASP.NET etc.)
            powered = headers.get("X-Powered-By", headers.get("x-powered-by", None))
            if powered:
                print(f"  {GREEN}[+] Powered By  : {powered}{RESET}")
                results["powered_by"] = powered

            # Content Type
            ctype = headers.get("Content-Type", headers.get("content-type", None))
            if ctype:
                print(f"  {GREEN}[+] Content-Type: {ctype}{RESET}")

            # Security Headers check
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "X-Frame-Options"          : "Clickjacking Protection",
                "X-XSS-Protection"         : "XSS Protection",
                "Content-Security-Policy"  : "CSP",
                "X-Content-Type-Options"   : "MIME Sniff Protection",
            }
            print(f"\n  {BOLD}Security Headers:{RESET}")
            for h, label in security_headers.items():
                val = headers.get(h, headers.get(h.lower(), None))
                if val:
                    print(f"  {GREEN}  [✓] {label}{RESET}")
                else:
                    print(f"  {RED}  [✗] {label} — MISSING{RESET}")

            results["headers"] = headers
            break  # Stop after first successful response

        except urllib.error.URLError:
            continue
        except Exception as e:
            print(f"  {YELLOW}[-] Could not fetch HTTP info: {e}{RESET}")
            break

    if not results:
        print(f"  {YELLOW}[-] Target does not appear to be running a web server{RESET}")

    return results


# ════════════════════════════════════════════════════════════
#  SECTION 5 — Database Detection via Ports
# ════════════════════════════════════════════════════════════

def detect_databases(open_ports):
    """Detect databases based on open ports."""
    print(f"\n{CYAN}{BOLD}[5/5] Database Detection{RESET}")
    print(f"{CYAN}{'─'*45}{RESET}")

    db_ports = {
        3306 : "MySQL / MariaDB",
        5432 : "PostgreSQL",
        1433 : "Microsoft SQL Server (MSSQL)",
        1521 : "Oracle Database",
        27017: "MongoDB",
        6379 : "Redis",
        9200 : "Elasticsearch",
        5984 : "CouchDB",
    }

    found_dbs = []
    port_nums  = [p for p, _ in open_ports]

    for port, db in db_ports.items():
        if port in port_nums:
            found_dbs.append(db)
            print(f"  {GREEN}[+] Detected : {db} (port {port}){RESET}")

    if not found_dbs:
        print(f"  {YELLOW}[-] No database ports found open{RESET}")
        print(f"  {DIM}    (Databases may be firewalled or on non-standard ports){RESET}")

    return found_dbs


# ════════════════════════════════════════════════════════════
#  Save Full Report
# ════════════════════════════════════════════════════════════

def save_report(target, ip, geo, open_ports, http_info, databases):
    """Save full recon report to a text file."""
    filename = f"reconx_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:
        f.write("=" * 55 + "\n")
        f.write("  ReconX - Full Reconnaissance Report\n")
        f.write(f"  Target  : {target}\n")
        f.write(f"  Date    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 55 + "\n\n")

        f.write("[DNS & IP]\n")
        f.write(f"  Target     : {target}\n")
        f.write(f"  Resolved IP: {ip}\n\n")

        f.write("[GeoIP]\n")
        for k, v in geo.items():
            f.write(f"  {k}: {v}\n")
        f.write("\n")

        f.write("[Open Ports]\n")
        for port, service in open_ports:
            f.write(f"  {port} -> {service}\n")
        f.write("\n")

        f.write("[Web Server Info]\n")
        f.write(f"  Server    : {http_info.get('server', 'N/A')}\n")
        f.write(f"  Powered By: {http_info.get('powered_by', 'N/A')}\n\n")

        f.write("[Databases Detected]\n")
        for db in databases:
            f.write(f"  {db}\n")
        f.write("\n")

    return filename


# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ReconX - Full Reconnaissance Tool",
        epilog="Example: python3 reconx.py -t example.com"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain (e.g. example.com or 8.8.8.8)")
    parser.add_argument("--save", action="store_true", help="Save report to a text file")
    args = parser.parse_args()

    target = args.target.replace("https://", "").replace("http://", "").strip("/")

    print(f"  {BOLD}Target   : {CYAN}{target}{RESET}")
    print(f"  {BOLD}Started  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"  {YELLOW}⚠️  For authorized use only!{RESET}\n")

    # Run all sections
    ip         = get_dns_records(target)
    if not ip:
        print(f"\n{RED}Could not resolve target. Exiting.{RESET}\n")
        sys.exit(1)

    geo        = get_geoip(ip)
    open_ports = scan_ports(ip)
    http_info  = get_http_info(target)
    databases  = detect_databases(open_ports)

    # Summary
    print(f"\n{CYAN}{BOLD}{'═'*55}")
    print(f"  ✅ Recon Complete — Summary")
    print(f"{'═'*55}{RESET}")
    print(f"  {BOLD}Target      :{RESET} {target} ({ip})")
    print(f"  {BOLD}Location    :{RESET} {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
    print(f"  {BOLD}ISP         :{RESET} {geo.get('isp', 'N/A')}")
    print(f"  {BOLD}Open Ports  :{RESET} {len(open_ports)}")
    print(f"  {BOLD}Web Server  :{RESET} {http_info.get('server', 'N/A')}")
    print(f"  {BOLD}Databases   :{RESET} {len(databases)} detected")

    if args.save:
        filename = save_report(target, ip, geo, open_ports, http_info, databases)
        print(f"\n  {GREEN}💾 Report saved: {filename}{RESET}")

    print(f"\n{CYAN}{'═'*55}{RESET}\n")


if __name__ == "__main__":
    main()
