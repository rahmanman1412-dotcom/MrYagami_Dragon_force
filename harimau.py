# mryagami dragon force - harimau
# usage: python harimau.py <target> [--ports] [--aggressive]

import socket
import sys
import requests
import argparse
from urllib.parse import urlparse
import re
from datetime import datetime
import threading
import time

BANNER = """
╔════════════════════════════════════════════╗
║       mryagami dragon force - harimau      ║
║       Advanced Recon & Web Scanner         ║
╚════════════════════════════════════════════╝
"""

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def resolve_domain(target):
    """Resolve domain ke IP"""
    try:
        if "://" in target:
            target = urlparse(target).netloc
        ip = socket.gethostbyname(target)
        print(f"{GREEN}[+] Resolved: {target} → {ip}{RESET}")
        return ip, target
    except socket.gaierror:
        print(f"{RED}[-] Gagal resolve domain: {target}{RESET}")
        sys.exit(1)

def port_scan(ip, ports="1-1000", aggressive=False):
    """Scan port cepat (mirip nmap -sS -T4)"""
    print(f"{YELLOW}[*] Scanning ports on {ip} ...{RESET}")

    common_ports = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,8080,8443]
    open_ports = []

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8 if not aggressive else 1.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports.append((port, service))
                print(f"{GREEN}[+] Port {port}/tcp open - {service}{RESET}")
            sock.close()
        except:
            pass

    if ports == "top":
        ports_list = common_ports
    elif "-" in ports:
        start, end = map(int, ports.split("-"))
        ports_list = range(start, end+1)
    else:
        ports_list = [int(p) for p in ports.split(",")]

    threads = []
    for port in ports_list:
        t = threading.Thread(target=scan_port, args=(port,))
        t.start()
        threads.append(t)
        time.sleep(0.01)  # hindari rate limit socket

    for t in threads:
        t.join()

    return open_ports

def web_tech_scan(url):
    """Scan teknologi web, header, celah umum"""
    if not url.startswith("http"):
        url = "https://" + url if url.startswith("www") else "http://" + url

    print(f"{YELLOW}[*] Scanning web technologies & headers: {url}{RESET}")

    try:
        headers = {
            "User-Agent": "mryagami-dragon-force/1.0 (Recon Tool)",
            "Accept": "*/*"
        }
        r = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)

        print(f"{GREEN}[+] Status Code: {r.status_code}{RESET}")
        print(f"{GREEN}[+] Final URL: {r.url}{RESET}")

        # Server & teknologi
        server = r.headers.get("Server", "Tidak ada")
        powered = r.headers.get("X-Powered-By", "Tidak ada")
        print(f"  Server: {server}")
        print(f"  X-Powered-By: {powered}")

        # CMS / Framework detection sederhana
        content = r.text.lower()
        tech = []
        if "wp-content" in content or "wordpress" in content:
            tech.append("WordPress")
        if "joomla" in content or "jdoc" in content:
            tech.append("Joomla")
        if "drupal" in content:
            tech.append("Drupal")
        if "laravel" in content or "csrf-token" in content:
            tech.append("Laravel (kemungkinan)")
        if "shopify" in content:
            tech.append("Shopify")
        if tech:
            print(f"{GREEN}[+] Kemungkinan CMS/Framework: {', '.join(tech)}{RESET}")

        # Header keamanan lemah
        missing_headers = []
        if "Strict-Transport-Security" not in r.headers:
            missing_headers.append("HSTS")
        if "Content-Security-Policy" not in r.headers:
            missing_headers.append("CSP")
        if "X-Frame-Options" not in r.headers:
            missing_headers.append("X-Frame-Options")
        if "X-Content-Type-Options" not in r.headers:
            missing_headers.append("X-Content-Type-Options")
        if missing_headers:
            print(f"{RED}[!] Missing security headers: {', '.join(missing_headers)}{RESET}")

        # Directory listing / exposed files check
        for path in ["/admin/", "/wp-admin/", "/config.php", "/.env", "/backup/", "/phpmyadmin/"]:
            try:
                test = requests.head(url.rstrip("/") + path, timeout=4, verify=False)
                if test.status_code in [200, 403]:
                    print(f"{RED}[!] Possible exposed path: {path} ({test.status_code}){RESET}")
            except:
                pass

    except Exception as e:
        print(f"{RED}[-] Web scan error: {e}{RESET}")

def save_report(ip, domain, open_ports, url):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"mryagami_report_{domain}_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("mryagami dragon force - harimau scan report\n")
        f.write("="*45 + "\n")
        f.write(f"Target       : {domain}\n")
        f.write(f"IP           : {ip}\n")
        f.write(f"Scan date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"URL scanned  : {url}\n\n")

        f.write("Open Ports:\n")
        for port, service in open_ports:
            f.write(f"  {port}/tcp - {service}\n")
        f.write("\n")

    print(f"{GREEN}[+] Report disimpan: {filename}{RESET}")

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="mryagami dragon force - harimau")
    parser.add_argument("target", help="Domain atau URL (contoh: example.com atau https://example.com)")
    parser.add_argument("--ports", default="top", help="Ports to scan: top, 1-1000, 80,443,8080,... (default: top)")
    parser.add_argument("--aggressive", action="store_true", help="Scan lebih agresif (longer timeout)")

    args = parser.parse_args()

    ip, domain = resolve_domain(args.target)
    url = args.target if args.target.startswith("http") else f"https://{domain}"

    open_ports = port_scan(ip, args.ports, args.aggressive)

    web_tech_scan(url)

    save_report(ip, domain, open_ports, url)

    print(f"\n{GREEN}Scan selesai. mryagami dragon force menyelesaikan tugas.{RESET}")

if __name__ == "__main__":
    main()
