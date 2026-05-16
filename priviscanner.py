#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       PriVi Network Recon Scanner v1.0                           ║
║       Full-Spectrum Domain Reconnaissance Suite                  ║
║       Developed by Prince Ubebe | PriViSecurity                  ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL NOTICE:
  This tool is intended ONLY for use against domains and targets
  you own or have explicit written authorization to assess.
  Unauthorized reconnaissance against systems you do not own is
  illegal under the Computer Misuse Act, CFAA, and equivalent
  laws worldwide. PriViSecurity accepts no liability for
  unauthorized use.
"""

import sys, subprocess, importlib

def _auto_install():
    """Auto-install missing dependencies. Works on live Kali, VM, and fresh installs."""
    packages = {
        "requests": "requests",
        "fpdf": "fpdf2",
        "rich": "rich",
        "nmap": "python-nmap",
        "whois": "python-whois",
        "dns": "dnspython",
        "urllib3": "urllib3",
    }
    missing = []
    for import_name, pip_name in packages.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"[PriViSecurity] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--break-system-packages", "-q",
            *missing
        ])
        print("[PriViSecurity] Done. Launching tool...\n")

_auto_install()


import os
import sys
import socket
import threading
import time
import re
import nmap
import whois
import urllib3
import requests
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

AUTHOR  = "Prince Ubebe"
BRAND   = "PriViSecurity"
VERSION = "2.0"
TOOL    = "PriVi Network Recon Scanner"


# ── AUTHORIZATION GATE ────────────────────────────────────────────────────────

def authorization_gate():
    os.system("clear")
    gate_text = Text()
    gate_text.append("\n  ⚠️  LEGAL AUTHORIZATION REQUIRED\n\n", style="bold red")
    gate_text.append(
        "  This tool performs active reconnaissance including WHOIS,\n"
        "  DNS enumeration, WAF detection, and Nmap vulnerability scanning.\n\n",
        style="white"
    )
    gate_text.append("  You MUST have one of the following before proceeding:\n\n", style="white")
    gate_text.append("    ✔  You own the target domain/system, OR\n", style="green")
    gate_text.append("    ✔  You hold a signed Letter of Authorization (LoA)\n", style="green")
    gate_text.append("       from the domain owner permitting this assessment.\n\n", style="green")
    gate_text.append(
        "  Unauthorized reconnaissance is illegal under the Computer\n"
        "  Misuse Act, CFAA, and equivalent laws worldwide.\n\n",
        style="dim white"
    )
    gate_text.append("  PriViSecurity accepts NO liability for unauthorized use.\n\n", style="dim red")

    console.print(Panel(
        gate_text,
        border_style="red",
        title=f"[bold red]{TOOL} v{VERSION}[/bold red]"
    ))

    console.print("[bold white]Do you have written authorization to scan the target domain?[/bold white]")
    console.print("[dim]Type [bold green]AGREE[/bold green] to confirm and proceed, or press Ctrl+C to exit.[/dim]\n")

    try:
        response = input("  > ").strip()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Session cancelled.[/bold yellow]")
        sys.exit(0)

    if response != "AGREE":
        console.print("\n[bold red][!] Authorization not confirmed. Exiting.[/bold red]")
        sys.exit(0)

    console.print("\n[bold green][✔] Authorization confirmed. Proceeding.[/bold green]\n")
    time.sleep(1)


# ── HEADER ────────────────────────────────────────────────────────────────────

def print_header():
    os.system("clear")
    header = Text()
    header.append(
        "\n"
        "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n"
        "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n"
        "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n"
        "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n"
        "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n"
        "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\n",
        style="bold cyan"
    )
    header.append(
        f"  {BRAND}  |  {TOOL} v{VERSION}  |  Full-Spectrum Domain Reconnaissance\n",
        style="dim white"
    )
    header.append(f"  Developer: {AUTHOR}  |  Authorized Use Only\n", style="dim red")
    console.print(Panel(header, border_style="blue"))


# ── ANIMATION  -  threading.Event (fixes race condition) ────────────────────────

class PhaseSpinner:
    """
    FIX: Replaces the raw global boolean stop_animation flag.

    The original bug: each phase set stop_animation=True in its finally block,
    then immediately set stop_animation=False for the next phase. If the
    animation thread hadn't checked the flag in that tiny window, it kept
    running through the next phase or indefinitely.

    threading.Event.set()/clear()/wait() is atomic  -  no race condition.
    join() ensures the thread is fully stopped before the next phase starts.
    """
    def __init__(self):
        self._stop_event = threading.Event()
        self._thread     = None

    def start(self, task_name: str):
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._spin, args=(task_name,), daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.5)  # wait for thread to actually exit
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def _spin(self, task_name: str):
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while not self._stop_event.is_set():
            sys.stdout.write(
                f"\r  \033[93m[{chars[idx % len(chars)]}]\033[0m "
                f"\033[97m{task_name}...\033[0m"
            )
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)


# ── EMAIL SCRAPER (was missing entirely) ──────────────────────────────────────

def scrape_emails(domain: str) -> list:
    """
    FIX: Email scraping was completely absent in the original  -  report_data['emails']
    was initialized as [] and written to the PDF without ever being populated,
    so the PDF always showed 'None'.

    This function fetches the target homepage and extracts emails via regex,
    with false-positive filtering for common non-email patterns.
    """
    emails = set()
    email_pattern = re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    )
    # Try https first, then http, then with www prefix
    urls_to_try = [
        f"https://{domain}",
        f"http://{domain}",
        f"https://www.{domain}",
    ]
    for url in urls_to_try:
        try:
            resp = requests.get(
                url,
                timeout=8,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; security-audit/1.0)"},
                allow_redirects=True,
            )
            found = email_pattern.findall(resp.text)
            for email in found:
                # Filter common false positives
                if any(skip in email.lower() for skip in [
                    ".png", ".jpg", ".gif", ".svg", ".js", ".css",
                    "example.", "yourdomain.", "email@", "user@",
                    "test@", "noreply@domain", "@2x",
                ]):
                    continue
                emails.add(email)
            if emails:
                break
        except requests.RequestException:
            continue

    return sorted(emails)


# ── WAF DETECTION ─────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "cf-ray":                "Cloudflare",
    "x-sucuri-id":           "Sucuri",
    "x-sucuri-cache":        "Sucuri",
    "x-firewall-protection": "Generic WAF",
    "x-waf-event-info":      "Barracuda WAF",
}

SERVER_WAF_MAP = {
    "cloudflare": "Cloudflare",
    "sucuri":     "Sucuri",
    "incapsula":  "Imperva Incapsula",
    "akamai":     "Akamai",
    "fortiweb":   "FortiWeb",
    "f5":         "F5 BIG-IP",
}


def detect_waf(domain: str) -> str:
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=6,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-audit/1.0)"},
            allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for sig, waf_name in WAF_SIGNATURES.items():
            if sig in headers_lower:
                return f"Detected  -  {waf_name} ({headers_lower[sig]})"

        # Check server header
        server = headers_lower.get("server", "").lower()
        for keyword, name in SERVER_WAF_MAP.items():
            if keyword in server:
                return f"Detected  -  {name} (via Server header)"

        # No WAF found but return server info as useful intel
        server_raw = resp.headers.get("server", "")
        return f"None Detected  (Server: {server_raw})" if server_raw else "None Detected"

    except requests.RequestException as e:
        return f"Detection failed: {e}"


# ── DNS ENUMERATION ───────────────────────────────────────────────────────────

def enumerate_dns(domain: str) -> list:
    records = []
    for r_type in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, r_type, lifetime=5)
            for rdata in answers:
                records.append(f"{r_type}: {rdata.to_text()}")
        except Exception:
            continue
    return records


# ── NMAP SCAN ─────────────────────────────────────────────────────────────────

def run_nmap_scan(ip: str) -> tuple:
    """Returns (port_results list, vuln_findings list)."""
    port_results  = []
    vuln_findings = []
    try:
        nm = nmap.PortScanner()
        # Standard scan — no root required
        # -sV: version detection, -T4: fast timing, --script vuln: vuln scripts
        scan_args = "-sV -T4 --script vuln --version-intensity 3"
        nm.scan(ip, arguments=f"{scan_args} -p 21,22,80,443,3306,8080,8443")

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    pinfo = nm[host][proto][port]
                    port_results.append({
                        "port":    port,
                        "proto":   proto,
                        "state":   pinfo.get("state", "?"),
                        "service": pinfo.get("name", "?"),
                        "version": pinfo.get("version", ""),
                    })
                    if "script" in pinfo:
                        for script_id, output in pinfo["script"].items():
                            vuln_findings.append({
                                "port":      port,
                                "script_id": script_id,
                                "output":    output[:300],
                            })
    except Exception as e:
        vuln_findings.append({
            "port": 0, "script_id": "scan-error", "output": str(e)
        })

    return port_results, vuln_findings


# ── PDF REPORT ────────────────────────────────────────────────────────────────

class ReconReport(FPDF):
    def header(self):
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 38, "F")
        self.set_xy(10, 8)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PriVi Full-Spectrum Recon Report",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(10, 20)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 8,
                  f"PriViSecurity  |  {TOOL} v{VERSION}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            f"Page {self.page_no()}  |  Powered by PriViSecurity  |  Developed by Prince Ubebe",
            align="C"
        )

    def section_title(self, title: str):
        self.set_fill_color(196, 30, 58)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kv(self, key: str, value: str, alert: bool = False):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(60, 60, 60)
        self.cell(45, 7, f"  {key}:",new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(196, 30, 58) if alert else self.set_text_color(0, 0, 0)
        self.cell(0, 7, str(value)[:100],new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)


def generate_pdf_report(report_data: dict, domain: str, operator: dict = None) -> str:
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_").replace(":", "_")
    filename    = f"PriVi_Recon_{safe_domain}_{timestamp}.pdf"

    try:
        pdf = ReconReport()
        pdf.add_page()

        # 1  -  Target intelligence
        pdf.section_title("1. Target & Organization Intelligence")
        op_display = (operator or {}).get("name", "Operator")
        if operator and operator.get("org"):
            op_display += f"  |  {operator['org']}"
        pdf.kv("Conducted by", op_display)
        pdf.kv("Domain",     domain)
        pdf.kv("IP Address", report_data.get("ip", "Unknown"))
        pdf.kv("Geo / ISP",  report_data.get("geo", "Unknown"))
        pdf.kv("Registrar",
               str(report_data.get("whois", {}).get("registrar", "Unknown")))
        pdf.kv("Org",
               str(report_data.get("whois", {}).get("org", "Unknown")))
        pdf.kv("WAF Status", report_data.get("waf", "Unknown"),
               alert="Detected" in report_data.get("waf", ""))
        pdf.kv("Audit Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        pdf.ln(4)

        # 2  -  DNS
        pdf.section_title("2. DNS Infrastructure")
        dns_records = report_data.get("dns_records", [])
        pdf.set_font("Helvetica", "", 9)
        if dns_records:
            for rec in dns_records:
                pdf.cell(0, 6, f"  * {rec}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "  No DNS records retrieved.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 3  -  Email intelligence
        pdf.section_title("3. Email Intelligence (Scraped from Homepage)")
        emails = report_data.get("emails", [])
        if emails:
            pdf.set_font("Helvetica", "", 9)
            for email in emails:
                pdf.cell(0, 6, f"  * {email}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "  No email addresses found on target homepage.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 4  -  Port scan
        pdf.section_title("4. Port Scan Results")
        port_results = report_data.get("ports", [])
        if port_results:
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(20, 7, "  Port",  fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(15, 7, "Proto",   fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(20, 7, "State",   fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(35, 7, "Service", fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0,  7, "Version", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(0, 0, 0)
            alt = False
            for p in port_results:
                pdf.set_fill_color(245, 245, 250) if alt else pdf.set_fill_color(255, 255, 255)
                alt = not alt
                state_color = (30, 160, 30) if p["state"] == "open" else (160, 30, 30)
                pdf.cell(20, 6, f"  {p['port']}", fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(15, 6, p["proto"],        fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(*state_color)
                pdf.cell(20, 6, p["state"],        fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(35, 6, p["service"][:15], fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0,  6, p["version"][:30], fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "  No port scan data available.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 5  -  Vulnerabilities
        pdf.section_title("5. Vulnerability Findings")
        vulns = report_data.get("vulns", [])
        if vulns:
            for v in vulns:
                pdf.set_text_color(196, 30, 58)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6,
                         f"  [FINDING] Port {v['port']}  -  {v['script_id']}",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(60, 60, 60)
                pdf.multi_cell(0, 5, f"    {v['output'][:250]}")
                pdf.ln(1)
            pdf.set_text_color(0, 0, 0)
        else:
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, "  No script-based vulnerabilities detected.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 6  -  Legal
        pdf.add_page()
        pdf.section_title("6. Legal & Scope Declaration")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(
            0, 6,
            f"This report was generated by {TOOL} v{VERSION}, developed by "
            f"{AUTHOR} / {BRAND}. The tool was used under the explicit "
            "authorization acknowledgment confirmed by the operator at session start.\n\n"
            "This report is confidential and intended solely for the authorized "
            "recipient. Redistribution without consent of the system owner is "
            "prohibited.\n\n"
            f"{BRAND} accepts no liability for actions taken based on the findings "
            "in this report without appropriate change-control, testing, and "
            "professional review."
        )

        pdf.output(filename)
        return filename

    except Exception as e:
        console.print(f"[bold red][!] PDF generation failed: {e}[/bold red]")
        return None


# ── RESULT DISPLAY ────────────────────────────────────────────────────────────

def display_results(report_data: dict, domain: str):
    # Target intel
    intel = Table(
        title="[bold cyan]Target Intelligence[/bold cyan]",
        border_style="blue", show_lines=True
    )
    intel.add_column("Field", style="bold white", width=18)
    intel.add_column("Value", style="white")
    waf = report_data.get("waf", "")
    intel.add_row("Domain",     domain)
    intel.add_row("IP",         report_data.get("ip", "?"))
    intel.add_row("Geo / ISP",  report_data.get("geo", "?"))
    intel.add_row("Registrar",  str(report_data.get("whois", {}).get("registrar", "?")))
    intel.add_row("Org",        str(report_data.get("whois", {}).get("org", "?")))
    intel.add_row("WAF",
        f"[bold red]{waf}[/bold red]" if "Detected" in waf else f"[green]{waf}[/green]"
    )
    console.print(intel)

    # DNS
    if report_data.get("dns_records"):
        dns_t = Table(
            title="[bold cyan]DNS Records[/bold cyan]",
            border_style="blue", show_lines=True
        )
        dns_t.add_column("Record", style="white")
        for rec in report_data["dns_records"]:
            dns_t.add_row(rec)
        console.print(dns_t)

    # Emails
    if report_data.get("emails"):
        em_t = Table(
            title="[bold cyan]Email Intelligence[/bold cyan]",
            border_style="blue", show_lines=True
        )
        em_t.add_column("Email Address", style="yellow")
        for em in report_data["emails"]:
            em_t.add_row(em)
        console.print(em_t)
    else:
        console.print("[dim]  No email addresses found on target homepage.[/dim]")

    # Ports
    if report_data.get("ports"):
        pt = Table(
            title="[bold cyan]Port Scan Results[/bold cyan]",
            border_style="blue", show_lines=True
        )
        pt.add_column("Port",    style="cyan",       width=8)
        pt.add_column("Proto",   style="white",      width=8)
        pt.add_column("State",   width=10)
        pt.add_column("Service", style="white",      width=15)
        pt.add_column("Version", style="dim white")
        for p in report_data["ports"]:
            state_str = (
                f"[bold green]{p['state']}[/bold green]"
                if p["state"] == "open"
                else f"[dim]{p['state']}[/dim]"
            )
            pt.add_row(str(p["port"]), p["proto"], state_str,
                       p["service"], p["version"])
        console.print(pt)

    # Vulns
    if report_data.get("vulns"):
        vt = Table(
            title="[bold red]Vulnerability Findings[/bold red]",
            border_style="red", show_lines=True
        )
        vt.add_column("Port",   style="bold red",    width=8)
        vt.add_column("Script", style="bold yellow", width=25)
        vt.add_column("Summary", style="white")
        for v in report_data["vulns"]:
            vt.add_row(str(v["port"]), v["script_id"], v["output"][:120])
        console.print(vt)


# ── MAIN ──────────────────────────────────────────────────────────────────────


def get_operator_info() -> dict:
    """
    Prompt for operator name and organization.
    Appears in the PDF report as "Conducted by".
    PriViSecurity brand and Prince Ubebe developer credit
    remain fixed in the report header — always.
    """
    console.print(Panel(
        "\n  [bold white]Operator Details[/bold white]\n\n"
        "  These will appear in the PDF report footer.\n"
        "  [dim]PriViSecurity branding stays fixed in the header.[/dim]\n",
        border_style="blue",
        title="[bold cyan]Report Configuration[/bold cyan]"
    ))
    op_name = console.input(
        "  [cyan]Your name[/cyan]          (analyst conducting this audit): "
    ).strip()
    op_org = console.input(
        "  [cyan]Organization[/cyan]       (optional, press Enter to skip):  "
    ).strip()
    if not op_name:
        op_name = "Operator"
    return {"name": op_name, "org": op_org}

def main():
    authorization_gate()
    print_header()
    operator = get_operator_info()

    # Target input
    if len(sys.argv) == 2:
        raw_target = sys.argv[1]
    else:
        raw_target = Prompt.ask(
            "[cyan]Target domain[/cyan]  (e.g. example.com)"
        ).strip()

    if "://" not in raw_target:
        raw_target = "http://" + raw_target
    domain = urlparse(raw_target).netloc or raw_target

    console.print(f"\n[bold cyan][*] Target locked: {domain}[/bold cyan]\n")

    report_data = {
        "ip":          None,
        "geo":         "Unknown",
        "whois":       {},
        "emails":      [],
        "ports":       [],
        "vulns":       [],
        "waf":         "None Detected",
        "dns_records": [],
    }

    spinner = PhaseSpinner()

    # Phase 1  -  WHOIS & Geo
    console.print("[bold white]Phase 1/5   -   WHOIS & Organization Intelligence[/bold white]")
    spinner.start("WHOIS & geo lookup")
    try:
        report_data["ip"] = socket.gethostbyname(domain)
        w = whois.whois(domain)
        report_data["whois"] = {
            "registrar":     getattr(w, "registrar", "Unknown"),
            "creation_date": str(getattr(w, "creation_date", "Unknown")),
            "org":           getattr(w, "org", "Unknown"),
        }
        geo = requests.get(
            f"https://ip-api.com/json/{report_data['ip']}", timeout=5
        ).json()
        if geo.get("status") == "success":
            report_data["geo"] = (
                f"{geo.get('country','?')}, {geo.get('city','?')} "
                f"({geo.get('isp','?')})"
            )
    except Exception as e:
        console.print(f"\n[bold yellow][~] WHOIS partial failure: {e}[/bold yellow]")
    finally:
        spinner.stop()
    console.print(
        f"  [green]✔[/green] IP: {report_data['ip']}  |  "
        f"Org: {report_data['whois'].get('org','?')}"
    )

    # Phase 2  -  WAF
    console.print("\n[bold white]Phase 2/5   -   WAF & Perimeter Detection[/bold white]")
    spinner.start("WAF fingerprinting")
    try:
        report_data["waf"] = detect_waf(domain)
    except Exception as e:
        report_data["waf"] = f"Detection error: {e}"
    finally:
        spinner.stop()
    waf_display = (
        f"[bold red]{report_data['waf']}[/bold red]"
        if "Detected" in report_data["waf"]
        else f"[green]{report_data['waf']}[/green]"
    )
    console.print(f"  [green]✔[/green] WAF: {waf_display}")

    # Phase 3  -  DNS
    console.print("\n[bold white]Phase 3/5   -   DNS Record Enumeration[/bold white]")
    spinner.start("DNS enumeration")
    try:
        report_data["dns_records"] = enumerate_dns(domain)
    except Exception as e:
        console.print(f"\n[bold yellow][~] DNS error: {e}[/bold yellow]")
    finally:
        spinner.stop()
    console.print(
        f"  [green]✔[/green] {len(report_data['dns_records'])} record(s) retrieved"
    )

    # Phase 4  -  Email scraping
    console.print("\n[bold white]Phase 4/5   -   Email Intelligence Scraping[/bold white]")
    spinner.start("Scraping homepage for email addresses")
    try:
        report_data["emails"] = scrape_emails(domain)
    except Exception as e:
        console.print(f"\n[bold yellow][~] Scraping error: {e}[/bold yellow]")
    finally:
        spinner.stop()
    count = len(report_data["emails"])
    console.print(
        f"  [green]✔[/green] {count} email address(es) found"
        if count else "  [dim]  No emails found on homepage[/dim]"
    )

    # Phase 5  -  Nmap
    console.print("\n[bold white]Phase 5/5   -   Nmap Stealth Vulnerability Scan[/bold white]")
    console.print("  [dim]This may take 1–3 minutes depending on target...[/dim]")
    spinner.start("Nmap stealth scan in progress")
    try:
        ports, vulns = run_nmap_scan(report_data["ip"])
        report_data["ports"] = ports
        report_data["vulns"] = vulns
    except Exception as e:
        console.print(f"\n[bold yellow][~] Nmap error: {e}[/bold yellow]")
    finally:
        spinner.stop()
    console.print(
        f"  [green]✔[/green] {len(report_data['ports'])} port(s) scanned  |  "
        f"{len(report_data['vulns'])} finding(s)"
    )

    # Display & report
    console.print("\n")
    display_results(report_data, domain)

    console.print("\n[bold cyan][*] Generating PDF report...[/bold cyan]")
    pdf_file = generate_pdf_report(report_data, domain, operator)
    if pdf_file:
        console.print(f"[bold green][+] Report saved: {pdf_file}[/bold green]")
    else:
        console.print("[bold red][!] PDF generation failed.[/bold red]")

    console.print(
        "\n[bold green][✔] Reconnaissance complete. PriViSecurity standing by.[/bold green]\n"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Scan aborted by user.[/bold yellow]")
        sys.exit(0)
