#!/usr/bin/env python3
# SkyOSINT - All-in-One Passive OSINT CLI (Educational)
# No hacking • No tracking • No APIs • Manual verification recommended

import re
import time
import json
import socket
from dataclasses import dataclass
from typing import Callable, Optional, List, Tuple, Dict, Any
from pathlib import Path
from datetime import datetime

import requests
import dns.resolver
import whois
import exifread

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
import pyfiglet


console = Console()

# --------------------------- REPORTING ---------------------------

REPORTS_DIR = Path("reports")
SESSION_TS = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
SESSION_TXT = REPORTS_DIR / f"session_{SESSION_TS}.txt"
SESSION_JSON = REPORTS_DIR / f"session_{SESSION_TS}.json"

# In-memory JSON log for the session
SESSION_LOG: List[Dict[str, Any]] = []


def ensure_reports_dir() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def safe_filename(text: str, max_len: int = 60) -> str:
    text = text.strip().lower()
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.replace("@", "_")
    text = text.strip("._-")
    if len(text) > max_len:
        text = text[:max_len]
    return text or "unknown"


def append_session_text(module_name: str, target: str, lines: List[str]) -> None:
    """
    Append to a single session text report.
    """
    ensure_reports_dir()
    block = []
    block.append("=" * 60)
    block.append(f"Time: {datetime.now().isoformat(timespec='seconds')}")
    block.append(f"Module: {module_name}")
    block.append(f"Target: {target}")
    block.append("-" * 60)
    block.extend(lines)
    block.append("")  # blank line
    SESSION_TXT.write_text(
        (SESSION_TXT.read_text(encoding="utf-8", errors="ignore") if SESSION_TXT.exists() else "")
        + "\n".join(block) + "\n",
        encoding="utf-8",
        errors="ignore",
    )


def append_session_json(module_name: str, target: str, data: Dict[str, Any]) -> None:
    """
    Append to in-memory list, then write to session JSON file.
    """
    ensure_reports_dir()
    entry = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "module": module_name,
        "target": target,
        "data": data,
    }
    SESSION_LOG.append(entry)
    SESSION_JSON.write_text(json.dumps(SESSION_LOG, indent=2), encoding="utf-8", errors="ignore")


def save_per_scan_report(module_name: str, target: str, lines: List[str]) -> Path:
    """
    Save a per-scan TXT report too (nice for beginners).
    """
    ensure_reports_dir()
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fname = f"{ts}_{safe_filename(module_name)}_{safe_filename(target)}.txt"
    path = REPORTS_DIR / fname

    header = [
        "SkyOSINT Report",
        f"Time: {datetime.now().isoformat(timespec='seconds')}",
        f"Module: {module_name}",
        f"Target: {target}",
        "-" * 50,
        "",
    ]
    content = "\n".join(header + lines) + "\n"
    path.write_text(content, encoding="utf-8", errors="ignore")
    return path


def show_saved(path: Path) -> None:
    console.print(f"[green]Saved report:[/green] {path}")


def show_session_paths() -> None:
    console.print(
        Panel(
            f"[bold]Session report files[/bold]\n\n"
            f"TXT: {SESSION_TXT.resolve()}\n"
            f"JSON: {SESSION_JSON.resolve()}\n\n"
            "A per-scan TXT file is also created for each search.",
            title="Reports",
            box=box.ROUNDED,
        )
    )


# --------------------------- BASIC UI HELPERS ---------------------------

def show_banner():
    banner = pyfiglet.figlet_format("SkyOSINT")
    console.print(banner, style="cyan")
    console.print(
        Panel(
            "[bold red]Passive OSINT Framework[/bold red]\n"
            "✅ Educational use only\n"
            "✅ No hacking • No tracking • No APIs\n"
            "⚠️ Always verify results manually",
            box=box.DOUBLE,
        )
    )


def pause():
    input("\nPress Enter to continue...")


def main_menu():
    console.print("\n[bold yellow]Main Menu[/bold yellow]")
    console.print("[1] Email OSINT")
    console.print("[2] Phone OSINT")
    console.print("[3] Domain OSINT")
    console.print("[4] IP OSINT")
    console.print("[5] Location Intelligence")
    console.print("[6] Username OSINT (profile checker)")
    console.print("[7] Reports: show session paths")
    console.print("[8] Reports: list & read TXT reports")
    console.print("[0] Exit")


# --------------------------- SAFE HTTP CLIENT ---------------------------

DEFAULT_HEADERS = {
    "User-Agent": "SkyOSINT/1.2 (Educational; Passive OSINT; No automation abuse)"
}


def http_get(url: str, timeout: int = 12) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return r, None
    except requests.RequestException as e:
        return None, str(e)


# --------------------------- EMAIL OSINT ---------------------------

def email_osint():
    email = input("\nEnter email: ").strip()
    lines: List[str] = []
    data: Dict[str, Any] = {}

    table = Table(title="Email OSINT", box=box.SIMPLE)
    table.add_column("Check")
    table.add_column("Result")

    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        table.add_row("Format", "[green]Valid[/green]")
        lines.append("Format: Valid")
        data["format_valid"] = True
    else:
        table.add_row("Format", "[red]Invalid[/red]")
        lines.append("Format: Invalid")
        data["format_valid"] = False
        note = "Email format looks wrong. Fix it and try again."
        table.add_row("Note", note)
        lines.append(f"Note: {note}")
        console.print(table)

        # Save reports
        per = save_per_scan_report("email", email, lines)
        show_saved(per)
        append_session_text("email", email, lines)
        append_session_json("email", email, data)
        pause()
        return

    domain = email.split("@")[-1].lower()
    table.add_row("Domain", domain)
    lines.append(f"Domain: {domain}")
    data["domain"] = domain

    try:
        dns.resolver.resolve(domain, "MX")
        table.add_row("MX Record", "[green]Found[/green]")
        lines.append("MX Record: Found")
        data["mx_found"] = True
    except Exception:
        table.add_row("MX Record", "[yellow]Not Found / Blocked[/yellow]")
        lines.append("MX Record: Not Found / Blocked")
        data["mx_found"] = False

    console.print(table)

    per = save_per_scan_report("email", email, lines)
    show_saved(per)
    append_session_text("email", email, lines)
    append_session_json("email", email, data)
    pause()


# --------------------------- PHONE OSINT (PASSIVE) ---------------------------

def phone_osint():
    phone = input("\nEnter phone number (with country code, e.g. +60123456789): ").strip()
    lines: List[str] = []
    data: Dict[str, Any] = {}

    table = Table(title="Phone OSINT (Passive)", box=box.SIMPLE)
    table.add_column("Info")
    table.add_column("Result")

    clean = re.sub(r"\s+", "", phone)
    data["input"] = phone
    data["clean"] = clean

    if not clean.startswith("+") or not re.match(r"^\+\d{6,15}$", clean):
        table.add_row("Format", "[red]Invalid[/red]")
        tip = "Use country code + digits only (example: +60123456789)."
        table.add_row("Tip", tip)
        lines += ["Format: Invalid", f"Tip: {tip}"]
        data["format_valid"] = False

        console.print(table)
        per = save_per_scan_report("phone", phone, lines)
        show_saved(per)
        append_session_text("phone", phone, lines)
        append_session_json("phone", phone, data)
        pause()
        return

    data["format_valid"] = True

    if clean.startswith("+60"):
        country = "Malaysia"
    elif clean.startswith("+62"):
        country = "Indonesia"
    elif clean.startswith("+65"):
        country = "Singapore"
    elif clean.startswith("+66"):
        country = "Thailand"
    elif clean.startswith("+63"):
        country = "Philippines"
    else:
        country = "Unknown (not in beginner list)"

    table.add_row("Country", country)
    table.add_row("Region/Carrier", "Not reliable offline without paid databases")
    table.add_row("Live location", "[red]Not possible (OSINT)[/red]")

    lines.append(f"Country: {country}")
    lines.append("Region/Carrier: Not reliable offline without paid databases")
    lines.append("Live location: Not possible (OSINT)")

    data["country"] = country

    console.print(table)
    per = save_per_scan_report("phone", clean, lines)
    show_saved(per)
    append_session_text("phone", clean, lines)
    append_session_json("phone", clean, data)
    pause()


# --------------------------- DOMAIN OSINT ---------------------------

def domain_osint():
    domain = input("\nEnter domain (example: example.com): ").strip().lower()
    lines: List[str] = []
    data: Dict[str, Any] = {"domain": domain}

    table = Table(title="Domain OSINT", box=box.SIMPLE)
    table.add_column("Field")
    table.add_column("Value")

    if not re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", domain):
        table.add_row("Format", "[red]Invalid[/red]")
        tip = "Enter a domain like example.com (no http://)."
        table.add_row("Tip", tip)
        lines += ["Format: Invalid", f"Tip: {tip}"]
        data["format_valid"] = False

        console.print(table)
        per = save_per_scan_report("domain", domain, lines)
        show_saved(per)
        append_session_text("domain", domain, lines)
        append_session_json("domain", domain, data)
        pause()
        return

    data["format_valid"] = True

    try:
        w = whois.whois(domain)
        registrar = str(w.registrar)
        created = str(w.creation_date)
        expires = str(w.expiration_date)

        table.add_row("Registrar", registrar)
        table.add_row("Created", created)
        table.add_row("Expires", expires)

        lines += [f"Registrar: {registrar}", f"Created: {created}", f"Expires: {expires}"]
        data["whois"] = {"registrar": registrar, "created": created, "expires": expires}
    except Exception:
        msg = "Failed/blocked (some TLDs restrict WHOIS)"
        table.add_row("WHOIS", f"[yellow]{msg}[/yellow]")
        lines.append(f"WHOIS: {msg}")
        data["whois"] = {"error": msg}

    try:
        ip = socket.gethostbyname(domain)
        table.add_row("Resolved IP", ip)
        lines.append(f"Resolved IP: {ip}")
        data["resolved_ip"] = ip
    except Exception:
        table.add_row("Resolved IP", "[yellow]Not Found[/yellow]")
        lines.append("Resolved IP: Not Found")
        data["resolved_ip"] = None

    def safe_dns(qtype: str) -> str:
        try:
            ans = dns.resolver.resolve(domain, qtype)
            return ", ".join(str(r) for r in ans[:5])
        except Exception:
            return "N/A"

    ns = safe_dns("NS")
    mx = safe_dns("MX")

    table.add_row("NS", ns)
    table.add_row("MX", mx)

    lines += [f"NS: {ns}", f"MX: {mx}"]
    data["dns"] = {"NS": ns, "MX": mx}

    console.print(table)
    per = save_per_scan_report("domain", domain, lines)
    show_saved(per)
    append_session_text("domain", domain, lines)
    append_session_json("domain", domain, data)
    pause()


# --------------------------- IP OSINT (PASSIVE) ---------------------------

def ip_osint():
    ip = input("\nEnter IP address (example: 8.8.8.8): ").strip()
    lines: List[str] = []
    data: Dict[str, Any] = {"ip": ip}

    table = Table(title="IP OSINT (Passive)", box=box.SIMPLE)
    table.add_column("Check")
    table.add_column("Result")

    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        table.add_row("Format", "[red]Invalid[/red]")
        tip = "Enter IPv4 like 1.1.1.1"
        table.add_row("Tip", tip)
        lines += ["Format: Invalid", f"Tip: {tip}"]
        data["format_valid"] = False

        console.print(table)
        per = save_per_scan_report("ip", ip, lines)
        show_saved(per)
        append_session_text("ip", ip, lines)
        append_session_json("ip", ip, data)
        pause()
        return

    data["format_valid"] = True

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        table.add_row("Reverse DNS", hostname)
        lines.append(f"Reverse DNS: {hostname}")
        data["reverse_dns"] = hostname
    except Exception:
        table.add_row("Reverse DNS", "[yellow]Not Found[/yellow]")
        lines.append("Reverse DNS: Not Found")
        data["reverse_dns"] = None

    if ip.startswith(("10.", "192.168.")) or re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", ip):
        ip_type = "Private"
        table.add_row("IP Type", "[cyan]Private[/cyan]")
    else:
        ip_type = "Public"
        table.add_row("IP Type", "[green]Public[/green]")

    lines.append(f"IP Type: {ip_type}")
    data["ip_type"] = ip_type

    note = "Accurate geo needs databases/APIs; keep it passive & manual."
    table.add_row("Location", note)
    lines.append(f"Location: {note}")
    data["location_note"] = note

    console.print(table)
    per = save_per_scan_report("ip", ip, lines)
    show_saved(per)
    append_session_text("ip", ip, lines)
    append_session_json("ip", ip, data)
    pause()


# --------------------------- LOCATION INTELLIGENCE (PASSIVE) ---------------------------

def image_gps_osint():
    image_path = input("Enter image file path: ").strip()
    lines: List[str] = [f"Image path: {image_path}"]
    data: Dict[str, Any] = {"image_path": image_path}

    try:
        with open(image_path, "rb") as f:
            tags = exifread.process_file(f)

        table = Table(title="Image EXIF GPS Metadata", box=box.SIMPLE)
        table.add_column("Tag")
        table.add_column("Value")

        gps: Dict[str, str] = {}
        for tag in tags:
            if "GPS" in tag:
                gps[tag] = str(tags[tag])
                table.add_row(tag, gps[tag])

        if not gps:
            table.add_row("GPS Data", "[yellow]Not Found[/yellow]")
            lines.append("GPS Data: Not Found")
            data["gps"] = {}
        else:
            lines.append("GPS Data Found:")
            for k, v in gps.items():
                lines.append(f"  - {k}: {v}")
            data["gps"] = gps

        note = "If GPS exists, it may reveal real coordinates. Handle responsibly."
        table.add_row("Note", note)
        lines.append(f"Note: {note}")
        data["note"] = note

        console.print(table)
    except Exception:
        console.print("[red]Failed to read image metadata. Check file path and type.[/red]")
        lines.append("Error: Failed to read image metadata. Check file path and type.")
        data["error"] = "Failed to read image metadata"

    per = save_per_scan_report("image_gps", image_path, lines)
    show_saved(per)
    append_session_text("image_gps", image_path, lines)
    append_session_json("image_gps", image_path, data)
    pause()


def location_osint():
    while True:
        console.print("\n[bold yellow]Location Intelligence (Passive)[/bold yellow]")
        console.print("[1] IP (Reverse DNS + type)")
        console.print("[2] Phone (Country inference)")
        console.print("[3] Image GPS Metadata (EXIF)")
        console.print("[0] Back")

        choice = input("Select: ").strip()

        if choice == "1":
            ip_osint()
        elif choice == "2":
            phone_osint()
        elif choice == "3":
            image_gps_osint()
        elif choice == "0":
            return
        else:
            console.print("[red]Invalid option[/red]")


# --------------------------- USERNAME OSINT ---------------------------

@dataclass
class SiteCheck:
    name: str
    url_template: str
    detector: Callable[[str, int, str], bool]


def detect_basic_notfound_keywords(html: str) -> bool:
    lowered = html.lower()
    keywords = [
        "not found",
        "page not found",
        "doesn't exist",
        "does not exist",
        "sorry, this page isn't available",
        "user not found",
        "404",
    ]
    return any(k in lowered for k in keywords)


def detector_github(html: str, status: int, final_url: str) -> bool:
    return status == 200


def detector_reddit(html: str, status: int, final_url: str) -> bool:
    return status == 200 and not detect_basic_notfound_keywords(html)


def detector_soft(html: str, status: int, final_url: str) -> bool:
    # For sites that block automated requests. We'll show "Possible (Verify)".
    return status in (200, 302)


SITES: List[SiteCheck] = [
    SiteCheck("GitHub", "https://github.com/{username}", detector_github),
    SiteCheck("Reddit", "https://www.reddit.com/user/{username}", detector_reddit),
    SiteCheck("X (Twitter)", "https://x.com/{username}", detector_soft),
    SiteCheck("Instagram", "https://www.instagram.com/{username}/", detector_soft),
]


def username_osint():
    username = input("\nEnter username (no spaces): ").strip()
    lines: List[str] = []
    data: Dict[str, Any] = {"username": username}

    if not re.match(r"^[A-Za-z0-9_.-]{2,30}$", username):
        console.print("[red]Invalid username format.[/red] Use letters/numbers/._- (2–30 chars).")
        lines.append("Invalid username format.")
        data["format_valid"] = False

        per = save_per_scan_report("username", username, lines)
        show_saved(per)
        append_session_text("username", username, lines)
        append_session_json("username", username, data)
        pause()
        return

    data["format_valid"] = True

    console.print(
        Panel(
            "Checks public profile URLs (no APIs).\n"
            "Some sites block automated requests—results may be [bold]Possible[/bold] and require manual verification.",
            title="Username OSINT Notes",
            box=box.ROUNDED,
        )
    )

    table = Table(title=f"Username OSINT: {username}", box=box.SIMPLE)
    table.add_column("Site")
    table.add_column("URL")
    table.add_column("Result")

    results: List[Dict[str, Any]] = []
    for site in SITES:
        url = site.url_template.format(username=username)

        time.sleep(1)  # polite delay
        resp, err = http_get(url, timeout=12)

        if err or resp is None:
            shown = "[yellow]Error/Blocked[/yellow]"
            table.add_row(site.name, url, shown)
            results.append({"site": site.name, "url": url, "result": "Error/Blocked"})
            continue

        status = resp.status_code
        html = resp.text or ""
        final_url = str(resp.url)

        try:
            found = site.detector(html, status, final_url)
        except Exception:
            found = False

        if status == 404 or (found and detect_basic_notfound_keywords(html)):
            result = "Not Found"
            shown = "[red]Not Found[/red]"
        elif found and status in (200, 302):
            if site.name in ("X (Twitter)", "Instagram"):
                result = "Possible (Verify)"
                shown = "[yellow]Possible (Verify)[/yellow]"
            else:
                result = "Found"
                shown = "[green]Found[/green]"
        else:
            result = "Unknown (Verify)"
            shown = "[yellow]Unknown (Verify)[/yellow]"

        table.add_row(site.name, final_url, shown)
        results.append({"site": site.name, "url": final_url, "result": result, "http": status})

    console.print(table)

    lines.append(f"Username: {username}")
    lines.append("Tip: 'Possible/Unknown' means open the URL in a browser to confirm.")
    lines.append("")
    for r in results:
        lines.append(f"{r.get('site')}: {r.get('url')} -> {r.get('result')} (HTTP {r.get('http', 'n/a')})")

    data["results"] = results

    per = save_per_scan_report("username", username, lines)
    show_saved(per)
    append_session_text("username", username, lines)
    append_session_json("username", username, data)
    pause()


# --------------------------- REPORTS: LIST & READ ---------------------------

def list_report_files() -> List[Path]:
    ensure_reports_dir()
    files = sorted(REPORTS_DIR.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def read_report_in_cli(path: Path, max_lines: int = 250) -> None:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        console.print("[red]Failed to read report.[/red]")
        return

    lines = content.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["", f"... (trimmed, showing first {max_lines} lines)"]

    console.print(Panel("\n".join(lines), title=str(path.name), box=box.ROUNDED))


def reports_list_and_read():
    files = list_report_files()
    if not files:
        console.print("[yellow]No reports found yet. Run a scan first.[/yellow]")
        pause()
        return

    table = Table(title="Reports (TXT) - newest first", box=box.SIMPLE)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Filename")
    table.add_column("Size")

    for i, p in enumerate(files[:30], start=1):
        size_kb = f"{p.stat().st_size/1024:.1f} KB"
        table.add_row(str(i), p.name, size_kb)

    console.print(table)
    choice = input("Enter report number to view (or 0 to back): ").strip()

    if choice == "0":
        return

    if not choice.isdigit():
        console.print("[red]Invalid choice[/red]")
        pause()
        return

    idx = int(choice)
    if idx < 1 or idx > min(len(files), 30):
        console.print("[red]Out of range[/red]")
        pause()
        return

    read_report_in_cli(files[idx - 1])
    pause()


# --------------------------- MAIN LOOP ---------------------------

def main():
    ensure_reports_dir()

    # Create session headers on first run
    if not SESSION_TXT.exists():
        SESSION_TXT.write_text(
            "SkyOSINT Session Report\n"
            f"Session start: {datetime.now().isoformat(timespec='seconds')}\n"
            f"TXT file: {SESSION_TXT.name}\n"
            f"JSON file: {SESSION_JSON.name}\n"
            + "=" * 60 + "\n\n",
            encoding="utf-8",
            errors="ignore",
        )
    if not SESSION_JSON.exists():
        SESSION_JSON.write_text("[]", encoding="utf-8", errors="ignore")

    show_banner()
    show_session_paths()

    while True:
        main_menu()
        choice = input("Select option: ").strip()

        if choice == "1":
            email_osint()
        elif choice == "2":
            phone_osint()
        elif choice == "3":
            domain_osint()
        elif choice == "4":
            ip_osint()
        elif choice == "5":
            location_osint()
        elif choice == "6":
            username_osint()
        elif choice == "7":
            show_session_paths()
            pause()
        elif choice == "8":
            reports_list_and_read()
        elif choice == "0":
            console.print("\n[green]Exit SkyOSINT[/green]")
            console.print(f"[dim]Session TXT:[/dim] {SESSION_TXT}")
            console.print(f"[dim]Session JSON:[/dim] {SESSION_JSON}")
            break
        else:
            console.print("[red]Invalid option[/red]")


if __name__ == "__main__":
    main()
