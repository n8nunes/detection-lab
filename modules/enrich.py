import os
import sys
import json
import time
import re
import ipaddress
import base64

try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    print("Error: requests or python-dotenv not installed. Run: pip install requests python-dotenv")
    sys.exit(1)

from rich.console import Console
from rich.table import Table

console = Console()

# Load environment variables from .env file
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def is_public_ip(ip_str: str) -> bool:
    """Validates if an IP string is a routable public IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_multicast and not ip.is_unspecified
    except ValueError:
        return False

def extract_iocs(scan_results: list) -> tuple[dict, int]:
    """Extracts IPv4 addresses and SHA256 hashes from matched logs, handling embedded strings without word boundaries."""
    iocs = {"ip": set(), "hash": set()}
    skipped_ips = set()
    
    # Boundary-agnostic regex patterns to capture embedded tokens
    ip_pattern = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
    hash_pattern = re.compile(r'[a-fA-F0-9]{64}')

    for match in scan_results:
        raw_text = match.get("raw_truncated", "")
        
        # 1. Scan the raw text directly using the boundary-free pattern
        for ip in ip_pattern.findall(raw_text):
            if is_public_ip(ip):
                iocs["ip"].add(ip)
            else:
                skipped_ips.add(ip)
        for h in hash_pattern.findall(raw_text):
            iocs["hash"].add(h.lower())
            
        # 2. Extract alphanumeric blocks to cover deep base64 sub-alignment windows
        blocks = re.findall(r'[a-zA-Z0-9+/=]{4,}', raw_text)
        for block in blocks:
            for start in range(len(block)):
                for end in range(start + 4, len(block) + 1):
                    substring = block[start:end]
                    try:
                        # Ensure proper padding length dynamically
                        padded_substring = substring + "=" * ((4 - len(substring) % 4) % 4)
                        decoded_text = base64.b64decode(padded_substring).decode('utf-8', errors='ignore')
                        
                        if decoded_text:
                            for ip in ip_pattern.findall(decoded_text):
                                if is_public_ip(ip):
                                    iocs["ip"].add(ip)
                                else:
                                    skipped_ips.add(ip)
                            for h in hash_pattern.findall(decoded_text):
                                iocs["hash"].add(h.lower())
                    except Exception:
                        continue
            
    return iocs, len(skipped_ips)

def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        console.print("[yellow]Skipping AbuseIPDB check: API key not set in .env[/yellow]")
        return {}
        
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        
        res = requests.get(url, headers=headers, params=params, timeout=10)
        res.raise_for_status()
        data = res.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        
        # Map to boolean schema required by Roadmap Phase 4.4
        return {
            "abuse_confidence_score": score,
            "is_tor": data.get("isTor", False),
            "moderate_abuse_reports": score > 0,
            "abuse_confidence_high": score >= 50,
            "known_malicious": score >= 80
        }
    except Exception as e:
        console.print(f"[dim yellow]AbuseIPDB error for {ip}: {e}[/dim yellow]")
        return {}

def check_virustotal(ioc: str, ioc_type: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        console.print("[yellow]Skipping VirusTotal check: API key not set in .env[/yellow]")
        return {}
        
    try:
        # Phase 4.3 Constraint: Enforce 15 second delay for VT free tier (4 req/min)
        console.print("[dim]Waiting 15s to respect VirusTotal rate limits...[/dim]")
        time.sleep(15) 
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if ioc_type == 'ip' else 'files'}/{ioc}"
            
        res = requests.get(url, headers=headers, timeout=10)
        res.raise_for_status()
        stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        
        return {
            "vt_malicious_count": malicious_count,
            "vt_flagged": malicious_count > 0,
            "vt_high_confidence": malicious_count >= 5,
            "known_malicious": malicious_count >= 10
        }
    except Exception as e:
        console.print(f"[dim yellow]VirusTotal error for {ioc}: {e}[/dim yellow]")
        return {}

def run_enrich(args):
    """4.5 CLI Command Handler"""
    if not os.path.exists(args.scan_results):
        console.print(f"[bold red]Scan results file not found: {args.scan_results}[/bold red]")
        sys.exit(1)

    with open(args.scan_results, 'r', encoding='utf-8') as f:
        scan_results = json.load(f)

    if not scan_results:
        console.print("[yellow]No rule matches found in scan results to enrich.[/yellow]")
        return

    iocs, skipped_count = extract_iocs(scan_results)
    total_iocs = len(iocs["ip"]) + len(iocs["hash"])
    console.print(f"[bold blue]Extracted {total_iocs} unique public IOCs for enrichment.[/bold blue]")
    
    enrichment_data = {}
    
    for ip in iocs["ip"]:
        console.print(f"Enriching IP: {ip}")
        ab_data = check_abuseipdb(ip)
        vt_data = check_virustotal(ip, "ip")
        
        enrichment_data[ip] = {
            "type": "ip",
            "abuse_confidence_high": ab_data.get("abuse_confidence_high", False),
            "moderate_abuse_reports": ab_data.get("moderate_abuse_reports", False),
            "vt_high_confidence": vt_data.get("vt_high_confidence", False),
            "vt_flagged": vt_data.get("vt_flagged", False),
            "is_tor": ab_data.get("is_tor", False),
            "known_malicious": ab_data.get("known_malicious", False) or vt_data.get("known_malicious", False),
            "raw_scores": {
                "abuseipdb": ab_data.get("abuse_confidence_score", 0),
                "vt_malicious": vt_data.get("vt_malicious_count", 0)
            }
        }

    for h in iocs["hash"]:
        console.print(f"Enriching Hash: {h}")
        vt_data = check_virustotal(h, "hash")
        enrichment_data[h] = {
            "type": "hash",
            "vt_high_confidence": vt_data.get("vt_high_confidence", False),
            "vt_flagged": vt_data.get("vt_flagged", False),
            "known_malicious": vt_data.get("known_malicious", False),
            "raw_scores": {
                "vt_malicious": vt_data.get("vt_malicious_count", 0)
            }
        }

    # Atomic write to protect data pipeline
    out_file = args.out
    tmp_file = out_file + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(enrichment_data, f, indent=2)
    os.replace(tmp_file, out_file)
    
    # 4.6 Terminal Rendering
    table = Table(title="IOC Enrichment Summary", show_header=True)
    table.add_column("IOC")
    table.add_column("Type")
    table.add_column("Abuse Conf")
    table.add_column("VT Flagged")
    table.add_column("Tor")
    table.add_column("Overall")

    for ioc, data in enrichment_data.items():
        ioc_type = data["type"].upper()
        ab_conf = f"{data['raw_scores'].get('abuseipdb', 0)}%" if ioc_type == "IP" else "N/A"
        vt_flag = str(data["vt_flagged"])
        is_tor = str(data.get("is_tor", "N/A"))
        
        # Severity thresholds per roadmap constraints
        if data["known_malicious"] or data["vt_high_confidence"]:
            overall = "MALICIOUS"
            row_style = "bold red"
        elif data["moderate_abuse_reports"] or data["vt_flagged"]:
            overall = "SUSPICIOUS"
            row_style = "bold yellow"
        else:
            overall = "BENIGN"
            row_style = "bold green"
            
        table.add_row(ioc, ioc_type, ab_conf, vt_flag, is_tor, overall, style=row_style)

    console.print("\n")
    console.print(table)
    console.print(f"[dim]Skipped {skipped_count} private/loopback IPs[/dim]")
    console.print(f"[dim]Results safely exported to {out_file}[/dim]")