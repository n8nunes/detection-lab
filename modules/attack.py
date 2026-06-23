import os
import sys
import json

# Pre-flight check for requests
try:
    import requests
except ImportError:
    print("Error: requests not installed. Run: pip install requests")
    sys.exit(1)

from rich.console import Console
from rich.table import Table
from modules import sigma

console = Console()

# --- CONSTANTS ---
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = "./data"
CACHE_FILE = os.path.join(DATA_DIR, "attack_matrix.json")

def download_attack_matrix(refresh: bool = False):
    """3.1 ATT&CK Matrix Download + Cache"""
    os.makedirs(DATA_DIR, exist_ok=True)
    
    if os.path.exists(CACHE_FILE) and not refresh:
        return

    console.print("[dim]Downloading MITRE ATT&CK STIX bundle... This may take a moment.[/dim]")
    try:
        response = requests.get(ATTACK_URL, timeout=30)
        response.raise_for_status()
        
        # Atomic write: write to .tmp then replace
        tmp_file = CACHE_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(response.text)
        os.replace(tmp_file, CACHE_FILE)
        
        console.print("[green]ATT&CK matrix cached successfully.[/green]")
    except Exception as e:
        console.print(f"[bold red]Failed to download ATT&CK matrix: {e}[/bold red]")
        sys.exit(1)

def load_techniques() -> dict:
    """3.2 Technique Record Schema - Parses STIX into usable ID -> Name mapping"""
    if not os.path.exists(CACHE_FILE):
        return {}
        
    techniques = {}
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        if tid:
                            techniques[tid.upper()] = {
                                "name": obj.get("name", "Unknown"),
                                "url": ref.get("url", ""),
                                "description": obj.get("description", "")
                            }
    return techniques

def extract_rule_coverage(rules_dir: str) -> dict:
    """Extracts T-codes from Sigma rules in the given directory."""
    rules = sigma.load_rules(rules_dir)
    coverage = {}  # T-Code -> list of rule titles
    
    for rule in rules:
        for tag in rule.get("tags", []):
            if tag.lower().startswith("attack.t"):
                tid = tag.split(".")[1].upper()
                if tid not in coverage:
                    coverage[tid] = []
                coverage[tid].append(rule["title"])
                
    return coverage

# --- CLI COMMAND HANDLERS ---

def run_coverage(args):
    """3.3 Coverage Analysis & 3.6 Terminal Rendering"""
    download_attack_matrix(args.refresh_attack)
    matrix = load_techniques()
    coverage = extract_rule_coverage(args.rules_dir)
    
    table = Table(title="ATT&CK Coverage Analysis", show_header=True, header_style="bold blue")
    table.add_column("Technique ID")
    table.add_column("Technique Name")
    table.add_column("Rule Count", justify="right")
    table.add_column("Covering Rules")

    for tid, rules in sorted(coverage.items()):
        name = matrix.get(tid, {}).get("name", "Unknown Technique")
        table.add_row(tid, name, str(len(rules)), ", ".join(rules))

    console.print(table)
    console.print(f"\n[dim]Total Covered Techniques: {len(coverage)} / {len(matrix)} available in STIX bundle[/dim]")

def run_navigator(args):
    """3.4 ATT&CK Navigator Layer Export"""
    download_attack_matrix(args.refresh_attack)
    coverage = extract_rule_coverage(args.rules_dir)
    
    layer = {
        "name": "Detection Lab Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Exported from Threat Detection Lab CLI",
        "techniques": []
    }
    
    for tid, rules in coverage.items():
        layer["techniques"].append({
            "techniqueID": tid,
            "color": "#ff6666",  # Highlighted red for visibility in the Navigator
            "comment": f"Covered by: {', '.join(rules)}",
            "enabled": True,
            "score": len(rules)
        })
        
    out_path = args.out
    
    # Atomic write to protect data
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    os.replace(tmp_path, out_path)
    
    console.print(f"[bold green]Navigator layer exported successfully to: {out_path}[/bold green]")
    console.print("[dim]Upload this file to https://mitre-attack.github.io/attack-navigator/ to view your heatmap.[/dim]")