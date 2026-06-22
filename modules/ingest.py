import os
import sys
import json
import re
import hashlib
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

# Pre-flight check for Evtx
try:
    import Evtx.Evtx as evtx
except ImportError:
    print("Error: python-evtx not installed. Run: pip install python-evtx")
    sys.exit(1)

from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()

# --- CONSTANTS & MAPPINGS ---
WINDOWS_CATEGORY_MAP = {
    4688: "process_creation", 4624: "authentication", 4625: "authentication",
    4648: "authentication", 4663: "file_access", 4698: "service",
    4720: "authentication", 5156: "network_connection", 7045: "service"
}

SYSLOG_CATEGORY_MAP = {
    "sshd": "authentication", "sudo": "authentication", "cron": "service",
    "kernel": "generic", "systemd": "service"
}

TIMESTAMP_CANDIDATES = ["timestamp", "time", "@timestamp", "EventTime", "date"]
HOST_CANDIDATES = ["host", "hostname", "computer", "ComputerName", "machine"]

SYSLOG_REGEX = re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.*)$')

def _generate_uid(raw_line: str, timestamp: str) -> str:
    """Deterministic SHA256[:12] of raw line + timestamp"""
    hash_input = f"{raw_line}{timestamp}".encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()[:12]

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _strip_xml_namespaces(xml_string: str) -> ET.Element:
    """Removes annoying namespaces from EVTX XML for easier parsing."""
    it = ET.iterparse(fromstring(xml_string))
    for _, el in it:
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]  # strip namespace
    return it.root

from io import StringIO
def fromstring(text):
    return StringIO(text)

# --- PARSERS ---

def parse_evtx(filepath: str) -> tuple[list[dict], list[str]]:
    events = []
    errors = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = _strip_xml_namespaces(xml_str)
                    
                    sys_elem = root.find('System')
                    event_id_elem = sys_elem.find('EventID') if sys_elem else None
                    time_elem = sys_elem.find('TimeCreated') if sys_elem else None
                    
                    event_id = int(event_id_elem.text) if event_id_elem is not None else 0
                    timestamp = time_elem.attrib.get('SystemTime', _now_iso()) if time_elem is not None else _now_iso()
                    
                    # Extract EventData
                    fields = {}
                    event_data = root.find('EventData')
                    if event_data is not None:
                        for data in event_data.findall('Data'):
                            name = data.attrib.get('Name', 'Unknown')
                            fields[name] = data.text

                    # Map schema
                    raw_truncated = xml_str[:300]
                    category = WINDOWS_CATEGORY_MAP.get(event_id, "generic")
                    
                    event = {
                        "event_uid": _generate_uid(raw_truncated, timestamp),
                        "timestamp": timestamp,
                        "source_type": "windows_evtx",
                        "category": category,
                        "event_id": event_id,
                        "severity": "info", # Default until rule evaluated
                        "host": sys_elem.find('Computer').text if sys_elem and sys_elem.find('Computer') is not None else None,
                        "user": None, # Complex to extract reliably without specific EventID mapping, leave for rule fields
                        "fields": fields,
                        "raw_truncated": raw_truncated,
                        "ingested_at": _now_iso()
                    }
                    events.append(event)
                except Exception as e:
                    errors.append(f"Record parse error: {str(e)}")
    except Exception as e:
        errors.append(f"Failed to open EVTX: {str(e)}")
    return events, errors

def parse_syslog(filepath: str) -> tuple[list[dict], list[str]]:
    events = []
    errors = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                match = SYSLOG_REGEX.match(line)
                if match:
                    timestamp, host, process, message = match.groups()
                    process_clean = process.split('[')[0] # Remove PID if present e.g. sshd[1234]
                    category = SYSLOG_CATEGORY_MAP.get(process_clean, "generic")
                    
                    # Convert syslog time (usually missing year) to ISO - simplistic approach for lab
                    current_year = datetime.now().year
                    try:
                        ts_obj = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
                        iso_time = ts_obj.isoformat()
                    except ValueError:
                        iso_time = _now_iso()

                    event = {
                        "event_uid": _generate_uid(line[:300], iso_time),
                        "timestamp": iso_time,
                        "source_type": "syslog",
                        "category": category,
                        "event_id": 0,
                        "severity": "info",
                        "host": host,
                        "user": None,
                        "fields": {"process": process_clean, "message": message},
                        "raw_truncated": line[:300],
                        "ingested_at": _now_iso()
                    }
                    events.append(event)
                else:
                    errors.append(f"Unmatched syslog pattern: {line[:50]}...")
    except Exception as e:
        errors.append(f"Failed to read syslog file: {str(e)}")
    return events, errors

def parse_json_log(filepath: str) -> tuple[list[dict], list[str]]:
    events = []
    errors = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            
            # Handle JSON array vs JSONL
            if content.startswith('['):
                records = json.loads(content)
            else:
                records = [json.loads(line) for line in content.splitlines() if line.strip()]

            for rec in records:
                # Auto-detect timestamp
                timestamp = _now_iso()
                for tc in TIMESTAMP_CANDIDATES:
                    if tc in rec:
                        timestamp = rec[tc]
                        break
                
                # Auto-detect host
                host = None
                for hc in HOST_CANDIDATES:
                    if hc in rec:
                        host = rec[hc]
                        break

                raw_line = json.dumps(rec)[:300]
                event = {
                    "event_uid": _generate_uid(raw_line, timestamp),
                    "timestamp": timestamp,
                    "source_type": "generic_json",
                    "category": "generic", # Defaults to generic for basic JSON
                    "event_id": rec.get("event_id", rec.get("EventID", 0)),
                    "severity": "info",
                    "host": host,
                    "user": rec.get("user", rec.get("username")),
                    "fields": rec,
                    "raw_truncated": raw_line,
                    "ingested_at": _now_iso()
                }
                events.append(event)
    except json.JSONDecodeError as e:
        errors.append(f"JSON decode error: {str(e)}")
    except Exception as e:
        errors.append(f"Failed to read JSON file: {str(e)}")
    
    return events, errors

def _auto_detect_and_parse(filepath: str, format_override: str) -> tuple[list[dict], list[str]]:
    if format_override == "evtx" or (format_override == "auto" and filepath.lower().endswith('.evtx')):
        return parse_evtx(filepath)
    elif format_override == "json" or (format_override == "auto" and filepath.lower().endswith(('.json', '.jsonl'))):
        return parse_json_log(filepath)
    elif format_override == "syslog" or (format_override == "auto" and filepath.lower().endswith(('.log', 'syslog'))):
        return parse_syslog(filepath)
    else:
        # Fallback to syslog parsing rules
        return parse_syslog(filepath)

# --- CLI COMMAND HANDLERS ---

def run_parse(args):
    events, errors = _auto_detect_and_parse(args.file, args.format)
    
    if args.output in ["json", "both"]:
        print(json.dumps(events, indent=2))
        
    if args.output in ["terminal", "both"]:
        console.print(f"[bold green]Successfully parsed {len(events)} events.[/bold green]")
        if errors:
            console.print(f"[yellow]Encountered {len(errors)} parse errors/warnings.[/yellow]")

def run_summary(args):
    events, errors = _auto_detect_and_parse(args.file, "auto")
    
    if not events:
        console.print("[bold red]No events could be parsed to generate a summary.[/bold red]")
        return

    # Calculate stats
    total = len(events)
    categories = {}
    hosts = set()
    users = set()
    event_ids = {}
    timestamps = []

    for e in events:
        cat = e["category"]
        categories[cat] = categories.get(cat, 0) + 1
        
        if e["host"]: hosts.add(e["host"])
        if e["user"]: users.add(e["user"])
        
        eid = e.get("event_id")
        if eid: event_ids[eid] = event_ids.get(eid, 0) + 1
        
        timestamps.append(e["timestamp"])

    timestamps.sort()
    date_range = f"{timestamps[0]} to {timestamps[-1]}" if timestamps else "N/A"

    # Main Summary Table
    table = Table(title=f"Log Summary: {os.path.basename(args.file)}", show_header=True, header_style="bold blue")
    table.add_column("Category")
    table.add_column("Count", justify="right")
    table.add_column("% of Total", justify="right")
    table.add_column("Date Range")
    table.add_column("Unique Hosts", justify="right")

    for cat, count in sorted(categories.items(), key=lambda item: item[1], reverse=True):
        pct = (count / total) * 100
        table.add_row(cat, str(count), f"{pct:.1f}%", date_range, str(len(hosts)))

    console.print(table)
    console.print(f"\n[dim]Total Events: {total} | Unique Users: {len(users)}[/dim]")

    # Top 5 EventIDs Table
    if event_ids:
        eid_table = Table(title="Top 5 Event IDs", show_header=True, header_style="bold magenta")
        eid_table.add_column("Event ID")
        eid_table.add_column("Count", justify="right")
        
        top_5_eids = sorted(event_ids.items(), key=lambda item: item[1], reverse=True)[:5]
        for eid, count in top_5_eids:
            eid_table.add_row(str(eid), str(count))
        
        console.print("\n")
        console.print(eid_table)

    if errors:
        console.print(f"\n[yellow]Note: {len(errors)} warnings generated during parsing (run 'validate' to view).[/yellow]")

def run_validate(args):
    console.print(f"Validating file: [bold]{args.file}[/bold]...")
    events, errors = _auto_detect_and_parse(args.file, "auto")
    
    if errors:
        console.print(f"\n[bold yellow]Validation completed with {len(errors)} issues:[/bold yellow]")
        for err in errors[:20]: # Limit error output to keep terminal clean
            console.print(f"[yellow] - {err}[/yellow]")
        if len(errors) > 20:
            console.print(f"[yellow]... and {len(errors) - 20} more errors.[/yellow]")
        sys.exit(1)
    else:
        console.print(f"[bold green]Validation successful! {len(events)} events parsed cleanly.[/bold green]")
        sys.exit(0)