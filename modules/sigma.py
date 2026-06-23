import os
import yaml
import json
import time
from rich.console import Console
from rich.table import Table

console = Console()

# 2.5 Field Resolution Map (Mapping Sigma to Ingest Schema)
FIELD_MAP = {
    "CommandLine": "command_line",
    "NewProcessName": "process_name",
    "ProcessName": "process_name",
    "ParentProcessName": "parent_process_name",
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "IpAddress": "src_ip",
    "SourceAddress": "src_ip",
    "DestAddress": "dst_ip",
    "DestPort": "dst_port",
    "EventID": "event_id",
    "TaskName": "task_name",
    "Protocol": "protocol"
}

def load_rules(rules_dir: str) -> list[dict]:
    """2.1 Sigma Rule Internal Schema - parses YAML files into memory."""
    rules = []
    if not os.path.exists(rules_dir):
        console.print(f"[bold red]Rules directory not found: {rules_dir}[/bold red]")
        return rules

    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        rule_docs = yaml.safe_load_all(f)
                        for rule in rule_docs:
                            if rule and 'title' in rule and 'detection' in rule:
                                rules.append({
                                    "id": rule.get("id", "no-id"),
                                    "title": rule.get("title", "Untitled"),
                                    "level": rule.get("level", "low"),
                                    "logsource": rule.get("logsource", {}),
                                    "detection": rule.get("detection", {}),
                                    "tags": rule.get("tags", []),
                                    "description": rule.get("description", ""),
                                    "file": filepath
                                })
                except Exception as e:
                    console.print(f"[yellow]Warning: Failed to parse rule {filepath}: {e}[/yellow]")
    return rules

def _resolve_field(field_name: str, event: dict) -> any:
    """2.5 Resolves Sigma Original Fields -> Normalised Standardized Keys"""
    std_field = FIELD_MAP.get(field_name, field_name.lower())
    
    # 1. Check top-level event schema (e.g. event_id, host)
    if std_field in event and event[std_field] is not None:
        return event[std_field]
    
    # 2. Check inside the parsed fields dictionary
    fields_dict = event.get("fields", {})
    if std_field in fields_dict:
        return fields_dict[std_field]
        
    # 3. Fallback to exact original name in fields
    if field_name in fields_dict:
        return fields_dict[field_name]
        
    return None

def _match_selection(selection: dict, event: dict) -> bool:
    """Evaluates a single selection block (key:value pairs)."""
    if not isinstance(selection, dict):
        return False
        
    for field, expected_val in selection.items():
        actual_val = _resolve_field(field, event)
        if actual_val is None:
            return False
            
        # Support array matches (OR logic within a single field selection)
        if isinstance(expected_val, list):
            matched = any(str(val).lower() in str(actual_val).lower() for val in expected_val)
            if not matched: return False
        else:
            # Default contains/equals matching logic
            if str(expected_val).lower() not in str(actual_val).lower():
                return False
    return True

def evaluate_rule(event: dict, rule: dict) -> bool:
    """Evaluates a normalised event against a single Sigma rule."""
    
    # 2.4 Logsource Matching
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "").lower()
    product = logsource.get("product", "").lower()
    
    event_cat = event.get("category", "")
    source_type = event.get("source_type", "")
    
    if category and category != event_cat:
        return False
    if product == "windows" and "windows" not in source_type:
        return False
    if product == "linux" and "syslog" not in source_type:
        return False
        
    # 2.3 Condition Evaluation Parser
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    if not condition: return False
        
    try:
        # Simplistic parser matching specific roadmap requirements
        if condition in detection:
            # Direct single selection e.g. "condition: selection"
            return _match_selection(detection[condition], event)
            
        elif "1 of " in condition:
            # E.g. "1 of selection*"
            target = condition.split("1 of ")[1].strip().replace("*", "")
            return any(_match_selection(val, event) for key, val in detection.items() if key.startswith(target) and key != "condition")
            
        elif "all of " in condition:
            # E.g. "all of selection*"
            target = condition.split("all of ")[1].strip().replace("*", "")
            return all(_match_selection(val, event) for key, val in detection.items() if key.startswith(target) and key != "condition")
            
        elif " and " in condition or " or " in condition:
            # Simplistic multi-term logic: "selection1 and selection2"
            parts = [p.strip() for p in condition.split(" and ")]
            return all(_match_selection(detection[p], event) for p in parts if p in detection)
            
    except Exception:
        # Unsupported syntax -> log warning, skip rule, continue per roadmap rules
        pass

    return False

def run_scan(args, ingest_module):
    """Executes the log scan against the Sigma ruleset."""
    start_time = time.time()
    
    console.print(f"Loading rules from [bold]{args.rules_dir}[/bold]...")
    rules = load_rules(args.rules_dir)
    if not rules:
        return
        
    console.print(f"Ingesting logs from [bold]{args.log_file}[/bold]...")
    events, errors = ingest_module._auto_detect_and_parse(args.log_file, "auto")
    console.print(f"Parsed [bold green]{len(events)}[/bold green] events for scanning.\n")
    
    matches = []
    for event in events:
        for rule in rules:
            if evaluate_rule(event, rule):
                # 2.6 Match Record Schema
                matches.append({
                    "timestamp": event.get("timestamp"),
                    "level": rule.get("level", "low").lower(),
                    "rule_title": rule.get("title"),
                    "category": event.get("category", "generic"),
                    "host": event.get("host") or "N/A",
                    "user": event.get("user") or "N/A",
                    "techniques": [t for t in rule.get("tags", []) if t.startswith("attack.")],
                    "event_uid": event.get("event_uid"),
                    "raw_truncated": event.get("raw_truncated")
                })

    scan_time = time.time() - start_time
    
    # 2.8 Terminal Rendering
    if not matches:
        console.print(f"[[bold green]INFO[/bold green]] No rule matches in provided log file.")
    else:
        table = Table(title="Sigma Scan Results", show_header=True, header_style="bold blue")
        table.add_column("Timestamp")
        table.add_column("Level")
        table.add_column("Rule Title")
        table.add_column("Category")
        table.add_column("Host")
        table.add_column("User")
        table.add_column("Techniques")
        
        level_colors = {
            "critical": "bold magenta", "high": "bold red",
            "medium": "bold yellow", "low": "green", "info": "dim"
        }
        
        for m in matches:
            lvl_color = level_colors.get(m["level"], "white")
            c_lvl = f"[{lvl_color}]{m['level'].upper()}[/]"
            techs = ", ".join([t.replace("attack.", "") for t in m["techniques"]])
            table.add_row(
                str(m["timestamp"]), c_lvl, str(m["rule_title"]), 
                str(m["category"]), str(m["host"]), str(m["user"]), techs
            )
        console.print(table)
        
    # Print summary panel
    console.print(f"\n[dim]Scan Summary: {len(events)} events scanned | {len(rules)} rules evaluated | {len(matches)} matches | Scan time {scan_time:.2f}s[/dim]")
    
    if args.output in ["json", "both"]:
        with open("scan_results.json", "w") as f:
            json.dump(matches, f, indent=2)
        console.print("[dim]Results saved to scan_results.json[/dim]")

def run_rules_list(args):
    """Lists available Sigma rules in the given directory."""
    rules = load_rules(args.rules_dir)
    if not rules: return
        
    table = Table(title=f"Sigma Rules Library: {args.rules_dir}", show_header=True)
    table.add_column("Rule Title")
    table.add_column("Level")
    table.add_column("Category")
    table.add_column("Data Source")
    
    for rule in rules:
        logsource = rule.get("logsource", {})
        table.add_row(
            rule["title"], rule["level"], 
            logsource.get("category", "N/A"), 
            logsource.get("product", "N/A")
        )
        
    console.print(table)
    console.print(f"\n[dim]Total valid rules loaded: {len(rules)}[/dim]")