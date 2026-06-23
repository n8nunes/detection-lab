import json
import os
from rich.console import Console
from rich.table import Table
from modules import ollama, sanitize, store

console = Console()

def run_triage(args):
    """Executes the AI-assisted triage pipeline."""
    if not os.path.exists(args.scan_results):
        console.print(f"[bold red]Cannot find scan results: {args.scan_results}[/bold red]")
        return

    with open(args.scan_results, 'r') as f:
        matches = json.load(f)

    enrichment_data = {}
    if os.path.exists(args.enrich_results):
        with open(args.enrich_results, 'r') as f:
            enrichment_data = json.load(f)

    for match in matches:
        uid = match.get("event_uid")
        
        # 1. Structure the input (Phase 5.1 & Bias constraints)
        payload = {
            "rule": match.get("rule_title")[:80],
            "category": match.get("category"),
            "techniques": match.get("techniques", [])[:3],
            "log_snippet": match.get("raw_truncated", "")[:200],  # STRICT 200 char limit
            "enrichment": {}
        }

        # Filter enrichment to booleans only, removing IP/Hash identities
        for ioc, data in enrichment_data.items():
            if str(ioc) in match.get("raw_truncated", ""):
                payload["enrichment"] = {
                    "known_malicious": data.get("known_malicious", False),
                    "vt_flagged": data.get("vt_flagged", False),
                    "abuse_confidence_high": data.get("abuse_confidence_high", False)
                }
                break
        
        # 2. Call Ollama & 3. Sanitize Response
        console.print(f"[dim]Triaging event {uid[:8]} via Ollama...[/dim]")
        raw_response = ollama.generate_triage(payload)
        safe_response = sanitize.sanitize_triage(raw_response)

        # 4. Compile and Save Record
        record = {
            "event_uid": uid,
            "timestamp": match.get("timestamp"),
            "rule_title": match.get("rule_title"),
            "verdict": safe_response["verdict"],
            "confidence": safe_response["confidence"],
            "reasoning": safe_response["reasoning"],
            "is_ai_assisted": True,
            "human_override": False
        }
        store.save_triage_record(record)

    render_triage_list()

def run_override(args):
    """Allows a human analyst to override the AI verdict."""
    records = store.load_triage_records()
    for r in records:
        if r.get("id") == args.id:
            r["verdict"] = args.verdict
            r["human_override"] = True
            store.save_triage_record(r)
            console.print(f"[bold green]Successfully overridden triage ID {args.id} to {args.verdict}[/bold green]")
            render_triage_list()
            return
    console.print(f"[bold red]Triage ID {args.id} not found.[/bold red]")

def render_triage_list():
    """Renders the Rich table specified in 5.7."""
    records = store.load_triage_records()
    if not records:
        console.print("[yellow]No triage records found.[/yellow]")
        return

    table = Table(title="AI-Assisted Triage List", show_header=True)
    table.add_column("ID")
    table.add_column("Rule")
    table.add_column("Verdict")
    table.add_column("Conf")
    table.add_column("AI")
    table.add_column("Status")

    stats = {"Escalate": 0, "Monitor": 0, "False Positive": 0}

    for r in records:
        v = r["verdict"]
        stats[v] = stats.get(v, 0) + 1

        v_style = "bold red" if v == "Escalate" else "yellow" if v == "Monitor" else "dim green"
        c_style = "bold" if r["confidence"] == "HIGH" else "normal" if r["confidence"] == "MEDIUM" else "dim"
        ai_badge = "[cyan][AI-assisted][/cyan]" if r["is_ai_assisted"] and not r.get("human_override") else "[magenta][Human][/magenta]"

        table.add_row(
            r.get("id", "N/A"),
            r.get("rule_title", "Unknown")[:40],
            f"[{v_style}]{v}[/]",
            f"[{c_style}]{r['confidence']}[/]",
            ai_badge,
            r.get("status", "active")
        )

    console.print(table)
    console.print(f"[dim]Summary: {stats['Escalate']} Escalate | {stats['Monitor']} Monitor | {stats['False Positive']} False Positive[/dim]")

def run_report(args):
    """Generates the JSON report for SIEM ingestion."""
    records = store.load_triage_records()
    out_file = args.out
    
    store._atomic_write(out_file, records)
    console.print(f"[bold green]Triage report safely exported to {out_file}[/bold green]")