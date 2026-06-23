import argparse
import sys
from modules import ingest, sigma

def main():
    parser = argparse.ArgumentParser(
        description="Threat Detection Lab — Standalone CLI tool for log analysis"
    )
    subparsers = parser.add_subparsers(dest="module", required=True, help="Available modules")

    # --- INGEST MODULE (Phase 1) ---
    ingest_parser = subparsers.add_parser("ingest", help="Log ingestion and normalisation")
    ingest_sub = ingest_parser.add_subparsers(dest="action", required=True, help="Ingest actions")

    parse_p = ingest_sub.add_parser("parse", help="Parse logs into a unified normalised schema")
    parse_p.add_argument("--file", required=True, help="Path to the log file")
    parse_p.add_argument("--format", choices=["auto", "evtx", "syslog", "json"], default="auto", help="Force log format")
    parse_p.add_argument("--output", choices=["terminal", "json", "both"], default="terminal", help="Output format")

    summary_p = ingest_sub.add_parser("summary", help="Print log summary statistics")
    summary_p.add_argument("--file", required=True, help="Path to the log file")

    validate_p = ingest_sub.add_parser("validate", help="Check file parseability and report errors")
    validate_p.add_argument("--file", required=True, help="Path to the log file")

    # --- RULES MODULE (Phase 2) ---
    rules_parser = subparsers.add_parser("rules", help="Manage and view parsed Sigma rules")
    rules_parser.add_argument("--rules-dir", required=True, help="Path to the directory containing .yml Sigma rules")

    # --- SCAN MODULE (Phase 2) ---
    scan_parser = subparsers.add_parser("scan", help="Scan ingested logs against a Sigma ruleset")
    scan_parser.add_argument("--log-file", required=True, help="Path to the log file to parse and scan")
    scan_parser.add_argument("--rules-dir", required=True, help="Path to Sigma rules directory")
    scan_parser.add_argument("--output", choices=["terminal", "json", "both"], default="terminal", help="Output format")

    # --- ATT&CK MODULE (Phase 3) ---
    attack_parser = subparsers.add_parser("attack", help="MITRE ATT&CK Mapping and Coverage")
    attack_sub = attack_parser.add_subparsers(dest="action", required=True, help="ATT&CK actions")

    coverage_p = attack_sub.add_parser("coverage", help="Analyze rule coverage against ATT&CK matrix")
    coverage_p.add_argument("--rules-dir", required=True, help="Path to Sigma rules directory")
    coverage_p.add_argument("--refresh-attack", action="store_true", help="Force re-download of ATT&CK matrix")

    navigator_p = attack_sub.add_parser("navigator", help="Export ATT&CK Navigator layer")
    navigator_p.add_argument("--rules-dir", required=True, help="Path to Sigma rules directory")
    navigator_p.add_argument("--out", default="navigator_layer.json", help="Output file path")
    navigator_p.add_argument("--refresh-attack", action="store_true", help="Force re-download of ATT&CK matrix")

    # --- ENRICH MODULE (Phase 4) ---
    enrich_parser = subparsers.add_parser("enrich", help="Extract and enrich IOCs from rule matches")
    enrich_parser.add_argument("--scan-results", default="scan_results.json", help="Path to the Phase 2 scan results file")
    enrich_parser.add_argument("--out", default="enrichment_results.json", help="Output JSON file for boolean enrichment flags")

    # --- TRIAGE MODULE (Phase 5) ---
    triage_parser = subparsers.add_parser("triage", help="AI-assisted triage of rule matches")
    triage_sub = triage_parser.add_subparsers(dest="action", required=True, help="Triage actions")

    triage_run_p = triage_sub.add_parser("run", help="Execute single-pass AI triage pipeline")
    triage_run_p.add_argument("--scan-results", default="scan_results.json", help="Path to Phase 2 scan results")
    triage_run_p.add_argument("--enrich-results", default="enrichment_results.json", help="Path to Phase 4 enrich results")

    triage_over_p = triage_sub.add_parser("override", help="Manual human override of AI verdict")
    triage_over_p.add_argument("--id", required=True, help="The 8-character ID of the triage record")
    triage_over_p.add_argument("--verdict", required=True, choices=["Escalate", "Monitor", "False Positive"], help="New verdict")

    # --- REPORT MODULE (Phase 5) ---
    report_parser = subparsers.add_parser("report", help="Export triaged records to JSON report")
    report_parser.add_argument("--out", default="triage_report.json", help="Output filepath")

    args = parser.parse_args()

    # Route logic to corresponding modules
    if args.module == "ingest":
        if args.action == "parse":
            ingest.run_parse(args)
        elif args.action == "summary":
            ingest.run_summary(args)
        elif args.action == "validate":
            ingest.run_validate(args)
    elif args.module == "rules":
        sigma.run_rules_list(args)
    elif args.module == "scan":
        sigma.run_scan(args, ingest)
    elif args.module == "attack":
        # Lazy import so Phase 1 and 2 don't load requests if not needed
        from modules import attack
        if args.action == "coverage":
            attack.run_coverage(args)
        elif args.action == "navigator":
            attack.run_navigator(args)
    elif args.module == "enrich":
        from modules import enrich
        enrich.run_enrich(args)
    elif args.module == "triage":
        from modules import triage
        if args.action == "run":
            triage.run_triage(args)
        elif args.action == "override":
            triage.run_override(args)
    elif args.module == "report":
        from modules import triage
        triage.run_report(args)
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)