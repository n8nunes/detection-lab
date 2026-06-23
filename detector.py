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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)