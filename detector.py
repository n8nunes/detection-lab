import argparse
import sys
from modules import ingest

def main():
    parser = argparse.ArgumentParser(
        description="Threat Detection Lab — Standalone CLI tool for log analysis"
    )
    subparsers = parser.add_subparsers(dest="module", required=True, help="Available modules")

    # --- INGEST MODULE ---
    ingest_parser = subparsers.add_parser("ingest", help="Log ingestion and normalisation")
    ingest_sub = ingest_parser.add_subparsers(dest="action", required=True, help="Ingest actions")

    # ingest parse
    parse_p = ingest_sub.add_parser("parse", help="Parse logs into a unified normalised schema")
    parse_p.add_argument("--file", required=True, help="Path to the log file")
    parse_p.add_argument("--format", choices=["auto", "evtx", "syslog", "json"], default="auto", help="Force log format")
    parse_p.add_argument("--output", choices=["terminal", "json", "both"], default="terminal", help="Output format")

    # ingest summary
    summary_p = ingest_sub.add_parser("summary", help="Print log summary statistics")
    summary_p.add_argument("--file", required=True, help="Path to the log file")

    # ingest validate
    validate_p = ingest_sub.add_parser("validate", help="Check file parseability and report errors")
    validate_p.add_argument("--file", required=True, help="Path to the log file")

    args = parser.parse_args()

    # Route to modules
    if args.module == "ingest":
        if args.action == "parse":
            ingest.run_parse(args)
        elif args.action == "summary":
            ingest.run_summary(args)
        elif args.action == "validate":
            ingest.run_validate(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)