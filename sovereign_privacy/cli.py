"""
Command Line Interface (CLI) for Sovereign Privacy Agent.
Usage:
  python -m sovereign_privacy.cli scan
  python -m sovereign_privacy.cli rtbf --target "spokeo.com" --law GDPR
  python -m sovereign_privacy.cli honeytoken --type HONEY_URL --label "Personal Blog"
  python -m sovereign_privacy.cli cycle
  python -m sovereign_privacy.cli serve [--port 8000]
"""

import sys
import argparse
import json
import uvicorn

from sovereign_privacy.db.storage import Storage
from sovereign_privacy.core.orchestrator import PrivacyOrchestrator
from sovereign_privacy.web.app import app

def main():
    parser = argparse.ArgumentParser(
        prog="sovereign-privacy",
        description="SovereignGuard AI - Personal Sovereign Privacy Protection CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Scan command
    subparsers.add_parser("scan", help="Run full leak scan across monitored email targets")

    # RTBF command
    rtbf_parser = subparsers.add_parser("rtbf", help="Generate an RTBF legal request letter")
    rtbf_parser.add_argument("--target", required=True, help="Target entity name or domain")
    rtbf_parser.add_argument("--contact", default="", help="Target privacy contact email")
    rtbf_parser.add_argument("--law", default="GDPR", choices=["GDPR", "CCPA", "PIPEDA", "GENERIC"], help="Legal framework")

    # Honeytoken command
    ht_parser = subparsers.add_parser("honeytoken", help="Deploy anti-scraping honeytoken canary")
    ht_parser.add_argument("--type", default="HONEY_URL", choices=["HONEY_URL", "HONEY_EMAIL", "DECOY_PII"])
    ht_parser.add_argument("--label", default="CLI Deployed Canary")

    # Cycle command
    subparsers.add_parser("cycle", help="Execute an autonomous agent defense cycle")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Launch Web GUI Dashboard & REST API server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host address")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number")

    args = parser.parse_args()

    storage = Storage()
    orchestrator = PrivacyOrchestrator(storage)

    if args.command == "scan":
        print("\n[+] Initiating Sovereign Privacy Leak Scan...")
        results = orchestrator.leak_monitor.run_full_scan()
        print(f"\n[=] Scan Complete!")
        print(f"    Privacy Health Score : {results['privacy_health_score']} / 100 ({results['rating']})")
        print(f"    Scanned Targets      : {', '.join(results['scanned_targets'])}")
        print(f"    Total Exposures      : {results['total_leaks']}")
        print(f"    Unresolved Exposures : {results['unresolved_leaks']}\n")

    elif args.command == "rtbf":
        contact = args.contact or f"privacy@{args.target}"
        req = orchestrator.rtbf_agent.create_request(
            target_entity=args.target,
            target_contact=contact,
            jurisdiction=args.law
        )
        print(f"\n[+] Created RTBF Request ID: {req['id']}")
        print(f"    Target Entity : {req['target_entity']}")
        print(f"    Jurisdiction  : {req['jurisdiction']}")
        print(f"    Status        : {req['status']}\n")
        print("--- GENERATED LEGAL NOTICE ---")
        print(req['notice_text'])

    elif args.command == "honeytoken":
        ht = orchestrator.anti_scraper.create_honeytoken(
            token_type=args.type,
            label=args.label
        )
        print(f"\n[+] Deployed Anti-Scraping Honeytoken ({ht['token_type']})")
        print(f"    Canary Key : {ht['key']}")
        print(f"    Embed Code : {ht['embed_code']}\n")

    elif args.command == "cycle":
        print("\n[+] Running Autonomous Privacy Defense Cycle...")
        summary = orchestrator.execute_autonomous_defense_cycle()
        print(json.dumps(summary, indent=2))

    elif args.command == "serve":
        print(f"\n[+] Starting SovereignGuard AI Web Dashboard on http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
