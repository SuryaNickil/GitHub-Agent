#!/usr/bin/env python3
"""Entry point — run the dashboard or a CLI scan."""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="Repo Security Scanner")
    sub = parser.add_subparsers(dest="command")

    # Dashboard mode
    serve_p = sub.add_parser("serve", help="Start the web dashboard")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=5000)
    serve_p.add_argument("--debug", action="store_true")

    # CLI scan mode
    scan_p = sub.add_parser("scan", help="Scan a repo from the command line")
    scan_p.add_argument("repo", help="Git repo URL or local path")
    scan_p.add_argument("--json", dest="as_json", action="store_true", help="Output raw JSON")

    args = parser.parse_args()

    if args.command == "serve":
        from scanner.dashboard import app
        print(f"Starting dashboard at http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=args.debug)

    elif args.command == "scan":
        from scanner.graph import run_scan
        print(f"Scanning: {args.repo}\n")
        result = run_scan(args.repo)

        if result.get("error"):
            print(f"Error: {result['error']}")
            sys.exit(1)

        if args.as_json:
            print(json.dumps({
                "summary": result.get("summary"),
                "vulnerabilities": result.get("vulnerabilities"),
            }, indent=2))
        else:
            summary = result.get("summary", {})
            vulns = result.get("vulnerabilities", [])

            print("=" * 60)
            print(f"  SCAN RESULTS — {summary.get('total', 0)} vulnerabilities found")
            print("=" * 60)
            print(f"  CRITICAL: {summary.get('critical', 0)}  |  HIGH: {summary.get('high', 0)}  |  MEDIUM: {summary.get('medium', 0)}  |  LOW: {summary.get('low', 0)}")
            src = summary.get("sources", {})
            print(f"  Sources → Bandit: {src.get('bandit',0)}  Pattern: {src.get('pattern',0)}  AI: {src.get('ai',0)}")
            print("=" * 60)

            for v in vulns:
                sev = v.get("severity", "?")
                marker = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~"}.get(sev, " ")
                print(f"\n  [{marker}] {sev} — {v.get('title')}")
                print(f"      File: {v.get('file')}:{v.get('line', '?')}")
                print(f"      Source: {v.get('source')}  |  Confidence: {v.get('confidence')}")
                desc = v.get("description", "")
                if desc:
                    print(f"      {desc[:120]}")
            print()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
