from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import ScanIncomplete, inspect_tracked_file, scan_repository, scan_unicode


def _render(report: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    if "summary" in report:
        summary = report["summary"]
        print(f"Tracked files: {report['trackedFiles']}")
        print(f"Findings: {summary['high']} high, {summary['medium']} medium")
        h = report["historySecretScan"]
        print(f"History secret scan: {h['status']}" + (f" ({h.get('reason')})" if h.get("reason") else ""))
        for finding in report["findings"]:
            print(f"{finding.get('severity', 'info'):>6} {finding['path']}: {finding['type']}")
    elif "files" in report:
        print(f"Hidden Unicode findings: {report['findingCount']}")
        for item in report["files"]:
            for finding in item["findings"]:
                print(f"{item['path']}:{finding['line']}:{finding['column']} {finding['codepoint']} {finding['name']}")
    else:
        print(f"{report['path']}: {report['kind']}, {len(report['findings'])} finding(s)")
        for finding in report["findings"]:
            print(f"  {finding.get('severity', 'info')}: {finding['type']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repo-first-look")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="inspect Git-tracked files without executing them")
    scan.add_argument("path", type=Path)
    scan.add_argument("--format", choices=("text", "json"), default="text")
    file_cmd = commands.add_parser("file", help="inspect one file without executing it")
    file_cmd.add_argument("file", type=Path)
    file_cmd.add_argument("--format", choices=("text", "json"), default="text")
    unicode_cmd = commands.add_parser("unicode", help="report hidden Unicode in files or tracked repositories")
    unicode_cmd.add_argument("paths", nargs="+", type=Path)
    unicode_cmd.add_argument("--format", choices=("text", "json"), default="text")
    variation = commands.add_parser("variation", help="report Unicode variation selectors")
    variation.add_argument("files", nargs="+", type=Path)
    variation.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            report = scan_repository(args.path)
            _render(report, args.format)
            if report["summary"]["incomplete"]:
                return 2
            return 1 if report["summary"]["high"] or report["summary"]["historySecretFindings"] else 0
        if args.command == "file":
            report = inspect_tracked_file(args.file)
            _render(report, args.format)
            return 1 if any(f.get("severity") == "high" for f in report["findings"]) else 0
        report = scan_unicode(args.paths if args.command == "unicode" else args.files)
        if args.command == "variation":
            report["files"] = [{"path": i["path"], "findings": [f for f in i["findings"] if f["type"] == "variation-selector"]} for i in report["files"]]
            report["files"] = [i for i in report["files"] if i["findings"]]
            report["findingCount"] = sum(len(i["findings"]) for i in report["files"])
        _render(report, args.format)
        return 1 if report["findingCount"] else 0
    except (ScanIncomplete, FileNotFoundError, NotADirectoryError, PermissionError, ValueError) as exc:
        print(f"repo-first-look: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

