"""Fail CI when Bandit findings differ from the reviewed, exact baseline.

Bandit's built-in baseline compares findings by rule and file, so a new
finding of the same kind in the same file can be hidden. This comparison also
checks the original line and surrounding code digest for every finding.
"""

import hashlib
import json
import sys
from pathlib import Path


def reviewed_finding(item):
    return {
        "filename": item["filename"],
        "line_number": item["line_number"],
        "test_id": item["test_id"],
        "issue_severity": item["issue_severity"],
        "issue_confidence": item["issue_confidence"],
        "issue_text": item["issue_text"],
        "code_sha256": hashlib.sha256(item["code"].encode()).hexdigest(),
    }


def main(report_path, baseline_path):
    report = json.loads(Path(report_path).read_text())
    if report.get("errors"):
        raise SystemExit(f"Bandit could not scan all files: {report['errors']}")

    current = [reviewed_finding(item) for item in report["results"]]
    baseline = json.loads(Path(baseline_path).read_text())["findings"]
    key = lambda item: (item["filename"], item["line_number"], item["test_id"], item["code_sha256"])
    current.sort(key=key)
    baseline.sort(key=key)
    if current == baseline:
        print(f"Bandit baseline unchanged: {len(current)} reviewed medium/high findings.")
        return

    for label, findings in (("Current", current), ("Baseline", baseline)):
        print(f"{label}: {len(findings)} medium/high findings", file=sys.stderr)
        for item in findings:
            print(f"  {item['filename']}:{item['line_number']} {item['test_id']} {item['code_sha256'][:12]}", file=sys.stderr)
    raise SystemExit("Bandit findings changed. Review the code and update the exact baseline deliberately.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_bandit_baseline.py REPORT.json BASELINE.json")
    main(sys.argv[1], sys.argv[2])
