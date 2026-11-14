"""Drain bounded IP registry and legacy fraud-flag privacy maintenance batches.

Run daily with --apply after taking a consistent database backup. This command
prints aggregate counts only; it never prints an address, hash, or account ID.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="required to mutate the configured database")
    parser.add_argument("--max-batches", type=int, default=100, help="maximum 1000-row batches per run (1-1000)")
    args = parser.parse_args()
    if not args.apply:
        parser.error("--apply is required; this command changes the configured database")
    if not 1 <= args.max_batches <= 1000:
        parser.error("--max-batches must be between 1 and 1000")

    from hackabull.fraud import maintain_ip_registry

    events_deleted = flags_redacted = audit_ips_cleared = 0
    drained = False
    for _ in range(args.max_batches):
        result = maintain_ip_registry(batch_limit=1000)
        events_deleted += result["eventsDeleted"]
        flags_redacted += result["flagsRedacted"]
        audit_ips_cleared += result["auditIpsCleared"]
        if result["eventsDeleted"] == 0 and result["flagsRedacted"] == 0 and result["auditIpsCleared"] == 0:
            drained = True
            break
    print(
        f"events_deleted={events_deleted} flags_redacted={flags_redacted} "
        f"audit_ips_cleared={audit_ips_cleared} backlog_possible={str(not drained).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
