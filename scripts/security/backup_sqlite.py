"""Create a consistent, private SQLite backup for offsite encryption.

This only snapshots the database. The operator must separately archive other
durable files, encrypt both outputs offsite, and perform a restore drill.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path
from urllib.parse import quote



def backup_database(source: Path, output: Path) -> None:
    source = source.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.resolve() == source:
        raise FileExistsError("Backup output must be a new file distinct from the source.")
    if not output.parent.is_dir():
        raise FileNotFoundError("Backup output directory does not exist.")
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    try:
        uri = "file:" + quote(str(source), safe="/") + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as active, sqlite3.connect(output) as snapshot:
            active.backup(snapshot)
            if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup failed SQLite integrity_check.")
        os.chmod(output, 0o600)
    except Exception:
        output.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a consistent SQLite backup for later encryption")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    backup_database(args.source, args.output)
    print("SQLite backup complete; encrypt and move it off the Render disk.")


if __name__ == "__main__":
    main()
