"""Small filesystem guards for SQLite files that can contain customer data."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def assert_outside_static(path: str | os.PathLike[str]) -> None:
    """Reject data paths reachable through the app's `/static` mount."""
    static_roots = {
        (Path(__file__).resolve().parent / "static").resolve(),
        Path("static").resolve(),
    }
    candidate = Path(path).resolve()
    if any(candidate == root or root in candidate.parents for root in static_roots):
        raise RuntimeError("Private data path must be outside the public static directory.")


def secure_sqlite_path(path: str | os.PathLike[str]) -> str:
    """Create a private SQLite file or restrict an existing regular file to 0600.

    The file is created with O_EXCL and mode 0600 before SQLite opens it. On
    existing files, chmod operates on a no-follow file descriptor so a symlink
    cannot redirect it to another file. A failed permission change aborts the
    caller rather than opening a world-readable customer database.
    """
    name = os.fspath(path)
    assert_outside_static(name)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec, 0o600)
    except FileExistsError:
        fd = os.open(name, os.O_RDONLY | nofollow | cloexec)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("SQLite path is not a regular file.")
        if stat.S_IMODE(info.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return name
