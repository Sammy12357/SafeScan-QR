"""Require a new version, archive, and review record when public legal text changes.

Run against the PR base (or previous push commit). This is a release-process
guard, not a judgment that any published term is enforceable or accurate.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KINDS = {"terms": "TERMS_HTML", "privacy": "PRIVACY_POLICY_HTML", "cookie": "COOKIE_POLICY_HTML"}


def _git_show(base: str, path: str) -> str | None:
    result = subprocess.run(["git", "show", f"{base}:{path}"], cwd=ROOT,
                            text=True, capture_output=True, check=False)
    return result.stdout if result.returncode == 0 else None


def _current(path: str) -> str | None:
    target = ROOT / path
    return target.read_text(encoding="utf-8") if target.is_file() else None


def _assigned_source(source: str | None, name: str) -> str | None:
    if source is None:
        return None
    for node in ast.parse(source).body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return ast.get_source_segment(source, node.value)
    return None


def _literal(source: str | None, name: str):
    expression = _assigned_source(source, name)
    if expression is None:
        return None
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        return None


def check(base: str) -> list[str]:
    errors: list[str] = []
    old_admin = _git_show(base, "hackabull/admin_data.py")
    new_admin = _current("hackabull/admin_data.py")
    old_meta = _literal(_git_show(base, "hackabull/legal_agreements.py"), "DOCUMENTS") or {}
    new_meta = _literal(_current("hackabull/legal_agreements.py"), "DOCUMENTS") or {}
    old_config = _git_show(base, "hackabull/config.py")
    new_config = _current("hackabull/config.py")
    old_global_version = _literal(old_config, "LEGAL_VERSION")
    new_global_version = _literal(new_config, "LEGAL_VERSION")
    old_global_date = _literal(old_config, "LEGAL_LAST_UPDATED")
    new_global_date = _literal(new_config, "LEGAL_LAST_UPDATED")
    changelog = _current("docs/legal/legal-document-changelog.md") or ""
    packet = _current("docs/legal/attorney-packet.md") or ""

    for kind, legacy_name in KINDS.items():
        old_entry, new_entry = old_meta.get(kind, {}), new_meta.get(kind, {})
        old_version = old_entry.get("current", old_global_version)
        new_version = new_entry.get("current", new_global_version)
        old_date = old_entry.get("versions", {}).get(old_version, old_global_date)
        new_date = new_entry.get("versions", {}).get(new_version, new_global_date)
        legacy_changed = _assigned_source(old_admin, legacy_name) != _assigned_source(new_admin, legacy_name)
        current_changed = old_version != new_version
        if old_entry:
            # A published snapshot is immutable. Correcting it requires a new version.
            for version in old_entry.get("versions", {}):
                path = f"hackabull/legal_published/{kind}.{version}.html"
                if _git_show(base, path) != _current(path):
                    errors.append(f"{path}: published snapshot changed or was removed")
        if not (legacy_changed or current_changed):
            continue
        if not isinstance(new_version, str) or new_version == old_version:
            errors.append(f"{kind}: public text changed without a new document version")
            continue
        if not isinstance(new_date, str) or new_date == old_date:
            errors.append(f"{kind}: public text changed without a new effective date")
        if new_entry:
            current_path = f"hackabull/legal_published/{kind}.{new_version}.html"
            if not _current(current_path):
                errors.append(f"{kind}: current version has no published snapshot")
            if old_version and not _current(f"hackabull/legal_published/{kind}.{old_version}.html"):
                errors.append(f"{kind}: previous version has no published snapshot")
        if not re.search(rf"\b{kind}\b[^\n]*\b{re.escape(new_version)}\b", changelog, re.I):
            errors.append(f"{kind}: add {new_version} to legal-document-changelog.md")
        if new_version not in packet:
            errors.append(f"{kind}: add {new_version} to attorney-packet.md")
    return errors


def main() -> None:
    if len(sys.argv) != 2 or not re.fullmatch(r"[0-9a-f]{40}", sys.argv[1]):
        raise SystemExit("Usage: check_legal_document_changes.py <base commit SHA>")
    errors = check(sys.argv[1])
    if errors:
        raise SystemExit("Legal document gate failed:\n" + "\n".join(f"- {error}" for error in errors))
    print("Legal document version and review gate passed")


if __name__ == "__main__":
    main()
