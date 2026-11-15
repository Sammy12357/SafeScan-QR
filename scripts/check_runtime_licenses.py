"""Fail closed when the Linux runtime lock gains an unreviewed license.

The checked-in register is a review allowlist, not a legal opinion. Package
metadata alone cannot establish all bundled binary and redistribution duties.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", re.MULTILINE)
DENIED = re.compile(r"(?<![A-Za-z])(?:AGPL|GPL|SSPL)(?:-\d(?:\.\d)?)?(?![A-Za-z])", re.IGNORECASE)
ALLOWED_IDS = {
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0",
    "MIT", "MIT-0", "MIT-CMU", "MPL-2.0", "PSF-2.0", "Zlib",
}


def check_runtime_licenses(lock_text: str, register: dict) -> list[str]:
    errors: list[str] = []
    for line in lock_text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and not PIN.fullmatch(line.split()[0]):
            errors.append(f"Unreviewed requirement syntax in runtime lock: {line[:80]}")
    pairs = [(name.lower().replace("_", "-"), version) for name, version in PIN.findall(lock_text)]
    pins = dict(pairs)
    if not pairs or len(pins) != len(pairs):
        errors.append("Runtime lock is empty or contains duplicate package pins")
    packages = register.get("packages")
    if not isinstance(packages, dict):
        return errors + ["Runtime license register has no packages object"]
    for name, version in sorted(pins.items()):
        item = packages.get(name)
        if not isinstance(item, dict):
            errors.append(f"{name}=={version}: no reviewed license entry")
            continue
        if item.get("version") != version:
            errors.append(f"{name}: reviewed version {item.get('version')!r} differs from lock {version!r}")
        license_id = item.get("license")
        if not isinstance(license_id, str) or not license_id.strip() or "UNKNOWN" in license_id.upper():
            errors.append(f"{name}=={version}: license is unknown")
        elif DENIED.search(license_id):
            errors.append(f"{name}=={version}: strong copyleft/server-source license needs review: {license_id}")
        else:
            identifiers = set(license_id.split()) - {"AND", "OR", "WITH", "(" , ")"}
            if not identifiers or not identifiers <= ALLOWED_IDS:
                errors.append(f"{name}=={version}: license expression contains an unreviewed identifier: {license_id}")
        evidence = item.get("evidence")
        if not isinstance(evidence, str) or not evidence.startswith("https://"):
            errors.append(f"{name}=={version}: missing primary-source evidence URL")
    for name in sorted(set(packages) - set(pins)):
        errors.append(f"{name}: stale license entry; review the removed dependency")
    if "pymupdf" in pins:
        errors.append("PyMuPDF must not return without a reviewed commercial license or source plan")
    return errors


def main() -> None:
    lock_text = (ROOT / "requirements.lock").read_text()
    register = json.loads((ROOT / "docs/legal/runtime-dependency-licenses.json").read_text())
    errors = check_runtime_licenses(lock_text, register)
    if errors:
        raise SystemExit("Runtime license gate failed:\n" + "\n".join(f"- {error}" for error in errors))
    print(f"Runtime license gate passed: {len(register['packages'])} reviewed packages")


if __name__ == "__main__":
    main()
