"""Ensure direct dependency pins and both hashed locks stay in sync."""

import re
from pathlib import Path

from packaging.requirements import Requirement


ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^ ;\\]+)", re.MULTILINE)


def lock_versions(path):
    content = path.read_text()
    versions = {name.lower().replace("_", "-"): version for name, version in PIN.findall(content)}
    assert versions, f"{path} contains no pinned dependencies"
    assert len(versions) == len(PIN.findall(content)), f"{path} has duplicate package pins"
    for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", "\n" + content):
        if PIN.search(block):
            assert "--hash=sha256:" in block, f"Missing hash in {path}: {block.splitlines()[0]}"
    return versions


def check_input(path, lock):
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        exact = [item.version for item in requirement.specifier if item.operator == "=="]
        if exact:
            name = requirement.name.lower().replace("_", "-")
            assert lock.get(name) == exact[0], (
                f"{name} is pinned to {exact[0]} in {path.name} but {lock.get(name)} in the lock"
            )


def main():
    runtime = lock_versions(ROOT / "requirements.lock")
    dev = lock_versions(ROOT / "requirements-dev.lock")
    assert runtime.items() <= dev.items(), "The dev lock must use the same runtime versions"
    check_input(ROOT / "requirements.txt", runtime)
    check_input(ROOT / "requirements-dev.txt", dev)
    print(f"Dependency locks valid: {len(runtime)} runtime and {len(dev)} test packages.")


if __name__ == "__main__":
    main()
