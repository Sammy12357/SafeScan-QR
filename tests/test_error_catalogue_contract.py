"""Literal error codes and statuses must agree with the public catalogue."""

import ast
from pathlib import Path

from hackabull.errors import ERRORS, _STATUS_CODES


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "hackabull"


def _name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _literal_string(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _literal_int(node: ast.expr | None) -> int | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is int else None


def test_error_catalogue_is_complete_and_status_defaults_agree() -> None:
    assert ERRORS
    for code, entry in ERRORS.items():
        assert code and code == code.lower(), code
        assert entry.message.strip(), code
        assert entry.hint.strip(), code
        assert 400 <= entry.status_code < 600, code
    for status, code in _STATUS_CODES.items():
        assert code in ERRORS, f"HTTP {status} references an unknown code: {code}"
        assert ERRORS[code].status_code == status, f"HTTP {status} maps to {code} with status {ERRORS[code].status_code}"


def test_literal_error_calls_use_catalogue_codes_and_matching_statuses() -> None:
    errors: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and _name(node.value) == "ERRORS":
                code = _literal_string(node.slice)
                if code is not None and code not in ERRORS:
                    errors.append(f"{path.relative_to(ROOT)}:{node.lineno}: unknown catalogue code {code!r}")
            if not isinstance(node, ast.Call) or _name(node.func) not in {"SafeScanError", "error_response"}:
                continue
            code = next((_literal_string(kw.value) for kw in node.keywords if kw.arg == "code"), None)
            if code is None:
                continue
            source = f"{path.relative_to(ROOT)}:{node.lineno}"
            if code not in ERRORS:
                errors.append(f"{source}: unknown error code {code!r}")
                continue
            status_node = node.args[1] if len(node.args) > 1 else next(
                (kw.value for kw in node.keywords if kw.arg == "status_code"), None
            )
            status = _literal_int(status_node)
            if status is not None and status != ERRORS[code].status_code:
                errors.append(f"{source}: {code!r} uses HTTP {status}, catalogue says {ERRORS[code].status_code}")
    assert not errors, "Error catalogue contract drift:\n" + "\n".join(errors)
