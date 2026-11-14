"""Small, explicit bounds for user-supplied text kept or processed by routes."""

from .audit import SafeScanError


def bounded_text(value, field, max_chars, *, required=False, strip=False):
    """Reject bad types and overlong values instead of silently truncating them."""
    if value is None and not required:
        value = ""
    if not isinstance(value, str):
        raise SafeScanError(f"Invalid {field}.", 400)
    if len(value) > max_chars:
        raise SafeScanError(f"{field.capitalize()} must be {max_chars} characters or fewer.", 400)
    if strip:
        value = value.strip()
    if required and not value.strip():
        raise SafeScanError(f"{field.capitalize()} is required.", 400)
    return value
