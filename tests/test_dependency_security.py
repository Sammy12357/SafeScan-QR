"""Keep the installed web and upload stack above known vulnerable releases."""

from importlib.metadata import version

import pytest
from packaging.version import Version


@pytest.mark.parametrize(
    ("distribution", "minimum"),
    [
        ("fastapi", "0.133.0"),  # Supports the Starlette 1.x security fixes.
        ("starlette", "1.3.1"),
        ("Pillow", "13.0.0"),
        ("python-multipart", "0.0.31"),
        ("cryptography", "50.0.0"),
        ("requests", "2.33.0"),
        ("python-dotenv", "1.2.2"),
        ("h11", "0.16.0"),
    ],
)
def test_installed_dependency_exceeds_security_floor(distribution, minimum):
    assert Version(version(distribution)) >= Version(minimum)
