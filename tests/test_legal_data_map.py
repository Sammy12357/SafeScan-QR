"""Keep the legal data inventory aligned with the actual SQLite schema."""

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_data_map_covers_current_tables_and_columns(tmp_path):
    documented = json.loads((ROOT / "docs/legal/data-map.yaml").read_text(encoding="utf-8"))
    assert documented["_status"].startswith("Phase 0 engineering inventory")

    environment = os.environ.copy()
    environment.update({
        "DATABASE_URL": f"sqlite:///{(tmp_path / 'legal-map.db').as_posix()}",
        "DATA_DIR": str(tmp_path),
        "APP_URL": "http://localhost:8000",
    })
    script = """
import json, sqlite3
import hackabull
from db import database_path
conn = sqlite3.connect(database_path())
tables = {}
for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
    tables[name] = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
print(json.dumps(tables))
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT, env=environment,
        text=True, capture_output=True, check=True, timeout=30,
    )
    actual = json.loads(result.stdout)
    mapped = documented["tables"]

    assert set(mapped) == set(actual)
    for table, fields in actual.items():
        assert mapped[table]["fields"] == fields, table
        assert mapped[table]["source"]
        assert mapped[table]["purpose"]
        assert mapped[table]["retention"]
