"""Run the Go Ghost manual browser workflow regression in CI."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_manual_scope_lists_all_brokers_and_last_broker_actions_work():
    subprocess.run(
        ["node", "tests/go_ghost_manual_scope.test.js"],
        cwd=ROOT,
        check=True,
    )
