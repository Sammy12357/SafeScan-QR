"""Run the standalone Go Ghost state machine checks in CI."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_go_ghost_state_machine():
    subprocess.run(["node", "tests/go_ghost_state.test.js"], cwd=ROOT, check=True)
