"""Run the browser script's wallet trust-state regression in Node."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_wallet_ui_trust_state():
    subprocess.run(["node", "tests/wallet_ui.test.js"], cwd=ROOT, check=True)
