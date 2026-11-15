"""The screenshot subprocess must never inherit production credentials."""

import subprocess
import sys

from scripts.ui_screenshots import isolated_server_env


def test_screenshot_server_env_isolated_from_parent_and_dotenv(monkeypatch, tmp_path):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "parent-google-client")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "parent-auth0-secret")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "parent-stripe-secret")
    monkeypatch.setenv("SOLANA_PRIVATE_KEY", "parent-solana-key")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/private/credentials")
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "false")
    env = isolated_server_env(str(tmp_path), "http://localhost:12345")

    assert env["HOME"] == str(tmp_path)
    assert env["TMPDIR"] == str(tmp_path)
    assert env["MOCK_MODE"] == "true"
    assert env["STORAGE_BACKEND"] == "local"
    assert env["AIRDROP_ENABLED"] == "false"
    assert env["SOLANA_MAINNET_ENABLED"] == "false"
    assert env["PYTHON_DOTENV_DISABLED"] == "1"
    for name in ("GOOGLE_CLIENT_ID", "AUTH0_CLIENT_SECRET", "STRIPE_WEBHOOK_SECRET", "SOLANA_PRIVATE_KEY"):
        assert env[name] == ""
    assert "AWS_SHARED_CREDENTIALS_FILE" not in env
    assert "RENDER" not in env
    assert "parent-google-client" not in env.values()
    assert "parent-auth0-secret" not in env.values()
    assert "parent-stripe-secret" not in env.values()
    assert "parent-solana-key" not in env.values()

    dotenv_file = tmp_path / ".env"
    dotenv_file.write_text("GOOGLE_CLIENT_ID=dotenv-google-client\nSTRIPE_WEBHOOK_SECRET=dotenv-stripe-secret\n")
    code = (
        "import os; from dotenv import load_dotenv; "
        "load_dotenv('.env'); print(repr(os.getenv('GOOGLE_CLIENT_ID'))); "
        "print(repr(os.getenv('STRIPE_WEBHOOK_SECRET')))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.splitlines() == ["''", "''"]
