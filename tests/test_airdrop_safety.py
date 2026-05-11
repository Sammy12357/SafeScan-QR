import importlib
import os
import sys

import pytest


def load_distribute(monkeypatch, **env):
    for key in (
        "AIRDROP_ENABLED",
        "SOLANA_MAINNET_ENABLED",
        "AIRDROP_DRY_RUN",
        "AIRDROP_ADMIN_SECRET",
        "AIRDROP_MAX_RECIPIENTS_PER_RUN",
        "AIRDROP_MAX_TOKENS_PER_RUN",
        "SOLANA_RPC_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    sys.modules.pop("distribute", None)
    return importlib.import_module("distribute")


def test_airdrop_is_disabled_by_default(monkeypatch):
    distribute = load_distribute(monkeypatch)

    with pytest.raises(RuntimeError, match="disabled"):
        distribute.validate_airdrop_runtime()


def test_mainnet_requires_explicit_opt_in(monkeypatch):
    distribute = load_distribute(
        monkeypatch,
        AIRDROP_ENABLED="true",
        AIRDROP_ADMIN_SECRET="x" * 32,
        SOLANA_RPC_URL="https://api.mainnet-beta.solana.com",
    )

    with pytest.raises(RuntimeError, match="Mainnet"):
        distribute.validate_airdrop_runtime()


def test_airdrop_requires_strong_admin_secret(monkeypatch):
    distribute = load_distribute(
        monkeypatch,
        AIRDROP_ENABLED="true",
        SOLANA_MAINNET_ENABLED="true",
        AIRDROP_ADMIN_SECRET="short",
    )

    with pytest.raises(RuntimeError, match="AIRDROP_ADMIN_SECRET"):
        distribute.validate_airdrop_runtime()


def test_airdrop_runtime_allows_safe_explicit_configuration(monkeypatch):
    distribute = load_distribute(
        monkeypatch,
        AIRDROP_ENABLED="true",
        SOLANA_MAINNET_ENABLED="true",
        AIRDROP_ADMIN_SECRET="x" * 32,
        AIRDROP_MAX_RECIPIENTS_PER_RUN="5",
        AIRDROP_MAX_TOKENS_PER_RUN="500",
    )

    distribute.validate_airdrop_runtime()
