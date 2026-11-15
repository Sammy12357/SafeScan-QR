"""Explicit, default-off switches for public token features and distribution."""

import os


_TRUE = {"1", "true", "yes", "on"}


def token_features_enabled():
    return os.getenv("TOKEN_FEATURES_ENABLED", "false").strip().lower() in _TRUE


def token_distribution_enabled():
    return token_features_enabled() and os.getenv("TOKEN_DISTRIBUTION_ENABLED", "false").strip().lower() in _TRUE
