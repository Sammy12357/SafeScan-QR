from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

LOG = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# 1. Calibrated thresholding + uncertain band
# -----------------------------------------------------------------------------

# F1-optimal threshold from the training notebook's threshold sweep on val.
# Used by ml_model_final._result_from_probs to label raw classifier output.
MALICIOUS_THRESHOLD = float(os.getenv("SAFESCAN_ML_MAL_THRESHOLD", "0.32"))

# The uncertain band brackets the malicious threshold. Probabilities inside
# this band are explicitly NOT trusted as signal; the analyzer falls back to
# its rule pipeline + reputation checks instead of letting the ML nudge the
# final score. Defaults give a ~30 percentage-point band.
UNCERTAIN_LOWER = float(os.getenv("SAFESCAN_ML_UNCERTAIN_LOWER", "0.20"))
UNCERTAIN_UPPER = float(os.getenv("SAFESCAN_ML_UNCERTAIN_UPPER", "0.50"))

# The "confidently malicious" cutoff is intentionally raised above the
# notebook's 0.80 default. Above ~90% the classifier earns full credit;
# 0.50-0.90 still carries information but at reduced weight.
CONFIDENT_MALICIOUS_THRESHOLD = float(os.getenv("SAFESCAN_ML_CONFIDENT", "0.90"))


@dataclass
class CalibratedDecision:
    """Result of interpreting a raw ML malicious probability."""
    bucket: str          # one of: "benign", "uncertain", "suspicious", "malicious"
    severity: str        # one of: "low", "medium", "high"
    passed: bool         # True iff the URL is in the safe bucket
    trust_signal: bool   # True iff the ML signal should be exposed at all
    label: str           # short label for the signal UI


def interpret_probability(mal_probability: float) -> CalibratedDecision:
    """Map a raw 0..1 malicious probability into a stable analyzer decision.

    The bands are:
        [0, UNCERTAIN_LOWER)          -> benign     (low severity, trusted)
        [UNCERTAIN_LOWER, UPPER)      -> uncertain  (suppressed - no signal)
        [UPPER, CONFIDENT_MALICIOUS)  -> suspicious (medium, trusted)
        [CONFIDENT_MALICIOUS, 1.0]    -> malicious  (high, trusted)
    """
    p = max(0.0, min(1.0, float(mal_probability or 0.0)))

    if p < UNCERTAIN_LOWER:
        return CalibratedDecision("benign", "low", True, True, "Benign (ML)")
    if p < UNCERTAIN_UPPER:
        return CalibratedDecision("uncertain", "low", False, False, "Uncertain (ML)")
    if p < CONFIDENT_MALICIOUS_THRESHOLD:
        return CalibratedDecision("suspicious", "medium", False, True, "Suspicious (ML)")
    return CalibratedDecision("malicious", "high", False, True, "Malicious (ML)")


