"""
Inference-time calibration + caching on top of the existing URL classifier
and CNN. These improvements ship without retraining.

What this fixes
---------------
1. **Threshold mismatch with training.**
   The notebook (`SafeScanQR_Improved`) found F1-optimal threshold = 0.32 on
   the validation set, but `ml_model_final.predict_url` and downstream code
   in `hackabull.classify_qr_with_ml` previously split benign vs malicious
   at 0.5 (and bucketed as "Malicious" only at >= 80% probability). The
   result was a model more conservative in production than in evaluation,
   weakening malicious recall.

2. **No reject option for borderline scores.**
   When the classifier returns a probability between (say) 0.35 and 0.65 it
   doesn't really *know* - the char-ngram model is not calibrated and
   close-to-50% scores carry near-zero information. `interpret_probability`
   returns an `uncertain` band that `hackabull.classify_qr_with_ml` uses to
   suppress the ML signal entirely.

3. **No feature awareness for things the char-ngram model can't see.**
   The URL classifier is char-substring frequencies. It misses domain age,
   TLD reputation tier, raw-IP hosts, userinfo obfuscation, punycode,
   hyphen-heavy hostnames, brand impersonation, and off-brand sensitive
   keywords. `lexical_feature_bonus` adds a small, capped post-hoc nudge.

4. **No prediction caching.**
   Same URL scanned five times in a day re-runs the full pipeline. The
   cache is keyed on the normalized URL (matching the classifier's own
   normalization so HTTP/HTTPS variants share a row) with split TTLs:
   benign verdicts live longer, malicious/suspicious verdicts expire fast
   so takedowns are seen quickly. Raw probability is stored alongside the
   payload so calibration tweaks don't require flushing the cache.

None of these changes require retraining. They are intentionally
conservative - any one of them can be disabled via env var without
affecting the rest.
"""
from __future__ import annotations

from . import decision, features, cache
from .decision import *  # noqa: F401,F403
from .features import *  # noqa: F401,F403
from .cache import *  # noqa: F401,F403

# `import *` skips single-underscore names, but this used to be one module where
# callers (and tests) could reach internal helpers like `_cache_connection`.
# Re-export those to keep that flat namespace intact.
for _mod in (decision, features, cache):
    for _name in dir(_mod):
        if _name.startswith("_") and not _name.startswith("__"):
            globals().setdefault(_name, getattr(_mod, _name))
del _mod, _name
