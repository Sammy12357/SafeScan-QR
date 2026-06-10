"""
Hybrid QR classifier mirroring the training notebook (SafeScanQR_Improved):

    1. Try the URL char-ngram classifier (url_classifier.joblib).
       This is the workhorse and hit 99.29% accuracy in training. When a
       QR decodes to a URL (the vast majority of real traffic), this is
       all we need.
    2. Fall back to the EfficientNetV2B0 CNN (final_model.keras) when the
       URL classifier is unavailable or no URL was decoded. The CNN's
       ceiling was ~88% in the notebook, so it's a safety net, not the
       primary signal.

Both artifacts live in ./models/ and load lazily.
"""

from __future__ import annotations

import os
import re
import threading

import numpy as np
from PIL import Image

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+\-.]*://", re.IGNORECASE)

# F1-optimal threshold from the training notebook's threshold sweep on val.
# Read from env so it stays in lock-step with safescan_model_calibration's
# MALICIOUS_THRESHOLD without forcing an import cycle (calibration imports
# heavy ML stack indirectly through hackabull).
_MAL_THRESHOLD = float(os.getenv("SAFESCAN_ML_MAL_THRESHOLD", "0.32"))


def _normalize_url(url: str) -> str:
    """Match the training-time normalization: strip scheme, lowercase, no trailing slash.

    The dataset encodes benign QRs as bare domains (google.com) and
    malicious ones as full URLs (https://drain.tk/...). Without stripping
    the scheme, the classifier would learn 'has https:// = malicious' and
    misclassify every well-formed URL from the deployment.
    """
    url = (url or "").strip()
    url = _SCHEME_RE.sub("", url, count=1)
    return url.lower().rstrip("/")

MODEL_PATH = os.getenv(
    "SAFESCAN_ML2_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "models", "final_model.keras"),
)
URL_CLASSIFIER_PATH = os.getenv(
    "SAFESCAN_URL_CLASSIFIER_PATH",
    os.path.join(os.path.dirname(__file__), "models", "url_classifier.joblib"),
)
POSITIVE_CLASS = os.getenv("SAFESCAN_ML2_POSITIVE_CLASS", "malicious").lower()

_cnn = None
_cnn_rescale_cached: bool | None = None
_url_classifier = None
_url_classifier_missing = False
_lock = threading.Lock()


def _load_cnn():
    global _cnn
    if _cnn is not None:
        return _cnn
    with _lock:
        if _cnn is not None:
            return _cnn
        os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
        import keras

        @keras.saving.register_keras_serializable(name="preprocess_input")
        def preprocess_input(x):  # noqa: ARG001
            return x

        # ModelWrapper is a custom layer used by the SafeScanQR ensemble
        # build (safescanqr_final_ensemble.keras). Register a shim so we
        # can load either the simple single-model file or the ensemble.
        @keras.saving.register_keras_serializable(name="ModelWrapper")
        class ModelWrapper(keras.layers.Layer):
            def __init__(self, model_config=None, model_name=None, **kwargs):
                super().__init__(**kwargs)
                self.model_config = model_config
                self.model_name = model_name
                self.inner = (
                    keras.saving.deserialize_keras_object(model_config)
                    if model_config else None
                )

            def call(self, inputs):
                return self.inner(inputs)

            def get_config(self):
                base = super().get_config()
                base["model_config"] = self.model_config
                base["model_name"] = self.model_name
                return base

        # safe_mode=False is required because the SafeScanQR ensemble file
        # contains a Lambda layer that Keras refuses to deserialize under
        # safe_mode=True. The model file is shipped from our own training
        # pipeline (see notebook SafeScanQR_Improved.ipynb) so the pickle
        # risk is acceptable. NEVER point MODEL_PATH at an attacker-
        # supplied .keras file.
        _cnn = keras.models.load_model(
            MODEL_PATH,
            compile=False,
            safe_mode=False,
            custom_objects={
                "preprocess_input": preprocess_input,
                "ModelWrapper": ModelWrapper,
            },
        )
    return _cnn


def _cnn_input_size():
    model = _load_cnn()
    shape = model.input_shape
    # Functional model.input_shape is (None, H, W, 3); fall back to 192.
    if isinstance(shape, tuple) and len(shape) == 4 and shape[1] and shape[2]:
        return int(shape[1]), int(shape[2])
    return 192, 192


def _cnn_needs_rescale() -> bool:
    """Decide whether to divide inputs by 255 before predict().

    Logic:
      - Explicit env override (`SAFESCAN_ML2_RESCALE`) always wins.
      - Otherwise, inspect the loaded model graph: if it already contains
        a `Rescaling` layer (the original final_model.keras does), feed
        raw 0..255 floats; if not (the ensemble build strips it), feed
        0..1 floats. Detection is cached on the first call.
    """
    global _cnn_rescale_cached
    override = os.getenv("SAFESCAN_ML2_RESCALE", "auto").lower()
    if override in ("1", "true", "yes", "on"):
        return True
    if override in ("0", "false", "no", "off"):
        return False
    if _cnn_rescale_cached is not None:
        return _cnn_rescale_cached
    try:
        model = _load_cnn()
        has_rescaling = any(
            layer.__class__.__name__ == "Rescaling" for layer in getattr(model, "layers", [])
        )
        _cnn_rescale_cached = not has_rescaling
    except Exception:
        _cnn_rescale_cached = False
    return _cnn_rescale_cached


def _load_url_classifier():
    """Returns (vectorizer, classifier) or None if the joblib can't be loaded.

    Treats EVERY load failure (file missing, scikit-learn version mismatch,
    corrupt pickle, etc.) as a soft miss. The caller falls back to the CNN
    or, when ML is fully unavailable, the rule pipeline still produces a
    verdict. The previous version of this function let joblib exceptions
    propagate, which surfaced as `ModuleNotFoundError: No module named
    '_loss'` on the result page whenever sklearn drifted across versions.
    """
    global _url_classifier, _url_classifier_missing
    if _url_classifier is not None:
        return _url_classifier
    if _url_classifier_missing:
        return None
    with _lock:
        if _url_classifier is not None:
            return _url_classifier
        if not os.path.exists(URL_CLASSIFIER_PATH):
            _url_classifier_missing = True
            return None
        try:
            import joblib
            _url_classifier = joblib.load(URL_CLASSIFIER_PATH)
        except Exception as exc:
            print({"warning": "url_classifier load failed", "error": f"{type(exc).__name__}: {exc}"})
            _url_classifier_missing = True
            return None
    return _url_classifier


def predict_url(url: str):
    """Char-ngram URL classifier. Returns None if the classifier is
    unavailable, the URL is empty, or the predict call itself errors
    (sklearn version drift can break predict_proba on a loaded model)."""
    pair = _load_url_classifier()
    if pair is None or not url:
        return None
    vec, clf = pair
    normalized = _normalize_url(url)
    if not normalized:
        return None
    try:
        prob = float(clf.predict_proba(vec.transform([normalized]))[0, 1])
    except Exception as exc:
        print({"warning": "url_classifier predict failed", "error": f"{type(exc).__name__}: {exc}"})
        return None
    return _result_from_probs(prob, "url_classifier")


def _result_from_probs(mal_p: float, source: str):
    """Build the inner ML result. Uses the F1-optimal threshold (0.32 by
    default) for the binary label rather than the default 0.5 split - the
    notebook tuned this on val and the calibration band below depends on
    the same threshold."""
    safe_p = 1.0 - mal_p
    label = "malicious" if mal_p >= _MAL_THRESHOLD else "safe"
    # Distance from the threshold, scaled to 0..100, gives a stabler
    # confidence than max(safe_p, mal_p) at non-0.5 thresholds.
    if label == "malicious":
        scale = max(1e-6, 1.0 - _MAL_THRESHOLD)
        confidence = round(min(1.0, (mal_p - _MAL_THRESHOLD) / scale) * 100)
    else:
        scale = max(1e-6, _MAL_THRESHOLD)
        confidence = round(min(1.0, (_MAL_THRESHOLD - mal_p) / scale) * 100)
    return {
        "safe_prob": round(safe_p * 100, 1),
        "malicious_prob": round(mal_p * 100, 1),
        "label": label,
        "confidence_pct": confidence,
        "source": source,
    }


def _crop_to_qr(pil_image, polygon=None):
    """If a QR bounding polygon was passed in, crop+pad to that region so
    the CNN doesn't classify on background. Falls back to the full image
    when no polygon is provided or the crop would be degenerate."""
    if polygon is None:
        return pil_image
    try:
        xs = [int(p[0]) for p in polygon]
        ys = [int(p[1]) for p in polygon]
    except Exception:
        return pil_image
    if not xs or not ys:
        return pil_image
    w, h = pil_image.size
    margin = int(0.08 * max(max(xs) - min(xs), max(ys) - min(ys)))
    left = max(0, min(xs) - margin)
    upper = max(0, min(ys) - margin)
    right = min(w, max(xs) + margin)
    lower = min(h, max(ys) + margin)
    if right - left < 16 or lower - upper < 16:
        return pil_image
    return pil_image.crop((left, upper, right, lower))


def predict_image(pil_image, polygon=None, tta: bool = False):
    """CNN fallback. Auto-detects input size from the loaded model.

    Args:
        pil_image: full-frame PIL image.
        polygon: optional list of (x, y) tuples for the QR bounding box.
            When provided, the CNN sees a tight crop of the QR rather
            than the whole photo - meaningful improvement when the QR is
            small in frame.
        tta: if True, average predictions across the 4 rotations of the
            input. Cheap test-time augmentation that removes orientation
            as a source of variance for the CNN fallback path.
    """
    model = _load_cnn()
    h, w = _cnn_input_size()
    base = _crop_to_qr(pil_image, polygon=polygon).convert("RGB").resize((w, h), Image.LANCZOS)

    def _prep(img):
        arr = np.asarray(img, dtype=np.float32)
        if _cnn_needs_rescale():
            arr = arr / 255.0
        return arr

    if tta:
        batch = np.stack([_prep(base.rotate(angle, expand=False)) for angle in (0, 90, 180, 270)], axis=0)
        raw = float(model.predict(batch, verbose=0).reshape(-1).mean())
    else:
        arr = _prep(base)[None, ...]
        raw = float(model.predict(arr, verbose=0).reshape(-1)[0])
    mal_p = raw if POSITIVE_CLASS != "safe" else 1.0 - raw
    return _result_from_probs(mal_p, "cnn_fallback")


def predict_hybrid(url: str | None = None, pil_image=None, polygon=None, tta: bool = False):
    """Mirror notebook's hybrid_predict: URL classifier first, CNN fallback.

    `url`     - decoded URL string (preferred path)
    `pil_image` - PIL image used only if the URL classifier is unavailable
    `polygon` - optional QR bounding polygon for CNN tight-crop
    `tta`     - rotation averaging on the CNN path
    """
    if url:
        url_result = predict_url(url)
        if url_result is not None:
            return url_result
    if pil_image is not None:
        return predict_image(pil_image, polygon=polygon, tta=tta)
    return None


def blend_url_and_cnn(url_result: dict, cnn_result: dict, url_weight: float = 0.6) -> dict:
    """Weighted blend of URL classifier + CNN malicious probabilities.

    Used by the caller when the URL score lands in the uncertain band and
    a QR image is available - the CNN occasionally breaks ties the URL
    text alone can't.
    """
    if not url_result or not cnn_result:
        return url_result or cnn_result
    w = max(0.0, min(1.0, float(url_weight)))
    url_mal = float(url_result.get("malicious_prob", 50.0)) / 100.0
    cnn_mal = float(cnn_result.get("malicious_prob", 50.0)) / 100.0
    blended = w * url_mal + (1.0 - w) * cnn_mal
    res = _result_from_probs(blended, "url_cnn_blend")
    res["url_component"] = round(url_mal, 4)
    res["cnn_component"] = round(cnn_mal, 4)
    return res


# Backwards-compat: existing call sites use predict(pil_image)
def predict(pil_image):
    return predict_image(pil_image)
