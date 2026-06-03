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


def _cnn_needs_rescale():
    """Some ensembles expect [0,1] inputs; the original final_model.keras has its own Rescaling layer."""
    return os.getenv("SAFESCAN_ML2_RESCALE", "auto").lower() in ("1", "true", "yes", "on")


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
    safe_p = 1.0 - mal_p
    label = "malicious" if mal_p > safe_p else "safe"
    confidence = round(max(safe_p, mal_p) * 100)
    return {
        "safe_prob": round(safe_p * 100, 1),
        "malicious_prob": round(mal_p * 100, 1),
        "label": label,
        "confidence_pct": confidence,
        "source": source,
    }


def predict_image(pil_image):
    """CNN fallback. Auto-detects input size from the loaded model."""
    model = _load_cnn()
    h, w = _cnn_input_size()
    img = pil_image.convert("RGB").resize((w, h), Image.LANCZOS)
    arr = np.asarray(img, dtype=np.float32)
    if _cnn_needs_rescale():
        arr = arr / 255.0
    arr = arr[None, ...]
    raw = float(model.predict(arr, verbose=0).reshape(-1)[0])
    mal_p = raw if POSITIVE_CLASS != "safe" else 1.0 - raw
    return _result_from_probs(mal_p, "cnn_fallback")


def predict_hybrid(url: str | None = None, pil_image=None):
    """Mirror notebook's hybrid_predict: URL classifier first, CNN fallback.

    `url`   - decoded URL string (preferred path)
    `pil_image` - PIL image used only if the URL classifier is unavailable
    """
    if url:
        url_result = predict_url(url)
        if url_result is not None:
            return url_result
    if pil_image is not None:
        return predict_image(pil_image)
    return None


# Backwards-compat: existing call sites use predict(pil_image)
def predict(pil_image):
    return predict_image(pil_image)
