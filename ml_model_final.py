"""
Loader for the secondary QR classifier (`final_model.keras`).

This is an EfficientNet-style model with a 192x192x3 input and a single
sigmoid output. We load it with Keras 3 + TensorFlow (lazy, cached).

The model's Lambda 'preprocess' layer references a function named
`preprocess_input` that is not bundled with the .keras file; subsequent
Rescaling + Normalization layers handle ImageNet-style normalization, so
we register an identity stub.

Output: a single sigmoid probability in [0,1]. By default we treat the
positive class (high value) as 'malicious'. Set
SAFESCAN_ML2_POSITIVE_CLASS=safe to invert.
"""

import os
import threading

import numpy as np
from PIL import Image

MODEL_PATH = os.getenv(
    "SAFESCAN_ML2_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "models", "final_model.keras"),
)
POSITIVE_CLASS = os.getenv("SAFESCAN_ML2_POSITIVE_CLASS", "malicious").lower()

_model = None
_lock = threading.Lock()


def _load_model():
    global _model
    if _model is not None:
        return _model
    with _lock:
        if _model is not None:
            return _model
        os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
        import keras  # noqa: E402

        @keras.saving.register_keras_serializable(name="preprocess_input")
        def preprocess_input(x):  # noqa: ARG001
            return x

        _model = keras.models.load_model(
            MODEL_PATH,
            compile=False,
            safe_mode=False,
            custom_objects={"preprocess_input": preprocess_input},
        )
    return _model


def predict(pil_image):
    """
    Run the EfficientNet classifier on a PIL image.

    Returns the same dict shape as ml_model.predict():
        safe_prob       float  0-100, 1dp
        malicious_prob  float  0-100, 1dp
        label           str    'safe' | 'malicious'
        confidence_pct  int    0-100
    """
    model = _load_model()
    img = pil_image.convert("RGB").resize((192, 192), Image.LANCZOS)
    arr = np.asarray(img, dtype=np.float32)[None, ...]
    raw = float(model.predict(arr, verbose=0).reshape(-1)[0])

    if POSITIVE_CLASS == "safe":
        safe_p, mal_p = raw, 1.0 - raw
    else:
        mal_p, safe_p = raw, 1.0 - raw

    label = "malicious" if mal_p > safe_p else "safe"
    confidence = round(max(safe_p, mal_p) * 100)
    return {
        "safe_prob": round(safe_p * 100, 1),
        "malicious_prob": round(mal_p * 100, 1),
        "label": label,
        "confidence_pct": confidence,
    }


def predict_from_url(url: str):
    try:
        import qrcode
        qr = qrcode.QRCode(box_size=4, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        return predict(img)
    except ImportError:
        return None
