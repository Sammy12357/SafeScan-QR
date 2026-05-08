"""
Numpy/h5py-based inference for safescan_qr_model.keras.
Architecture: Conv2D(32) -> BN -> MaxPool -> Conv2D(64) -> BN -> MaxPool
              -> Flatten -> Dense(128) -> Dropout -> Dense(2) [logits]
Input: 32x32 RGB image, float32 [0,1]
Output: [safe_prob, malicious_prob]  (class 0 = safe, class 1 = malicious)
"""

import os
import io
import zipfile

import h5py
import numpy as np
from PIL import Image

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "safescan_qr_model.keras")
_weights = None


def _load_weights():
    global _weights
    if _weights is not None:
        return _weights
    with zipfile.ZipFile(MODEL_PATH) as z:
        with z.open("model.weights.h5") as f:
            raw = f.read()
    with h5py.File(io.BytesIO(raw), "r") as hf:
        def get(path):
            return hf[path][:].astype(np.float32)
        _weights = {
            "conv1_w":   get("layers/conv2d/vars/0"),             # (3,3,3,32)
            "conv1_b":   get("layers/conv2d/vars/1"),             # (32,)
            "bn1_gamma": get("layers/batch_normalization/vars/0"),# (32,)
            "bn1_beta":  get("layers/batch_normalization/vars/1"),# (32,)
            "bn1_mean":  get("layers/batch_normalization/vars/2"),# (32,)
            "bn1_var":   get("layers/batch_normalization/vars/3"),# (32,)
            "conv2_w":   get("layers/conv2d_1/vars/0"),           # (3,3,32,64)
            "conv2_b":   get("layers/conv2d_1/vars/1"),           # (64,)
            "bn2_gamma": get("layers/batch_normalization_1/vars/0"),
            "bn2_beta":  get("layers/batch_normalization_1/vars/1"),
            "bn2_mean":  get("layers/batch_normalization_1/vars/2"),
            "bn2_var":   get("layers/batch_normalization_1/vars/3"),
            "dense1_w":  get("layers/dense/vars/0"),              # (4096,128)
            "dense1_b":  get("layers/dense/vars/1"),              # (128,)
            "dense2_w":  get("layers/dense_1/vars/0"),            # (128,2)
            "dense2_b":  get("layers/dense_1/vars/1"),            # (2,)
        }
    return _weights


def _conv2d_same(x, W, b):
    """Vectorised Conv2D with 'same' padding via as_strided windows."""
    H, W_in, C = x.shape
    kH, kW, _, F = W.shape
    pH, pW = (kH - 1) // 2, (kW - 1) // 2
    xp = np.pad(x, ((pH, pH), (pW, pW), (0, 0)), mode="constant")
    s = xp.strides
    # Build (H, W_in, kH, kW, C) view without copying
    windows = np.lib.stride_tricks.as_strided(
        xp,
        shape=(H, W_in, kH, kW, C),
        strides=(s[0], s[1], s[0], s[1], s[2]),
    )
    # (H, W_in, kH*kW*C) @ (kH*kW*C, F) + b
    flat = windows.reshape(H, W_in, -1)
    wf = W.reshape(-1, F)
    return (flat @ wf + b).astype(np.float32)


def _batch_norm(x, gamma, beta, mean, var, eps=0.001):
    return (gamma * (x - mean) / np.sqrt(var + eps) + beta).astype(np.float32)


def _maxpool2d(x, size=2):
    H, W, C = x.shape
    return x.reshape(H // size, size, W // size, size, C).max(axis=(1, 3))


def _relu(x):
    return np.maximum(0.0, x)


def _softmax(x):
    e = np.exp(x - x.max())
    return (e / e.sum()).astype(np.float32)


def predict(pil_image):
    """
    Run the CNN on a PIL image.

    Returns a dict with keys:
        safe_prob       float  0–1
        malicious_prob  float  0–1
        label           str    'safe' | 'malicious'
        confidence_pct  int    0–100 (confidence in the predicted class)
    """
    w = _load_weights()

    # Pre-process: resize to 32×32 RGB, normalise to [0,1]
    img = pil_image.convert("RGB").resize((32, 32), Image.LANCZOS)
    x = np.array(img, dtype=np.float32) / 255.0  # (32,32,3)

    # Block 1: Conv → BN → ReLU → MaxPool
    x = _conv2d_same(x, w["conv1_w"], w["conv1_b"])            # (32,32,32)
    x = _batch_norm(x, w["bn1_gamma"], w["bn1_beta"],
                    w["bn1_mean"], w["bn1_var"])
    x = _relu(x)
    x = _maxpool2d(x)                                           # (16,16,32)

    # Block 2: Conv → BN → ReLU → MaxPool
    x = _conv2d_same(x, w["conv2_w"], w["conv2_b"])            # (16,16,64)
    x = _batch_norm(x, w["bn2_gamma"], w["bn2_beta"],
                    w["bn2_mean"], w["bn2_var"])
    x = _relu(x)
    x = _maxpool2d(x)                                           # (8,8,64)

    # Head: Flatten → Dense(128, relu) → Dense(2, linear) → Softmax
    x = x.flatten()                                             # (4096,)
    x = _relu(x @ w["dense1_w"] + w["dense1_b"])               # (128,)
    logits = x @ w["dense2_w"] + w["dense2_b"]                 # (2,)
    probs = _softmax(logits)

    safe_p = float(probs[0])
    mal_p = float(probs[1])
    label = "malicious" if mal_p > safe_p else "safe"
    confidence = round(max(safe_p, mal_p) * 100)

    return {
        "safe_prob": round(safe_p * 100, 1),
        "malicious_prob": round(mal_p * 100, 1),
        "label": label,
        "confidence_pct": confidence,
    }


def predict_from_url(url: str):
    """
    Generate a QR code for the URL and run the CNN on it.
    Requires the 'qrcode' package; returns None if unavailable.
    """
    try:
        import qrcode
        qr = qrcode.QRCode(box_size=4, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        return predict(img)
    except ImportError:
        return None
