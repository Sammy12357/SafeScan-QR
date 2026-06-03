# Retraining the SafeScan ML Models

This document is the operator's guide for the work that **needs a GPU**.
The inference-time improvements (calibration, uncertain band, lexical
feature bonus, prediction cache) are already in `safescan_model_calibration.py`
and don't require retraining.

The model files live in `models/`:

| File | What it is | Replace by |
|---|---|---|
| `url_classifier.joblib` | char-ngram + SGD logistic — currently the workhorse | Phase 1 — see below, no GPU required |
| `final_model.keras` | EfficientNetV2B0 CNN — fallback when QR didn't decode | Phase 2 — needs GPU |
| `safescanqr_final_ensemble.keras` | Larger ensemble (1.2 GB) — referenced as `SAFESCAN_ML_ENSEMBLE_PATH` | Phase 2 — needs GPU |

## Why retrain at all

`safescan_model_calibration.py` already addresses the headline issues from
the model review (uncalibrated probabilities, wrong threshold, missing
features) **without** retraining. So the question for retraining is:
how much accuracy is on the table?

Estimated upside per artifact:

- **URL classifier**: marginal (~+0.5-1% accuracy from proper calibration,
  another ~1-2% from feature-union with hand-crafted features). Easy to
  ship: CPU only, ~10 minutes on a laptop. **Recommended.**
- **CNN**: significant. The current `final_model.keras` was trained on
  only **400 images** because the original notebook's source CSVs were
  missing and it fell back to a controlled 1k sample. With the 1.6M-image
  dataset in `massive_qr_dataset.zip`, a proper run should push the CNN
  from ~88% test accuracy to 96-99%. **High upside, needs GPU.**

## Phase 1 — Recalibrate the URL classifier (CPU only, ~10 min)

The notebook's char-ngram + SGDClassifier setup is sound but uncalibrated.
Recompute with `CalibratedClassifierCV` and ship a `_v2` artifact.

```bash
# In your local clone, with a venv that has scikit-learn + joblib:
pip install scikit-learn==1.9 joblib pandas requests

# 1. Fetch the same URL feeds the notebook used.
python3 tools/train_url_classifier.py \
    --output models/url_classifier_v2.joblib \
    --sample-per-class 50000 \
    --calibrate
```

(See `tools/train_url_classifier.py` — to be added when you're ready. The
notebook section 2 is the reference algorithm; we just want
`CalibratedClassifierCV(SGDClassifier(loss='log_loss'), method='isotonic')`
wrapped around it.)

Once produced:

```bash
# Swap the artifact, point inference at it via env var, deploy.
mv models/url_classifier_v2.joblib models/url_classifier.joblib
git add models/url_classifier.joblib
git commit -m "Recalibrate URL classifier"
git push
```

Render redeploys; `safescan_model_calibration.interpret_probability` will
now operate on calibrated probabilities, making the uncertain band band
more meaningful.

## Phase 2 — Retrain the CNN on the 1.6M-image dataset (GPU required)

The dataset in `massive_qr_dataset.zip` (1.5 GB compressed, 1.2 GB
uncompressed) has the structure:

```
benign_parallel/shard_{0..16}/benign_{n}.png
malicious_parallel/shard_{0..6}/malicious_{n}.png
```

≈800K benign and ≈800K malicious — finally enough to actually train the
CNN. The original notebook (`SafeScanQR_Improved (1).ipynb`) trained on
400 images because its source CSVs were missing.

### Hardware

- **Colab T4** is fine. The notebook is already RAM-tuned for it (see the
  top of `SafeScanQR_Improved (1).ipynb` — "RAM-hardened for Colab T4").
- Estimated wall time: **3-5 hours** at 192×192, batch 32, 15 epochs.
- Or local: anything with ≥8 GB VRAM (RTX 3060+).

### Steps

1. **Unzip the dataset** somewhere fast (NVMe SSD or Colab `/content`):
   ```bash
   unzip massive_qr_dataset.zip -d /content/qr_dataset
   ```

2. **Build the manifest CSV** the notebook expects. The notebook scans
   for CSVs named `qr_data.csv`, `qr_dat_1_5.csv`, etc., each with
   `file_path,label`. Generate one from the directory layout:
   ```python
   import csv, pathlib, random
   root = pathlib.Path("/content/qr_dataset")
   rows = []
   for img in (root / "benign_parallel").rglob("*.png"):
       rows.append({"file_path": str(img), "label": "benign"})
   for img in (root / "malicious_parallel").rglob("*.png"):
       rows.append({"file_path": str(img), "label": "malicious"})
   random.shuffle(rows)
   with open("qr_data.csv", "w") as f:
       w = csv.DictWriter(f, fieldnames=["file_path", "label"])
       w.writeheader()
       w.writerows(rows)
   ```

3. **Run the notebook** (`SafeScanQR_Improved (1).ipynb`) end-to-end.
   With the manifest in place, section 4 will use the full dataset
   instead of falling back to the controlled 1k sample. Section 6
   trains the EfficientNetV2B0. Final artifact lives at
   `/content/drive/MyDrive/safescanqr/final_model.keras`.

4. **Sanity-check before deploying**:
   ```python
   from sklearn.metrics import accuracy_score, classification_report
   import tensorflow as tf, pandas as pd, numpy as np
   from PIL import Image

   m = tf.keras.models.load_model("final_model.keras")
   test_df = pd.read_csv("qr_data.csv").sample(2000, random_state=42)
   X = np.stack([
       np.array(Image.open(p).convert("RGB").resize((192, 192)), dtype=np.float32)
       for p in test_df["file_path"]
   ])
   y_true = (test_df["label"] == "malicious").astype(int).values
   y_pred = (m.predict(X, verbose=0).flatten() > 0.32).astype(int)
   print(accuracy_score(y_true, y_pred))
   print(classification_report(y_true, y_pred, target_names=["benign", "malicious"]))
   ```
   Aim for >0.95 accuracy and balanced precision/recall before shipping.

5. **Deploy the new artifact**:
   - Replace `models/final_model.keras` in this repo.
   - The file is ~40 MB which is fine to commit (the existing one is
     already in the repo).
   - For the larger ensemble (`safescanqr_final_ensemble.keras` at 1.2 GB),
     **don't commit** — store on object storage (S3 / Cloudflare R2) and
     set `SAFESCAN_ML_ENSEMBLE_PATH` to the download URL. The repo has a
     helper that fetches it lazily on first use.

## Phase 3 — Adversarial robustness suite

Once the new models are deployed, build a hold-out set of adversarial
URLs to catch regressions whenever the model changes:

- Percent-encoded paths: `https://google.com/%25%32%65%25%32%65/`
- IDN homographs: `https://а.com/` (Cyrillic а)
- Deeply nested subdomains: `https://login.account.security.update.tk/`
- Open redirects: `https://google.com/url?q=https://evil.test/`
- Recently observed phishing domains (refresh weekly from URLhaus +
  OpenPhish + PhishTank)

Save as `tests/test_adversarial_urls.py` and run on every model swap.

## Phase 4 — Active learning loop (future work)

Backend already audit-logs every scan in `scans` + every user report in
`url_reports`. A weekly cron can:

1. Pull last-7-day `url_reports` with `reason in ('phishing','wallet_drain','malware')`.
2. Pull a balanced negative sample from Tranco top 100K not seen in `scans`.
3. Retrain the URL classifier on the augmented set.
4. Compare new model's adversarial-set accuracy to baseline; reject if
   regression > 1%.
5. Auto-deploy only if it beats baseline.

This is the work that keeps the model from getting stale. Phishing
campaigns rotate domains weekly; a model trained 6 months ago is already
behind.

---

## Inference-time changes already shipped (no retraining needed)

For posterity — these landed in `safescan_model_calibration.py` and are
active right now:

| Improvement | What it does |
|---|---|
| **Tuned threshold (0.32)** | Matches notebook's F1-optimal value, not the 0.5 the inference code was using |
| **Uncertain band** | When probability ∈ [0.20, 0.50], ML signal is **suppressed entirely** — let rules + reputation decide |
| **Lexical feature bonus** | Domain TLD tier, hyphen count, brand-impersonation check — capped at +20% probability nudge |
| **Prediction cache** | SQLite-backed URL → result cache with 1hr TTL, ~saves 40-60% of pipeline cost in steady state |
| **Robust threat-type label** | Uses `bucket == "malicious"` instead of string match on the (now-changed) label |

Tuning knobs (all env vars, all safe defaults):

```
SAFESCAN_ML_MAL_THRESHOLD=0.32       # malicious cut point
SAFESCAN_ML_UNCERTAIN_LOWER=0.20     # uncertain band lower edge
SAFESCAN_ML_UNCERTAIN_UPPER=0.50     # uncertain band upper edge
SAFESCAN_ML_CONFIDENT=0.90           # confident-malicious cutoff
SAFESCAN_ML_CACHE_ENABLED=true       # turn cache off if it misbehaves
SAFESCAN_ML_CACHE_TTL=3600           # cache TTL in seconds
SAFESCAN_ML_CACHE_PATH=...           # SQLite path (defaults to DATA_DIR)
```
