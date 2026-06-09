// SafeScan live QR scanner.
//
// Architecture:
//   1. getUserMedia → live <video> stream (rear camera preferred) so the
//      user can aim, but we never decode on our own.
//   2. The user presses "Take picture" and we decode that single frame —
//      nothing is read until they deliberately capture.
//   3. Decoder is BarcodeDetector when available (native, ~free CPU on
//      Chrome Android / Edge), else jsQR loaded lazily from the
//      CSP-allowed jsdelivr CDN as a fallback for iOS Safari / Firefox.
//
// Notes on mobile gotchas:
//   • <video playsinline muted> is required for iOS — without playsinline
//     iOS Safari fullscreens the video and the rAF loop pauses.
//   • getUserMedia must be called from a user gesture (we only call from
//     the click handler).
//   • The page must be HTTPS (or localhost) — Render's domain already is.
//   • Permissions-Policy: camera=(self) must be set server-side, otherwise
//     getUserMedia rejects with NotAllowedError before the user even sees
//     the prompt. See hackabull.py middleware.

(function () {
  const JS_QR_CDN = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js";
  const FALLBACK_MAX_DIM = 720; // downsample for jsQR to keep mobile CPU happy.
  const ENHANCED_SCAN_EVERY_N_FRAMES = 3;
  const STYLIZED_THRESHOLDS = [55, 70, 85, 95, 115, 135, 155, 185];

  let jsQRLoader = null;
  let fallbackFrameCount = 0;
  function loadJsQR() {
    if (typeof window.jsQR === "function") return Promise.resolve(window.jsQR);
    if (jsQRLoader) return jsQRLoader;
    jsQRLoader = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = JS_QR_CDN;
      script.async = true;
      script.crossOrigin = "anonymous";
      script.referrerPolicy = "no-referrer";
      script.onload = () => {
        if (typeof window.jsQR === "function") resolve(window.jsQR);
        else reject(new Error("jsQR did not load."));
      };
      script.onerror = () => reject(new Error("Could not load the QR fallback decoder."));
      document.head.appendChild(script);
    });
    return jsQRLoader;
  }

  function drawVideoFrame(video, canvas, ctx) {
    const vw = video.videoWidth;
    const vh = video.videoHeight;
    if (!vw || !vh) return null;
    const scale = Math.min(1, FALLBACK_MAX_DIM / Math.max(vw, vh));
    const w = Math.max(1, Math.round(vw * scale));
    const h = Math.max(1, Math.round(vh * scale));
    if (canvas.width !== w) canvas.width = w;
    if (canvas.height !== h) canvas.height = h;
    ctx.drawImage(video, 0, 0, w, h);
    return ctx.getImageData(0, 0, w, h);
  }

  function decodeWithJsQRPasses(jsQR, imageData, w, h, includeEnhanced) {
    const raw = jsQR(imageData.data, w, h, { inversionAttempts: "attemptBoth" });
    if (raw && raw.data) return raw.data;
    if (!includeEnhanced) return null;

    const source = imageData.data;
    const pixels = w * h;
    const gray = new Uint8ClampedArray(pixels);
    let min = 255;
    let max = 0;

    for (let index = 0, pixel = 0; pixel < pixels; index += 4, pixel += 1) {
      const luminance = Math.round(source[index] * 0.299 + source[index + 1] * 0.587 + source[index + 2] * 0.114);
      gray[pixel] = luminance;
      if (luminance < min) min = luminance;
      if (luminance > max) max = luminance;
    }

    const span = Math.max(1, max - min);
    const enhanced = new Uint8ClampedArray(source.length);
    for (const threshold of STYLIZED_THRESHOLDS) {
      for (let pixel = 0, index = 0; pixel < pixels; pixel += 1, index += 4) {
        const normalized = Math.round(((gray[pixel] - min) * 255) / span);
        const value = normalized > threshold ? 255 : 0;
        enhanced[index] = value;
        enhanced[index + 1] = value;
        enhanced[index + 2] = value;
        enhanced[index + 3] = 255;
      }
      const code = jsQR(enhanced, w, h, { inversionAttempts: "attemptBoth" });
      if (code && code.data) return code.data;
    }
    return null;
  }

  async function decodeWithJsQRFallback(video, canvas, ctx, includeEnhanced) {
    const jsQR = await loadJsQR();
    const imageData = drawVideoFrame(video, canvas, ctx);
    if (!imageData) return null;
    return decodeWithJsQRPasses(jsQR, imageData, canvas.width, canvas.height, includeEnhanced);
  }

  async function buildDecoder() {
    const hasNativeDetector = "BarcodeDetector" in window;
    if (hasNativeDetector) {
      try {
        const supported = await window.BarcodeDetector.getSupportedFormats();
        if (supported.indexOf("qr_code") !== -1) {
          const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
          return {
            kind: "BarcodeDetector",
            decode: async (video, canvas, ctx, forceEnhanced) => {
              const codes = await detector.detect(video);
              if (codes && codes[0]) return codes[0].rawValue;
              // On an explicit capture, spend the extra effort: load jsQR (if
              // it isn't already) and run the stylized-threshold enhancement
              // pass so a single press has the best possible chance of reading
              // a tricky code.
              if (forceEnhanced) {
                try {
                  return await decodeWithJsQRFallback(video, canvas, ctx, true);
                } catch (_e) {
                  return null;
                }
              }
              if (typeof window.jsQR !== "function") return null;
              fallbackFrameCount += 1;
              return decodeWithJsQRFallback(video, canvas, ctx, fallbackFrameCount % ENHANCED_SCAN_EVERY_N_FRAMES === 0);
            }
          };
        }
      } catch (err) {
        // Some Android builds throw on getSupportedFormats — fall through.
      }
    }
    // No native detector available (iOS Safari < 17, older browsers). Load
    // jsQR from the CDN; surface a clear, actionable message if it fails so
    // the user can switch to the upload path instead of staring at a frozen
    // viewfinder.
    let jsQR;
    try {
      jsQR = await loadJsQR();
    } catch (err) {
      const reason = hasNativeDetector
        ? "Live scanning isn't supported in this browser and the fallback decoder failed to load."
        : "Live scanning isn't supported in this browser, and the fallback decoder could not be reached (check your connection).";
      const richError = new Error(reason + " Use \"Upload QR file/photo\" instead.");
      richError.code = "qr_decoder_unavailable";
      throw richError;
    }
    return {
      kind: "jsQR",
      decode: (video, canvas, ctx, forceEnhanced) => {
        const imageData = drawVideoFrame(video, canvas, ctx);
        if (!imageData) return null;
        fallbackFrameCount += 1;
        const includeEnhanced = forceEnhanced || fallbackFrameCount % ENHANCED_SCAN_EVERY_N_FRAMES === 0;
        return decodeWithJsQRPasses(jsQR, imageData, canvas.width, canvas.height, includeEnhanced);
      }
    };
  }

  function buildModal() {
    const modal = document.createElement("div");
    modal.className = "qr-camera-modal";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-label", "Live QR scanner");
    modal.innerHTML =
      '<div class="qr-camera-card">' +
        '<div class="qr-camera-header">' +
          '<h3>Scan a QR code</h3>' +
          '<button class="qr-camera-close" type="button" aria-label="Back to scanner">Back</button>' +
        '</div>' +
        '<div class="qr-camera-stage">' +
          '<video class="qr-camera-video" autoplay playsinline muted></video>' +
          '<div class="qr-camera-frame" aria-hidden="true"></div>' +
        '</div>' +
        '<p class="qr-camera-status" aria-live="polite">Starting camera…</p>' +
        '<div class="qr-camera-actions">' +
          '<button class="qr-camera-capture" type="button" disabled>Take picture</button>' +
        '</div>' +
      '</div>';
    return modal;
  }

  function openScanner(options) {
    const opts = options || {};
    const modal = buildModal();
    document.body.appendChild(modal);
    document.body.classList.add("qr-camera-open");

    const video = modal.querySelector("video");
    const status = modal.querySelector(".qr-camera-status");
    const closeBtn = modal.querySelector(".qr-camera-close");
    const captureBtn = modal.querySelector(".qr-camera-capture");
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

    let stream = null;
    let active = true;
    let decoder = null;
    let scanning = false;

    function cleanup() {
      if (!active) return;
      active = false;
      if (stream) {
        stream.getTracks().forEach((track) => {
          try { track.stop(); } catch (_e) {}
        });
      }
      document.body.classList.remove("qr-camera-open");
      modal.remove();
      if (typeof opts.onClose === "function") opts.onClose();
    }

    closeBtn.addEventListener("click", cleanup);
    modal.addEventListener("click", (event) => {
      if (event.target === modal) cleanup();
    });
    document.addEventListener("keydown", function escapeHandler(event) {
      if (!active) {
        document.removeEventListener("keydown", escapeHandler);
        return;
      }
      if (event.key === "Escape") cleanup();
    });

    function reportError(message) {
      status.textContent = message;
      if (typeof opts.onError === "function") opts.onError(message);
    }

    (async function start() {
      if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== "function") {
        reportError("This browser cannot access the camera. Use Upload QR or paste the URL.");
        return;
      }
      if (!window.isSecureContext) {
        reportError("Camera access requires HTTPS. Open the secure version of this page.");
        return;
      }

      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: { ideal: "environment" },
            width: { ideal: 1280 },
            height: { ideal: 720 }
          },
          audio: false
        });
      } catch (err) {
        if (err && err.name === "NotAllowedError") {
          reportError("Camera access was blocked. Allow it in your browser to scan.");
        } else if (err && err.name === "NotFoundError") {
          reportError("No camera found on this device.");
        } else {
          reportError((err && err.message) || "Could not start the camera.");
        }
        return;
      }

      video.srcObject = stream;
      try {
        await video.play();
      } catch (_e) {
        // Some Safari builds need a tick before play() resolves; the rAF
        // loop will pick up frames once HAVE_ENOUGH_DATA is reached.
      }

      try {
        decoder = await buildDecoder();
      } catch (err) {
        reportError((err && err.message) || "Could not initialise the QR decoder.");
        return;
      }

      // The preview is live so the user can aim, but we never decode on our
      // own — a QR is only read when the user presses "Take picture".
      status.textContent = decoder.kind === "BarcodeDetector"
        ? "Line up the QR code, then take a picture."
        : "Line up the QR code, then take a picture. (using fallback decoder)";
      captureBtn.disabled = false;
    })();

    // Capture handler: grab the current frame and decode it once. Nothing
    // happens until the user clicks, so this is a deliberate "take a photo of
    // the QR code" action rather than continuous auto-scanning.
    async function capture() {
      if (!active || scanning || !decoder) return;
      if (video.readyState < 2 /* HAVE_CURRENT_DATA */) {
        status.textContent = "Camera is still warming up — try again in a second.";
        return;
      }
      scanning = true;
      captureBtn.disabled = true;
      status.textContent = "Reading the QR code…";

      let value = null;
      try {
        value = await decoder.decode(video, canvas, ctx, true);
      } catch (_e) {
        value = null;
      }

      if (!active) return;

      if (value) {
        status.textContent = "QR detected — analysing…";
        cleanup();
        if (typeof opts.onResult === "function") opts.onResult(value);
        return;
      }

      status.textContent = "No QR code found in that picture. Line it up and take another.";
      captureBtn.disabled = false;
      scanning = false;
    }

    captureBtn.addEventListener("click", capture);
  }

  window.SafeScanQrCamera = { open: openScanner };
})();
