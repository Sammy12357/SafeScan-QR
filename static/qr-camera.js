// SafeScan web camera scanner. QR decoding starts only after "Take picture".
// The native detector is a fast first pass; the self-hosted ZXing worker checks
// the full-resolution frame and protects the multi-code refusal on every browser.
(function () {
  const WORKER_URL = "/static/qr-worker.js?v=scanner-phase-2";
  const WORKER_START_TIMEOUT_MS = 8000;
  const DECODE_TIMEOUT_MS = 6000;

  function validPayloads(values) {
    return [...new Set(values.filter((value) =>
      typeof value === "string" && value.trim() && value.length <= 4096
    ))];
  }

  async function createNativeDetector() {
    if (typeof window.BarcodeDetector !== "function") return null;
    try {
      const supported = await window.BarcodeDetector.getSupportedFormats();
      if (!supported.includes("qr_code")) return null;
      return new window.BarcodeDetector({ formats: ["qr_code"] });
    } catch (_err) {
      return null;
    }
  }

  async function captureFrame(video, canvas, ctx) {
    if (!video.videoWidth || !video.videoHeight) throw new Error("No camera frame is ready.");
    // Transferring a bitmap avoids a large readback on browsers with worker
    // OffscreenCanvas. ImageData is the compatibility path for other browsers.
    if (typeof createImageBitmap === "function" && typeof OffscreenCanvas === "function") {
      try {
        const bitmap = await createImageBitmap(video);
        return { bitmap, transfer: [bitmap] };
      } catch (_err) {
        // Safari and some camera drivers cannot snapshot video to ImageBitmap.
      }
    }
    if (!ctx) throw new Error("Canvas is unavailable in this browser.");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return { imageData, transfer: [imageData.data.buffer] };
  }

  function createWorkerBridge() {
    return new Promise((resolve, reject) => {
      if (typeof Worker !== "function") {
        reject(new Error("Web Workers are unavailable."));
        return;
      }
      let worker;
      try {
        worker = new Worker(WORKER_URL);
      } catch (err) {
        reject(err);
        return;
      }
      let closed = false;
      let ready = false;
      let nextId = 0;
      const pending = new Map();
      const startupTimer = setTimeout(() => fail(new Error("QR decoder took too long to start.")), WORKER_START_TIMEOUT_MS);

      function fail(error) {
        if (closed) return;
        closed = true;
        clearTimeout(startupTimer);
        worker.terminate();
        for (const request of pending.values()) {
          clearTimeout(request.timer);
          request.reject(error);
        }
        pending.clear();
        if (!ready) reject(error);
      }

      async function decode(video, canvas, ctx) {
        if (closed) throw new Error("QR decoder is unavailable.");
        const frame = await captureFrame(video, canvas, ctx);
        const id = ++nextId;
        return new Promise((resolveResult, rejectResult) => {
          const timer = setTimeout(() => {
            pending.delete(id);
            rejectResult(new Error("QR decode timed out."));
          }, DECODE_TIMEOUT_MS);
          pending.set(id, { resolve: resolveResult, reject: rejectResult, timer });
          try {
            worker.postMessage({
              type: "decode", id, mode: "capture",
              ...(frame.bitmap ? { bitmap: frame.bitmap } : { imageData: frame.imageData }),
            }, frame.transfer);
          } catch (error) {
            clearTimeout(timer);
            pending.delete(id);
            rejectResult(error);
          }
        });
      }

      worker.onmessage = (event) => {
        const result = event.data || {};
        if (result.type === "ready") {
          if (closed || ready) return;
          ready = true;
          clearTimeout(startupTimer);
          resolve({ decode, close: () => fail(new Error("QR scanner closed.")) });
          return;
        }
        if (result.type === "init-error") {
          fail(new Error("Local QR decoder failed to start."));
          return;
        }
        const request = pending.get(result.id);
        if (!request) return;
        clearTimeout(request.timer);
        pending.delete(result.id);
        if (result.error) request.reject(new Error("Local QR decoder failed."));
        else request.resolve(result);
      };
      worker.onerror = () => fail(new Error("Local QR decoder stopped."));
    });
  }

  async function buildDecoder() {
    const [nativeDetector, workerBridge] = await Promise.all([
      createNativeDetector(), createWorkerBridge().catch(() => null),
    ]);
    if (!workerBridge) {
      throw new Error('This browser cannot start the local QR decoder. Use "Upload QR file/photo" instead.');
    }
    return {
      kind: nativeDetector ? "BarcodeDetector + local ZXing" : "local ZXing",
      close: () => workerBridge?.close(),
      decode: async (video, canvas, ctx) => {
        let nativeValues = [];
        if (nativeDetector) {
          try {
            const codes = await nativeDetector.detect(video);
            nativeValues = validPayloads((codes || []).map((code) => code.rawValue));
          } catch (_err) {
            // Worker decode remains available if native detection fails.
          }
        }
        if (nativeValues.length > 1) return { ambiguous: true };
        // A native-only result cannot establish that the complete frame has
        // been checked for a competing code. Fail closed if the worker fails.
        const result = await workerBridge.decode(video, canvas, ctx);
        if (result.multipleCodes === true) return { ambiguous: true };
        const workerValues = validPayloads((result.symbols || [])
          .filter((symbol) => symbol.valid === true)
          .map((symbol) => symbol.text));
        const values = validPayloads([...nativeValues, ...workerValues]);
        if (values.length > 1) return { ambiguous: true };
        return values[0] || null;
      },
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
      if (decoder) decoder.close();
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
        if (!active) {
          stream.getTracks().forEach((track) => track.stop());
          return;
        }
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
        // Some Safari builds need a moment before the first frame is ready.
      }

      try {
        decoder = await buildDecoder();
        if (!active) {
          decoder.close();
          return;
        }
      } catch (err) {
        reportError((err && err.message) || "Could not initialise the QR decoder.");
        return;
      }

      // The preview is live so the user can aim, but we never decode on our
      // own — a QR is only read when the user presses "Take picture".
      status.textContent = "Aim at one QR code, then take a picture. " +
        (decoder.kind === "local ZXing" ? "Using the local QR decoder." : "");
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
      let scanError = null;
      try {
        value = await decoder.decode(video, canvas, ctx);
      } catch (error) {
        scanError = error;
      }

      if (!active) return;

      if (value && value.ambiguous) {
        status.textContent = "Multiple different QR codes found. Aim at one code or crop the picture, then try again.";
        captureBtn.disabled = false;
        scanning = false;
        return;
      }

      if (value) {
        status.textContent = "QR detected — analysing…";
        cleanup();
        if (typeof opts.onResult === "function") opts.onResult(value);
        return;
      }

      status.textContent = scanError
        ? 'The local QR decoder could not read this picture. Go back and use "Upload QR file/photo".'
        : "No QR code found in that picture. Line it up and take another.";
      captureBtn.disabled = false;
      scanning = false;
    }

    captureBtn.addEventListener("click", capture);
  }

  window.SafeScanQrCamera = { open: openScanner };
})();
