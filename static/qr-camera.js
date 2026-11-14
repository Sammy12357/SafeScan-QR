// SafeScan web camera scanner. QR decoding starts only after "Take picture".
// The native detector is a fast first pass; the self-hosted ZXing worker checks
// the whole frame and protects the multi-code refusal on every browser.
(function () {
  const WORKER_URL = "/static/qr-worker.js?v=scanner-phase-4";
  const WORKER_START_TIMEOUT_MS = 8000;
  const DECODE_TIMEOUT_MS = 6000;
  const MAX_BURST_PIXELS = 3_000_000;
  const CAMERA_DEVICE_KEY = "safescan-qr-camera-device:" + window.location.origin;

  function savedDeviceId() {
    try { return window.localStorage.getItem(CAMERA_DEVICE_KEY) || null; }
    catch (_err) { return null; }
  }

  function rememberDeviceId(deviceId) {
    try {
      if (deviceId) window.localStorage.setItem(CAMERA_DEVICE_KEY, deviceId);
      else window.localStorage.removeItem(CAMERA_DEVICE_KEY);
    } catch (_err) { /* Private browsing may block localStorage. */ }
  }

  function cameraCapabilities(track) {
    try { return track && typeof track.getCapabilities === "function" ? track.getCapabilities() || {} : {}; }
    catch (_err) { return {}; }
  }

  function cameraSettings(track) {
    try { return track && typeof track.getSettings === "function" ? track.getSettings() || {} : {}; }
    catch (_err) { return {}; }
  }

  function supportsMode(capabilities, property, mode) {
    return Array.isArray(capabilities[property]) && capabilities[property].includes(mode);
  }

  async function acquireCamera(deviceId) {
    const target = deviceId ? { deviceId: { exact: deviceId } } : { facingMode: { ideal: "environment" } };
    const variants = [
      { ...target, width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } },
      { ...target, width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
      target,
    ];
    let lastError;
    for (const video of variants) {
      try { return await navigator.mediaDevices.getUserMedia({ video, audio: false }); }
      catch (error) {
        lastError = error;
        if (!error || error.name !== "OverconstrainedError") throw error;
      }
    }
    throw lastError || new Error("No compatible camera settings were found.");
  }

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

  async function captureFrame(video, canvas, ctx, allowBitmap) {
    if (!video.videoWidth || !video.videoHeight) throw new Error("No camera frame is ready.");
    const scale = Math.min(1, Math.sqrt(MAX_BURST_PIXELS / (video.videoWidth * video.videoHeight)));
    const width = Math.max(1, Math.round(video.videoWidth * scale));
    const height = Math.max(1, Math.round(video.videoHeight * scale));
    // Cap six-frame memory on cameras that exceed the 1920x1080 request.
    // Bitmap transfer avoids readback when the worker supports OffscreenCanvas;
    // ImageData is the compatibility path for other browsers.
    if (allowBitmap && typeof createImageBitmap === "function") {
      try {
        const bitmap = scale < 1
          ? await createImageBitmap(video, { resizeWidth: width, resizeHeight: height, resizeQuality: "high" })
          : await createImageBitmap(video);
        if (bitmap.width * bitmap.height <= MAX_BURST_PIXELS) return { bitmap, transfer: [bitmap] };
        bitmap.close?.();
      } catch (_err) {
        // Safari and some camera drivers cannot snapshot video to ImageBitmap.
      }
    }
    if (!ctx) throw new Error("Canvas is unavailable in this browser.");
    canvas.width = width;
    canvas.height = height;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return { imageData, transfer: [imageData.data.buffer] };
  }

  function captureSample(video, canvas, ctx, maxDimension) {
    const scale = Math.min(1, maxDimension / Math.max(video.videoWidth, video.videoHeight));
    canvas.width = Math.max(1, Math.round(video.videoWidth * scale));
    canvas.height = Math.max(1, Math.round(video.videoHeight * scale));
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return { imageData, transfer: [imageData.data.buffer] };
  }

  function disposeFrame(frame) {
    try { frame?.bitmap?.close?.(); } catch (_err) { /* It may have transferred. */ }
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

      async function request(mode, frame) {
        if (closed) throw new Error("QR decoder is unavailable.");
        const id = ++nextId;
        return new Promise((resolveResult, rejectResult) => {
          const timer = setTimeout(() => {
            pending.delete(id);
            rejectResult(new Error("QR decode timed out."));
          }, DECODE_TIMEOUT_MS);
          pending.set(id, { resolve: resolveResult, reject: rejectResult, timer });
          try {
            worker.postMessage({
              type: "decode", id, mode,
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
          resolve({ request, supportsBitmap: result.offscreenCanvas === true,
            close: () => fail(new Error("QR scanner closed.")) });
          return;
        }
        if (result.type === "init-error") {
          fail(new Error("Local QR decoder failed to start."));
          return;
        }
        const pendingRequest = pending.get(result.id);
        if (!pendingRequest) return;
        clearTimeout(pendingRequest.timer);
        pending.delete(result.id);
        if (result.error) pendingRequest.reject(new Error("Local QR decoder failed."));
        else pendingRequest.resolve(result);
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
      supportsBitmap: workerBridge.supportsBitmap,
      close: () => workerBridge?.close(),
      score: (frame) => workerBridge.request("score", frame),
      locate: (frame) => workerBridge.request("locate", frame),
      decode: async (frame) => {
        let nativeValues = [];
        if (nativeDetector) {
          try {
            const codes = await nativeDetector.detect(frame.bitmap || frame.imageData);
            if ((codes || []).length > 1) return { ambiguous: true };
            nativeValues = validPayloads((codes || []).map((code) => code.rawValue));
          } catch (_err) {
            // Worker decode remains available if native detection fails.
          }
        }
        if (nativeValues.length > 1) return { ambiguous: true };
        // A native-only result cannot establish that the complete frame has
        // been checked for a competing code. Fail closed if the worker fails.
        const result = await workerBridge.request("capture", frame);
        if (result.multipleCodes === true) return { ambiguous: true };
        if (result.structuredAppend === true) return { ambiguous: true, structuredAppend: true };
        const workerValues = validPayloads((result.symbols || [])
          .filter((symbol) => symbol.valid === true)
          .map((symbol) => symbol.text));
        const values = validPayloads([...nativeValues, ...workerValues]);
        if (values.length > 1) return { ambiguous: true };
        return values[0] || null;
      },
    };
  }

  function quadPoints(quad) {
    return quad && [quad.topLeft, quad.topRight, quad.bottomRight, quad.bottomLeft].every(
      (point) => point && Number.isFinite(point.x) && Number.isFinite(point.y)
    ) ? [quad.topLeft, quad.topRight, quad.bottomRight, quad.bottomLeft] : null;
  }

  function quadBox(quad) {
    const points = quadPoints(quad);
    if (!points) return null;
    const xs = points.map((point) => point.x);
    const ys = points.map((point) => point.y);
    const x = Math.min(...xs);
    const y = Math.min(...ys);
    return { x, y, width: Math.max(...xs) - x, height: Math.max(...ys) - y };
  }

  function physicalSymbols(symbols) {
    const found = [];
    for (const symbol of symbols || []) {
      const box = quadBox(symbol.quad);
      if (!box) continue;
      const center = { x: box.x + box.width / 2, y: box.y + box.height / 2 };
      const same = found.some(({ box: other }) =>
        Math.hypot(center.x - other.x - other.width / 2, center.y - other.y - other.height / 2) <
        Math.max(12, Math.min(box.width, box.height, other.width, other.height) * 0.2));
      if (!same) found.push({ symbol, box });
    }
    return found;
  }

  function boxesOverlap(first, second) {
    const width = Math.max(0, Math.min(first.x + first.width, second.x + second.width) - Math.max(first.x, second.x));
    const height = Math.max(0, Math.min(first.y + first.height, second.y + second.height) - Math.max(first.y, second.y));
    return width * height > 0.02 * Math.min(first.width * first.height, second.width * second.height);
  }

  function guidanceFor(result, visible, now, noCodeSince, blurSince, canZoom) {
    if (visible.length > 1) {
      return visible.some((item, index) => visible.slice(index + 1).some((other) => boxesOverlap(item.box, other.box)))
        ? "One code is stuck on top of another. This can be a QR sticker scam. Aim at one code."
        : "Two codes in view. Aim at just one.";
    }
    const item = visible[0];
    if (!item) return now - noCodeSince >= 4000 ? "Can't see a code. Try more light or upload a photo instead." : "Aim at one QR code.";
    const { box, symbol } = item;
    const width = result.width || 1;
    const height = result.height || 1;
    if (box.x <= width * 0.02) return "Move the code right so it is fully visible.";
    if (box.x + box.width >= width * 0.98) return "Move the code left so it is fully visible.";
    if (box.y <= height * 0.02) return "Move the code down so it is fully visible.";
    if (box.y + box.height >= height * 0.98) return "Move the code up so it is fully visible.";
    if (Math.min(box.width, box.height) < Math.min(width, height) * 0.15) {
      return canZoom ? "The code is small. Move closer or tap zoom." : "The code is small. Move closer.";
    }
    if (blurSince && now - blurSince >= 1000) return "Hold steady. Tap the code to focus.";
    if ((symbol.stats?.meanLuma ?? result.stats?.meanLuma ?? 255) < 50) return "Too dark. Add light or use the flashlight.";
    if (symbol.stats?.brightFraction > 0.7 && symbol.stats?.darkFraction < 0.08) return "Glare may hide the code. Tilt the phone a little.";
    const points = quadPoints(symbol.quad);
    if (points) {
      const top = Math.hypot(points[1].x - points[0].x, points[1].y - points[0].y);
      const bottom = Math.hypot(points[2].x - points[3].x, points[2].y - points[3].y);
      if (Math.max(top, bottom) / Math.max(1, Math.min(top, bottom)) > 1.6) return "Face the code more straight on.";
    }
    return symbol.valid ? "Code found. Take a picture to check it." : "Almost. Hold still and take the picture.";
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
          '<canvas class="qr-camera-overlay" aria-hidden="true"></canvas>' +
          '<div class="qr-camera-frame" aria-hidden="true"></div>' +
        '</div>' +
        '<p class="qr-camera-status" aria-live="polite">Starting camera…</p>' +
        '<div class="qr-camera-controls" aria-label="Camera controls" hidden>' +
          '<button class="qr-camera-switch" type="button" hidden>Switch camera</button>' +
          '<button class="qr-camera-zoom" type="button" hidden>2× zoom</button>' +
          '<button class="qr-camera-torch" type="button" aria-pressed="false" hidden>Flashlight off</button>' +
          '<button class="qr-camera-auto" type="button" aria-pressed="false">Auto-capture off</button>' +
        '</div>' +
        '<div class="qr-camera-actions">' +
          '<button class="qr-camera-capture" type="button" disabled>Take picture</button>' +
          '<button class="qr-camera-retry" type="button" hidden>Retry camera</button>' +
        '</div>' +
        '<div class="qr-camera-server-offer" hidden>' +
          '<p>Couldn\'t read it here. Send the clearest photo to SafeScan for another try? The image is processed in memory and is not saved.</p>' +
          '<button class="qr-camera-server-send" type="button">Send photo to SafeScan</button>' +
        '</div>' +
      '</div>';
    return modal;
  }

  function openScanner(options) {
    const opts = options || {};
    if (document.querySelector(".qr-camera-modal")) return;
    const modal = buildModal();
    document.body.appendChild(modal);
    document.body.classList.add("qr-camera-open");

    const video = modal.querySelector("video");
    const status = modal.querySelector(".qr-camera-status");
    const closeBtn = modal.querySelector(".qr-camera-close");
    const captureBtn = modal.querySelector(".qr-camera-capture");
    const controls = modal.querySelector(".qr-camera-controls");
    const switchBtn = modal.querySelector(".qr-camera-switch");
    const zoomBtn = modal.querySelector(".qr-camera-zoom");
    const torchBtn = modal.querySelector(".qr-camera-torch");
    const autoBtn = modal.querySelector(".qr-camera-auto");
    const retryBtn = modal.querySelector(".qr-camera-retry");
    const serverOffer = modal.querySelector(".qr-camera-server-offer");
    const serverSendBtn = modal.querySelector(".qr-camera-server-send");
    const overlay = modal.querySelector(".qr-camera-overlay");
    const overlayContext = overlay.getContext("2d");
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    const locateCanvas = document.createElement("canvas");
    const locateContext = locateCanvas.getContext("2d", { willReadFrequently: true });
    const scoreCanvas = document.createElement("canvas");
    const scoreContext = scoreCanvas.getContext("2d", { willReadFrequently: true });
    const fallbackCanvas = document.createElement("canvas");
    const fallbackContext = fallbackCanvas.getContext("2d", { willReadFrequently: true });

    let stream = null;
    let track = null;
    let active = true;
    let decoder = null;
    let decoderPromise = null;
    let scanning = false;
    let cameraGeneration = 0;
    let selectedDeviceId = savedDeviceId();
    let cameras = [];
    let capabilities = {};
    let zoomBase = 1;
    let zoomTarget = 2;
    let zoomed = false;
    let torchOn = false;
    let focusTimer = null;
    let beginPromise = null;
    let beginTarget = null;
    let locateTimer = null;
    let videoFrameHandle = null;
    let autoArmed = false;
    let autoCandidate = null;
    let lastHapticText = null;
    let noCodeSince = Date.now();
    let blurSince = null;
    let lastGuidanceAt = 0;
    let lastGuidanceText = "";
    let fallbackBlob = null;

    function clearOverlay() {
      if (overlayContext) overlayContext.clearRect(0, 0, overlay.width, overlay.height);
    }

    function drawOutlines(result, visible) {
      if (!overlayContext || !result.width || !result.height) return;
      const stage = modal.querySelector(".qr-camera-stage");
      const rect = stage.getBoundingClientRect();
      const ratio = Math.min(2, window.devicePixelRatio || 1);
      overlay.width = Math.max(1, Math.round(rect.width * ratio));
      overlay.height = Math.max(1, Math.round(rect.height * ratio));
      overlayContext.setTransform(ratio, 0, 0, ratio, 0, 0);
      overlayContext.clearRect(0, 0, rect.width, rect.height);
      const scale = Math.max(rect.width / result.width, rect.height / result.height);
      const cropX = (result.width * scale - rect.width) / 2;
      const cropY = (result.height * scale - rect.height) / 2;
      overlayContext.lineWidth = 3;
      const accent = typeof window.getComputedStyle === "function"
        ? window.getComputedStyle(stage).getPropertyValue("--accent").trim() : "";
      overlayContext.strokeStyle = visible.length > 1 ? "#ff4c7f" : accent || "#ff4c7f";
      for (const { symbol } of visible) {
        const points = quadPoints(symbol.quad);
        if (!points) continue;
        overlayContext.beginPath();
        points.forEach((point, index) => {
          let x = point.x * scale - cropX;
          if (video.classList.contains("is-mirrored")) x = rect.width - x;
          const y = point.y * scale - cropY;
          if (index === 0) overlayContext.moveTo(x, y);
          else overlayContext.lineTo(x, y);
        });
        overlayContext.closePath();
        overlayContext.stroke();
      }
    }

    function cancelLocate() {
      if (locateTimer) clearTimeout(locateTimer);
      locateTimer = null;
      if (videoFrameHandle !== null && typeof video.cancelVideoFrameCallback === "function") {
        video.cancelVideoFrameCallback(videoFrameHandle);
      }
      videoFrameHandle = null;
      autoCandidate = null;
      clearOverlay();
    }

    function setAutoArmed(enabled) {
      autoArmed = enabled;
      autoCandidate = null;
      autoBtn.textContent = enabled ? "Auto-capture on" : "Auto-capture off";
      autoBtn.setAttribute("aria-pressed", String(enabled));
    }

    function updateGuidance(result) {
      const now = Date.now();
      const visible = physicalSymbols(result.symbols);
      drawOutlines(result, visible);
      if (visible.length) noCodeSince = now;
      const soft = result.stats?.sharpness;
      if (Number.isFinite(soft) && soft < 20) blurSince ||= now;
      else blurSince = null;

      if (visible.length === 1 && visible[0].symbol.valid) {
        if (lastHapticText !== visible[0].symbol.text) {
          try { navigator.vibrate?.(30); } catch (_err) { /* Optional haptic. */ }
          lastHapticText = visible[0].symbol.text;
        }
      } else lastHapticText = null;

      if (autoArmed && visible.length === 1 && visible[0].symbol.valid &&
          Number.isFinite(soft) && soft >= 20) {
        const { box, symbol } = visible[0];
        const centerX = box.x + box.width / 2;
        const centerY = box.y + box.height / 2;
        const edge = box.x <= result.width * 0.02 || box.y <= result.height * 0.02 ||
          box.x + box.width >= result.width * 0.98 || box.y + box.height >= result.height * 0.98;
        if (!edge && autoCandidate?.text === symbol.text &&
            Math.hypot(centerX - autoCandidate.x, centerY - autoCandidate.y) < Math.min(result.width, result.height) * 0.08) {
          autoCandidate.count += 1;
          autoCandidate.x = centerX;
          autoCandidate.y = centerY;
        } else autoCandidate = edge ? null : { text: symbol.text, x: centerX, y: centerY, count: 1, firstAt: now };
        if (autoCandidate?.count >= 3 && now - autoCandidate.firstAt >= 800) {
          setAutoArmed(false);
          void capture();
          return;
        }
      } else autoCandidate = null;

      const guidance = guidanceFor(result, visible, now, noCodeSince, blurSince, !zoomBtn.hidden);
      if (guidance !== lastGuidanceText && now - lastGuidanceAt >= 1500) {
        status.textContent = guidance;
        lastGuidanceText = guidance;
        lastGuidanceAt = now;
      }
    }

    function scheduleLocate(generation) {
      if (!active || scanning || generation !== cameraGeneration || !track || document.hidden) return;
      locateTimer = setTimeout(() => {
        locateTimer = null;
        if (!active || scanning || generation !== cameraGeneration || !track) return;
        if (typeof video.requestVideoFrameCallback === "function") {
          videoFrameHandle = video.requestVideoFrameCallback(() => {
            videoFrameHandle = null;
            void locateOnce(generation);
          });
        } else void locateOnce(generation);
      }, 200);
    }

    async function locateOnce(generation) {
      if (!active || scanning || generation !== cameraGeneration || !decoder || !locateContext ||
          !video.videoWidth || !video.videoHeight) return;
      try {
        const result = await decoder.locate(captureSample(video, locateCanvas, locateContext, 960));
        if (active && !scanning && generation === cameraGeneration) updateGuidance(result);
      } catch (_err) { /* A busy guidance frame is disposable. */ }
      scheduleLocate(generation);
    }

    function updateControlsVisibility() {
      controls.hidden = switchBtn.hidden && zoomBtn.hidden && torchBtn.hidden && autoBtn.hidden;
    }

    function hideControls() {
      switchBtn.hidden = true;
      zoomBtn.hidden = true;
      torchBtn.hidden = true;
      autoBtn.hidden = true;
      updateControlsVisibility();
    }

    function clearFocusTimer() {
      if (focusTimer) clearTimeout(focusTimer);
      focusTimer = null;
    }

    function stopStream() {
      cancelLocate();
      clearFocusTimer();
      const oldStream = stream;
      stream = null;
      track = null;
      if (oldStream) {
        oldStream.getTracks().forEach((mediaTrack) => {
          mediaTrack.onended = null;
          try { mediaTrack.stop(); } catch (_err) { /* Already stopped. */ }
        });
      }
      try { video.pause(); } catch (_err) { /* Preview may not have started. */ }
      video.srcObject = null;
    }

    function refreshFrameSize() {
      // Read the actual sensor dimensions again after rotation or resizing.
      // The capture path always uses videoWidth/videoHeight, never CSS pixels.
      video.dataset.frameWidth = String(video.videoWidth || 0);
      video.dataset.frameHeight = String(video.videoHeight || 0);
    }

    function cameraError(error) {
      if (error && error.name === "NotAllowedError") return "Camera access was blocked. Allow it in your browser, then retry.";
      if (error && error.name === "NotFoundError") return "No camera found on this device. You can upload a QR photo instead.";
      if (error && error.name === "NotReadableError") return "Camera is in use by another app. Close that app, then retry.";
      if (error && error.name === "OverconstrainedError") return "This camera cannot use the requested settings. Try another camera or upload a photo.";
      return "Could not start the camera. Retry or upload a QR photo instead.";
    }

    function reportError(message) {
      status.textContent = message;
      if (typeof opts.onError === "function") opts.onError(message);
    }

    async function refreshCameras(generation) {
      if (!active || !track || !navigator.mediaDevices.enumerateDevices) return;
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        if (!active || generation !== cameraGeneration) return;
        // Device labels are localized. Let the user cycle through all video
        // inputs instead of guessing which labels mean "rear".
        cameras = devices.filter((device) => device.kind === "videoinput" && device.deviceId);
        const currentId = cameraSettings(track).deviceId;
        const currentIndex = cameras.findIndex((device) => device.deviceId === currentId);
        switchBtn.hidden = cameras.length < 2;
        switchBtn.textContent = cameras.length > 1
          ? "Switch camera" + (currentIndex >= 0 ? ` (${currentIndex + 1}/${cameras.length})` : "")
          : "Switch camera";
        switchBtn.setAttribute("aria-label", currentIndex >= 0 && cameras[currentIndex].label
          ? `Switch camera. Current: ${cameras[currentIndex].label}` : "Switch camera");
        updateControlsVisibility();
      } catch (_err) {
        if (active && generation === cameraGeneration) {
          cameras = [];
          switchBtn.hidden = true;
          updateControlsVisibility();
        }
      }
    }

    async function applyContinuousModes(currentTrack, currentCaps) {
      if (typeof currentTrack.applyConstraints !== "function") return;
      for (const [property, mode] of [["focusMode", "continuous"], ["exposureMode", "continuous"]]) {
        if (!supportsMode(currentCaps, property, mode)) continue;
        try { await currentTrack.applyConstraints({ advanced: [{ [property]: mode }] }); }
        catch (_err) { /* A camera may advertise a mode but reject it. */ }
      }
    }

    function showTrackControls(currentTrack) {
      capabilities = cameraCapabilities(currentTrack);
      const settings = cameraSettings(currentTrack);
      const mirrorPreview = settings.facingMode === "user" || !settings.facingMode;
      video.classList.toggle("is-mirrored", mirrorPreview);
      zoomed = false;
      torchOn = false;
      torchBtn.setAttribute("aria-pressed", "false");
      torchBtn.textContent = "Flashlight off";
      torchBtn.hidden = !(capabilities.torch === true ||
        (Array.isArray(capabilities.torch) && capabilities.torch.includes(true)));
      const zoom = capabilities.zoom;
      zoomBase = zoom && Number.isFinite(zoom.min)
        ? Math.max(1, zoom.min, Number.isFinite(settings.zoom) ? settings.zoom : 1)
        : 1;
      zoomTarget = zoom && Number.isFinite(zoom.max) ? Math.min(zoom.max, zoomBase * 2) : zoomBase;
      zoomBtn.hidden = !(zoomTarget > zoomBase + 0.05 && typeof currentTrack.applyConstraints === "function");
      zoomBtn.textContent = `${Number((zoomTarget / zoomBase).toFixed(1))}× zoom`;
      zoomBtn.setAttribute("aria-pressed", "false");
      autoBtn.hidden = false;
      updateControlsVisibility();
    }

    async function startCamera(requestedDeviceId) {
      if (!active || document.hidden) return false;
      if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== "function") {
        reportError("This browser cannot access the camera. Use Upload QR or paste the URL.");
        retryBtn.hidden = false;
        return false;
      }
      if (!window.isSecureContext) {
        reportError("Camera access requires HTTPS. Open the secure version of this page.");
        retryBtn.hidden = true;
        return false;
      }
      const generation = ++cameraGeneration;
      scanning = false;
      fallbackBlob = null;
      serverOffer.hidden = true;
      setAutoArmed(false);
      captureBtn.disabled = true;
      retryBtn.hidden = true;
      hideControls();
      status.textContent = "Starting camera…";
      stopStream();

      let acquired;
      try {
        try { acquired = await acquireCamera(requestedDeviceId); }
        catch (error) {
          // A remembered device can disappear between visits. Restore the
          // default environment camera without making the scanner unusable.
          if (!requestedDeviceId || requestedDeviceId !== savedDeviceId() || error?.name === "NotAllowedError") throw error;
          rememberDeviceId(null);
          requestedDeviceId = null;
          acquired = await acquireCamera(null);
        }
      } catch (error) {
        if (active && generation === cameraGeneration) {
          reportError(cameraError(error));
          retryBtn.hidden = false;
        }
        return false;
      }
      if (!active || generation !== cameraGeneration || document.hidden) {
        acquired.getTracks().forEach((mediaTrack) => mediaTrack.stop());
        return false;
      }

      stream = acquired;
      track = acquired.getVideoTracks()[0] || null;
      if (!track) {
        stopStream();
        reportError("This camera did not provide a video track. Try another camera.");
        retryBtn.hidden = false;
        return false;
      }
      const currentTrack = track;
      currentTrack.onended = () => {
        if (!active || generation !== cameraGeneration || track !== currentTrack) return;
        cameraGeneration += 1;
        beginPromise = null;
        beginTarget = null;
        stopStream();
        captureBtn.disabled = true;
        hideControls();
        retryBtn.hidden = false;
        reportError("Camera stopped or was taken by another app. Tap Retry camera.");
      };
      video.srcObject = stream;
      try { await video.play(); }
      catch (_error) {
        if (active && generation === cameraGeneration) {
          stopStream();
          retryBtn.hidden = false;
          reportError("Camera preview could not start. Tap Retry camera or upload a QR photo.");
        }
        return false;
      }
      if (!active || generation !== cameraGeneration || document.hidden) return false;
      refreshFrameSize();
      showTrackControls(currentTrack);
      await applyContinuousModes(currentTrack, capabilities);
      if (!active || generation !== cameraGeneration) return false;

      try {
        if (!decoderPromise) decoderPromise = buildDecoder();
        decoder = await decoderPromise;
      } catch (error) {
        decoderPromise = null;
        decoder = null;
        if (active && generation === cameraGeneration) {
          if (typeof opts.onServerFallback === "function") {
            // The camera still works when WASM/Worker startup fails. A frame
            // can be captured locally and offered for explicit server consent.
            selectedDeviceId = cameraSettings(currentTrack).deviceId || requestedDeviceId || null;
            await refreshCameras(generation);
            if (!active || generation !== cameraGeneration || document.hidden) return false;
            autoBtn.hidden = true;
            updateControlsVisibility();
            captureBtn.disabled = false;
            retryBtn.hidden = true;
            status.textContent = "Local QR reader unavailable. Take a picture to offer a server retry.";
            return true;
          }
          stopStream();
          retryBtn.hidden = false;
          reportError((error && error.message) || "Could not initialise the QR decoder.");
        }
        return false;
      }
      if (!active || generation !== cameraGeneration || document.hidden) return false;
      const actualId = cameraSettings(currentTrack).deviceId || requestedDeviceId;
      selectedDeviceId = actualId || null;
      await refreshCameras(generation);
      if (!active || generation !== cameraGeneration) return false;
      const settings = cameraSettings(currentTrack);
      const fixedFocusHint = (settings.facingMode === "user" || !settings.facingMode) &&
        !supportsMode(capabilities, "focusMode", "continuous");
      status.textContent = "Aim at one QR code, then take a picture." +
        (fixedFocusHint ? " Hold the code 20–30 cm from the camera." : "");
      captureBtn.disabled = false;
      retryBtn.hidden = true;
      noCodeSince = Date.now();
      blurSince = null;
      lastGuidanceAt = 0;
      lastGuidanceText = "";
      scheduleLocate(generation);
      return true;
    }

    function beginCamera(requestedDeviceId = selectedDeviceId) {
      if (beginPromise && beginTarget === requestedDeviceId) return beginPromise;
      beginTarget = requestedDeviceId;
      const currentPromise = startCamera(requestedDeviceId);
      beginPromise = currentPromise;
      currentPromise.then(
        () => { if (beginPromise === currentPromise) beginPromise = null; },
        () => { if (beginPromise === currentPromise) beginPromise = null; }
      );
      return currentPromise;
    }

    function suspendCamera(message) {
      if (!active) return;
      cameraGeneration += 1;
      beginPromise = null;
      beginTarget = null;
      scanning = false;
      fallbackBlob = null;
      serverOffer.hidden = true;
      setAutoArmed(false);
      captureBtn.disabled = true;
      hideControls();
      stopStream();
      status.textContent = message;
    }

    function cleanup() {
      if (!active) return;
      active = false;
      fallbackBlob = null;
      cameraGeneration += 1;
      beginPromise = null;
      beginTarget = null;
      clearFocusTimer();
      cancelLocate();
      if (decoder) decoder.close();
      else decoderPromise?.then((pendingDecoder) => pendingDecoder.close()).catch(() => {});
      stopStream();
      document.removeEventListener("keydown", escapeHandler);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("pagehide", onPageHide);
      window.removeEventListener("pageshow", onPageShow);
      window.removeEventListener("resize", refreshFrameSize);
      window.removeEventListener("orientationchange", refreshFrameSize);
      video.removeEventListener("loadedmetadata", refreshFrameSize);
      navigator.mediaDevices?.removeEventListener?.("devicechange", onDeviceChange);
      document.body.classList.remove("qr-camera-open");
      modal.remove();
      if (typeof opts.onClose === "function") opts.onClose();
    }

    function escapeHandler(event) {
      if (event.key === "Escape") cleanup();
    }

    function onVisibilityChange() {
      if (document.hidden) suspendCamera("Camera paused while the page is hidden.");
      else if (active && !stream) beginCamera(selectedDeviceId);
    }

    function onPageHide() {
      suspendCamera("Camera paused while the page is away.");
    }

    function onPageShow() {
      if (active && !document.hidden && !stream) beginCamera(selectedDeviceId);
    }

    function onDeviceChange() {
      if (!active || !track) return;
      if (track.readyState === "ended") {
        track.onended?.();
        return;
      }
      refreshCameras(cameraGeneration);
    }

    document.addEventListener("keydown", escapeHandler);
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("pagehide", onPageHide);
    window.addEventListener("pageshow", onPageShow);
    window.addEventListener("resize", refreshFrameSize);
    window.addEventListener("orientationchange", refreshFrameSize);
    video.addEventListener("loadedmetadata", refreshFrameSize);
    navigator.mediaDevices?.addEventListener?.("devicechange", onDeviceChange);
    closeBtn.addEventListener("click", cleanup);
    modal.addEventListener("click", (event) => {
      if (event.target === modal) cleanup();
    });

    switchBtn.addEventListener("click", async () => {
      if (!active || scanning || cameras.length < 2 || !track) return;
      const oldId = cameraSettings(track).deviceId || selectedDeviceId;
      const index = cameras.findIndex((camera) => camera.deviceId === oldId);
      const next = cameras[(index + 1 + cameras.length) % cameras.length];
      if (!next || next.deviceId === oldId) return;
      if (await beginCamera(next.deviceId) && selectedDeviceId === next.deviceId) rememberDeviceId(next.deviceId);
    });

    zoomBtn.addEventListener("click", async () => {
      if (!active || scanning || !track || zoomBtn.hidden) return;
      const current = track;
      const nextZoom = zoomed ? zoomBase : zoomTarget;
      try {
        await current.applyConstraints({ advanced: [{ zoom: nextZoom }] });
        if (current !== track) return;
        zoomed = !zoomed;
        zoomBtn.textContent = zoomed ? "1× zoom" : `${Number((zoomTarget / zoomBase).toFixed(1))}× zoom`;
        zoomBtn.setAttribute("aria-pressed", String(zoomed));
      } catch (_err) { status.textContent = "Zoom is unavailable on this camera."; }
    });

    torchBtn.addEventListener("click", async () => {
      if (!active || scanning || !track || torchBtn.hidden) return;
      const current = track;
      try {
        await current.applyConstraints({ advanced: [{ torch: !torchOn }] });
        if (current !== track) return;
        torchOn = !torchOn;
        torchBtn.textContent = torchOn ? "Flashlight on" : "Flashlight off";
        torchBtn.setAttribute("aria-pressed", String(torchOn));
      } catch (_err) { status.textContent = "Flashlight is unavailable on this camera."; }
    });

    video.addEventListener("click", async (event) => {
      if (!active || scanning || !track || !supportsMode(capabilities, "focusMode", "single-shot") ||
          !capabilities.pointsOfInterest || typeof track.applyConstraints !== "function") return;
      const current = track;
      const rect = video.getBoundingClientRect();
      const videoWidth = video.videoWidth;
      const videoHeight = video.videoHeight;
      if (!rect.width || !rect.height || !videoWidth || !videoHeight) return;
      // Map the CSS object-fit:cover viewport back to normalized sensor space.
      const scale = Math.max(rect.width / videoWidth, rect.height / videoHeight);
      const cropX = (videoWidth * scale - rect.width) / 2;
      const cropY = (videoHeight * scale - rect.height) / 2;
      let x = (event.clientX - rect.left + cropX) / (videoWidth * scale);
      const y = (event.clientY - rect.top + cropY) / (videoHeight * scale);
      if (video.classList.contains("is-mirrored")) x = 1 - x;
      const point = { x: Math.max(0, Math.min(1, x)), y: Math.max(0, Math.min(1, y)) };
      clearFocusTimer();
      try {
        await current.applyConstraints({ advanced: [{ pointsOfInterest: [point], focusMode: "single-shot" }] });
        if (current !== track) return;
        status.textContent = "Focusing on the spot you tapped…";
        if (supportsMode(capabilities, "focusMode", "continuous")) {
          focusTimer = setTimeout(() => {
            if (active && current === track) {
              current.applyConstraints({ advanced: [{ focusMode: "continuous" }] }).catch(() => {});
            }
          }, 2000);
        }
      } catch (_err) { status.textContent = "Tap to focus is unavailable on this camera."; }
    });

    retryBtn.addEventListener("click", () => { if (active) beginCamera(selectedDeviceId); });
    autoBtn.addEventListener("click", () => {
      if (!active || scanning || !track || autoBtn.hidden) return;
      setAutoArmed(!autoArmed);
      status.textContent = autoArmed
        ? "Auto-capture will scan one steady code. It will never open the destination."
        : "Auto-capture off. Take a picture when ready.";
    });
    beginCamera(selectedDeviceId);

    function waitForVideoFrame() {
      return new Promise((resolve) => {
        let done = false;
        let callbackId = null;
        const finish = () => {
          if (done) return;
          done = true;
          clearTimeout(timeout);
          if (callbackId !== null && typeof video.cancelVideoFrameCallback === "function") {
            video.cancelVideoFrameCallback(callbackId);
          }
          resolve();
        };
        const timeout = setTimeout(finish, 110);
        if (typeof video.requestVideoFrameCallback === "function") callbackId = video.requestVideoFrameCallback(finish);
      });
    }

    async function collectBurst(generation) {
      const frames = [];
      try {
        for (let index = 0; index < 6; index += 1) {
          if (index) {
            await new Promise((resolve) => setTimeout(resolve, 80));
            await waitForVideoFrame();
          }
          if (!active || generation !== cameraGeneration || !track || track.readyState !== "live") break;
          const frame = await captureFrame(video, canvas, ctx, decoder.supportsBitmap);
          const sample = scoreContext ? captureSample(video, scoreCanvas, scoreContext, 320) : null;
          frames.push({ frame, sample, index, sharpness: 0 });
        }
        return frames;
      } catch (error) {
        frames.forEach(({ frame }) => disposeFrame(frame));
        throw error;
      }
    }

    async function jpegFromFrame(frame) {
      if (!fallbackContext || typeof fallbackCanvas.toBlob !== "function") return null;
      const source = frame.bitmap || frame.imageData;
      if (!source) return null;
      const scale = Math.min(1, 1920 / Math.max(source.width, source.height));
      fallbackCanvas.width = Math.max(1, Math.round(source.width * scale));
      fallbackCanvas.height = Math.max(1, Math.round(source.height * scale));
      if (frame.bitmap) fallbackContext.drawImage(frame.bitmap, 0, 0, fallbackCanvas.width, fallbackCanvas.height);
      else {
        // The Safari compatibility path keeps ImageData on the main thread.
        // Draw it once for a possible consented upload; no network request yet.
        const original = document.createElement("canvas");
        original.width = source.width;
        original.height = source.height;
        original.getContext("2d").putImageData(source, 0, 0);
        fallbackContext.drawImage(original, 0, 0, fallbackCanvas.width, fallbackCanvas.height);
      }
      return new Promise((resolve) => fallbackCanvas.toBlob(resolve, "image/jpeg", 0.92));
    }

    serverSendBtn.addEventListener("click", async () => {
      if (!active || !fallbackBlob || typeof opts.onServerFallback !== "function") return;
      serverSendBtn.disabled = true;
      status.textContent = "Sending this photo to SafeScan for another read…";
      try {
        const accepted = await opts.onServerFallback(fallbackBlob);
        if (accepted === false) throw new Error("Upload is unavailable in this browser.");
        cleanup();
      } catch (_error) {
        if (!active) return;
        status.textContent = "Could not send the photo. Use Upload QR file/photo instead.";
        serverSendBtn.disabled = false;
      }
    });

    // Only this function may forward a decoded payload for risk analysis.
    // Locate mode and auto-capture both feed this same bounded burst path.
    async function capture() {
      if (!active || scanning || !track || track.readyState !== "live") return;
      if (video.readyState < 2 /* HAVE_CURRENT_DATA */) {
        status.textContent = "Camera is still warming up — try again in a second.";
        return;
      }
      scanning = true;
      const captureGeneration = cameraGeneration;
      cancelLocate();
      serverOffer.hidden = true;
      fallbackBlob = null;
      captureBtn.disabled = true;
      status.textContent = "Taking several pictures to find the clearest QR…";

      if (!decoder) {
        let frame = null;
        try {
          frame = await captureFrame(video, canvas, ctx, false);
          const blob = await jpegFromFrame(frame);
          if (active && captureGeneration === cameraGeneration) fallbackBlob = blob;
        } catch (_error) { /* The upload button remains available below. */ }
        finally { disposeFrame(frame); }
        if (!active || captureGeneration !== cameraGeneration) return;
        serverOffer.hidden = !fallbackBlob;
        status.textContent = fallbackBlob
          ? "Photo captured. Choose Send photo to SafeScan for a server retry."
          : "Could not capture a photo. Try again or use Upload QR file/photo.";
        captureBtn.disabled = false;
        scanning = false;
        return;
      }

      let frames = [];
      let scanError = false;
      let ambiguous = false;
      let structuredAppend = false;
      let value = null;
      try {
        frames = await collectBurst(captureGeneration);
        if (!frames.length) throw new Error("No camera frames were captured.");
        for (const item of frames) {
          if (!item.sample) continue;
          try {
            const score = await decoder.score(item.sample);
            item.sharpness = score.stats?.sharpness || 0;
          } catch (_error) { scanError = true; }
        }
        frames.sort((first, second) => second.sharpness - first.sharpness);
        if (active && captureGeneration === cameraGeneration && typeof opts.onServerFallback === "function") {
          fallbackBlob = await jpegFromFrame(frames[0].frame);
        }
        status.textContent = "Checking the clearest pictures for QR codes…";
        for (const item of frames) {
          if (!active || captureGeneration !== cameraGeneration) break;
          try {
            const decoded = await decoder.decode(item.frame);
            if (decoded?.ambiguous) {
              ambiguous = true;
              structuredAppend ||= decoded.structuredAppend === true;
              break;
            }
            if (decoded) {
              if (value && decoded !== value) {
                ambiguous = true;
                break;
              }
              value = decoded;
            }
          } catch (_error) { scanError = true; }
          finally { disposeFrame(item.frame); }
        }
        if (!value && !ambiguous && active && captureGeneration === cameraGeneration &&
            decoder.supportsBitmap && typeof ImageCapture === "function" && typeof createImageBitmap === "function") {
          // Chrome Android can expose a sharper full-sensor still after the
          // video burst. This is a local last attempt, never an upload.
          let still = null;
          try {
            still = await createImageBitmap(await new ImageCapture(track).takePhoto());
            const decoded = await decoder.decode({ bitmap: still, transfer: [still] });
            if (decoded?.ambiguous) {
              ambiguous = true;
              structuredAppend ||= decoded.structuredAppend === true;
            } else if (decoded) value = decoded;
          } catch (_error) { /* ImageCapture is optional on supporting browsers. */ }
          finally { disposeFrame({ bitmap: still }); }
        }
      } catch (_error) {
        scanError = true;
      } finally {
        frames.forEach(({ frame }) => disposeFrame(frame));
      }

      if (!active) return;
      if (captureGeneration !== cameraGeneration) {
        scanning = false;
        return;
      }

      if (ambiguous) {
        fallbackBlob = null;
        status.textContent = structuredAppend
          ? "This code is split across multiple QR codes. Scan a complete code instead."
          : "The camera saw two QR codes. Aim at one code and try again.";
        captureBtn.disabled = false;
        scanning = false;
        scheduleLocate(cameraGeneration);
        return;
      }

      if (value && !scanError) {
        status.textContent = "QR detected — analysing…";
        cleanup();
        if (typeof opts.onResult === "function") opts.onResult(value);
        return;
      }

      if (value && scanError) fallbackBlob = null;
      serverOffer.hidden = !(fallbackBlob && !value && typeof opts.onServerFallback === "function");
      status.textContent = value && scanError
        ? "One frame was unclear after a QR was found. Aim at one code and retry."
        : serverOffer.hidden
          ? "No complete QR found. Try again or upload a photo instead."
          : "No QR read locally. You can retry or choose to send the photo to SafeScan.";
      captureBtn.disabled = false;
      scanning = false;
      scheduleLocate(cameraGeneration);
    }

    captureBtn.addEventListener("click", capture);
  }

  window.SafeScanQrCamera = { open: openScanner };
})();
