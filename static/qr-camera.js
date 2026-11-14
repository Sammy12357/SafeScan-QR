// SafeScan web camera scanner. QR decoding starts only after "Take picture".
// The native detector is a fast first pass; the self-hosted ZXing worker checks
// the full-resolution frame and protects the multi-code refusal on every browser.
(function () {
  const WORKER_URL = "/static/qr-worker.js?v=scanner-phase-2b";
  const WORKER_START_TIMEOUT_MS = 8000;
  const DECODE_TIMEOUT_MS = 6000;
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
        '<div class="qr-camera-controls" aria-label="Camera controls" hidden>' +
          '<button class="qr-camera-switch" type="button" hidden>Switch camera</button>' +
          '<button class="qr-camera-zoom" type="button" hidden>2× zoom</button>' +
          '<button class="qr-camera-torch" type="button" aria-pressed="false" hidden>Flashlight off</button>' +
        '</div>' +
        '<div class="qr-camera-actions">' +
          '<button class="qr-camera-capture" type="button" disabled>Take picture</button>' +
          '<button class="qr-camera-retry" type="button" hidden>Retry camera</button>' +
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
    const retryBtn = modal.querySelector(".qr-camera-retry");
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

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

    function updateControlsVisibility() {
      controls.hidden = switchBtn.hidden && zoomBtn.hidden && torchBtn.hidden;
    }

    function hideControls() {
      switchBtn.hidden = true;
      zoomBtn.hidden = true;
      torchBtn.hidden = true;
      updateControlsVisibility();
    }

    function clearFocusTimer() {
      if (focusTimer) clearTimeout(focusTimer);
      focusTimer = null;
    }

    function stopStream() {
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
        if (active && generation === cameraGeneration) {
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
      captureBtn.disabled = true;
      hideControls();
      stopStream();
      status.textContent = message;
    }

    function cleanup() {
      if (!active) return;
      active = false;
      cameraGeneration += 1;
      beginPromise = null;
      beginTarget = null;
      clearFocusTimer();
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
    beginCamera(selectedDeviceId);

    // Capture handler: grab the current frame and decode it once. Nothing
    // happens until the user clicks, so this is a deliberate "take a photo of
    // the QR code" action rather than continuous auto-scanning.
    async function capture() {
      if (!active || scanning || !decoder || !track || track.readyState !== "live") return;
      if (video.readyState < 2 /* HAVE_CURRENT_DATA */) {
        status.textContent = "Camera is still warming up — try again in a second.";
        return;
      }
      scanning = true;
      const captureGeneration = cameraGeneration;
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
      if (captureGeneration !== cameraGeneration) {
        scanning = false;
        return;
      }

      if (value && value.ambiguous) {
        status.textContent = "Multiple QR codes found. Aim at one code or crop the picture, then try again.";
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
