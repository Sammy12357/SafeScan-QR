// Generate a QR only after the server completes its safety checks. The text
// preview swaps whole, independently scannable QR frames; exported text stays
// fixed so it can be printed or copied without changing underneath the user.
(() => {
  const generateBtn = document.getElementById("generateQrButton");
  const urlInputField = document.getElementById("generateQrUrlInput");
  const formatInputs = [...document.querySelectorAll('input[name="generateQrFormat"]')];
  const wrap = document.getElementById("generatedQrWrap");
  const img = document.getElementById("generatedQrImage");
  const dl = document.getElementById("generatedQrDownload");
  const textWrap = document.getElementById("generatedAsciiWrap");
  const paper = document.querySelector(".generated-ascii-paper");
  const art = document.getElementById("generatedAsciiArt");
  const sizeNotice = document.getElementById("generatedAsciiSizeNotice");
  const destination = document.getElementById("generatedAsciiDestination");
  const motionToggle = document.getElementById("generatedAsciiMotionToggle");
  const copyButton = document.getElementById("generatedAsciiCopy");
  const textDownload = document.getElementById("generatedAsciiDownload");
  const actionStatus = document.getElementById("generatedAsciiActionStatus");
  const errEl = document.getElementById("generateQrError");
  if (!generateBtn || !urlInputField || !wrap || !img || !dl || !textWrap || !paper || !art || !sizeNotice || !destination || !motionToggle || !copyButton || !textDownload || !actionStatus || !errEl) return;

  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)");
  let currentImageUrl = null;
  let currentTextUrl = null;
  let currentText = "";
  let frames = [];
  let frameIndex = 0;
  let animationTimer = null;
  let motionPaused = true;
  let activeController = null;
  let requestVersion = 0;

  const stopAnimation = () => {
    if (animationTimer) window.clearInterval(animationTimer);
    animationTimer = null;
  };
  const updateMotionButton = () => {
    motionToggle.textContent = motionPaused ? "Play motion" : "Pause motion";
    motionToggle.setAttribute("aria-pressed", String(!motionPaused));
    motionToggle.disabled = frames.length < 2;
  };
  const startAnimation = () => {
    stopAnimation();
    if (motionPaused || frames.length < 2 || document.hidden) return;
    animationTimer = window.setInterval(() => {
      frameIndex = (frameIndex + 1) % frames.length;
      art.textContent = frames[frameIndex];
    }, 3000);
  };
  const fitTextPreview = () => {
    if (!frames.length) return;
    art.style.removeProperty("font-size");
    const style = window.getComputedStyle(paper);
    const available = paper.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    if (art.scrollWidth > available) {
      const baseSize = parseFloat(window.getComputedStyle(art).fontSize);
      art.style.fontSize = `${Math.max(10, baseSize * available / art.scrollWidth * 0.96)}px`;
    }
    sizeNotice.classList.toggle("hidden", art.scrollWidth <= available + 1);
  };
  const clearResult = () => {
    stopAnimation();
    wrap.classList.add("hidden");
    textWrap.classList.add("hidden");
    img.removeAttribute("src");
    dl.removeAttribute("href");
    textDownload.removeAttribute("href");
    art.textContent = "";
    art.style.removeProperty("font-size");
    sizeNotice.classList.add("hidden");
    destination.textContent = "";
    actionStatus.textContent = "";
    currentText = "";
    frames = [];
    frameIndex = 0;
    motionPaused = true;
    updateMotionButton();
    if (currentImageUrl) URL.revokeObjectURL(currentImageUrl);
    if (currentTextUrl) URL.revokeObjectURL(currentTextUrl);
    currentImageUrl = null;
    currentTextUrl = null;
  };
  const clearError = () => {
    errEl.textContent = "";
    errEl.classList.add("hidden");
  };
  const showError = (message) => {
    errEl.textContent = String(message);
    errEl.classList.remove("hidden");
    clearResult();
  };
  const cancelCurrent = () => {
    requestVersion += 1;
    activeController?.abort();
    activeController = null;
    clearError();
    clearResult();
  };

  urlInputField.addEventListener("input", cancelCurrent);
  for (const radio of formatInputs) radio.addEventListener("change", cancelCurrent);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopAnimation();
    else startAnimation();
  });
  window.addEventListener("resize", fitTextPreview);
  reducedMotion?.addEventListener?.("change", (event) => {
    if (!event.matches || !frames.length) return;
    motionPaused = true;
    frameIndex = 0;
    art.textContent = frames[0];
    updateMotionButton();
    stopAnimation();
  });
  motionToggle.addEventListener("click", () => {
    if (frames.length < 2) return;
    motionPaused = !motionPaused;
    if (motionPaused) {
      frameIndex = 0;
      art.textContent = frames[0];
    }
    updateMotionButton();
    startAnimation();
  });
  copyButton.addEventListener("click", async () => {
    if (!currentText) return;
    try {
      await navigator.clipboard.writeText(currentText);
      actionStatus.textContent = "Text QR copied. Keep its spacing and use a fixed-width font.";
    } catch (_err) {
      actionStatus.textContent = "Could not copy automatically. Use Download .txt instead.";
    }
  });

  generateBtn.addEventListener("click", () => {
    if (generateBtn.disabled) return;
    cancelCurrent();
    const raw = urlInputField.value.trim();
    if (!raw) {
      showError("Paste a URL above first.");
      return;
    }
    let normalized = raw;
    if (!/^[a-z][a-z\d+.-]*:/i.test(normalized)) normalized = `https://${normalized}`;
    try {
      const parsed = new URL(normalized);
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
        showError("Enter a valid http or https URL without embedded credentials.");
        return;
      }
      normalized = parsed.href;
    } catch (_err) {
      showError("That does not look like a valid URL.");
      return;
    }

    const outputFormat = formatInputs.find((radio) => radio.checked)?.value === "ascii" ? "ascii" : "png";
    const version = requestVersion;
    const controller = new AbortController();
    activeController = controller;
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    UIStates.busy(generateBtn, async () => {
      try {
        const payload = outputFormat === "ascii"
          ? { url: normalized, format: "ascii", animation: true }
          : { url: normalized };
        const res = await fetch("/api/qr/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          signal: controller.signal,
          body: JSON.stringify(payload)
        });
        if (version !== requestVersion) return;
        if (!res.ok) {
          let detail = "Could not generate QR.";
          try {
            const body = await res.json();
            detail = body.detail || body.error || detail;
          } catch (_err) {
            /* non-JSON error body */
          }
          if (version !== requestVersion) return;
          showError(detail);
          return;
        }
        const verified = res.headers.get("X-SafeScan-Verdict")?.toLowerCase() === "safe"
          && res.headers.get("X-SafeScan-Verification")?.toLowerCase() === "complete";
        const contentType = res.headers.get("Content-Type")?.toLowerCase() || "";
        if (!verified || (outputFormat === "png" && !contentType.startsWith("image/png"))
          || (outputFormat === "ascii" && !contentType.startsWith("application/json"))) {
          showError("SafeScan could not confirm a low-risk result for this URL. No QR was made available.");
          return;
        }
        if (outputFormat === "png") {
          const blob = await res.blob();
          if (version !== requestVersion) return;
          currentImageUrl = URL.createObjectURL(blob);
          img.src = currentImageUrl;
          dl.href = currentImageUrl;
          wrap.classList.remove("hidden");
          return;
        }
        const body = await res.json();
        if (version !== requestVersion) return;
        if (typeof body?.text !== "string" || !body.text || !Array.isArray(body.frames)
          || body.frames.length < 1 || body.frames.length > 8
          || body.frames[0] !== body.text || body.frames.some((frame) => typeof frame !== "string" || !frame)) {
          showError("The text QR response was incomplete. No QR was made available.");
          return;
        }
        currentText = body.text;
        frames = body.frames;
        frameIndex = 0;
        art.textContent = currentText;
        destination.textContent = normalized;
        currentTextUrl = URL.createObjectURL(new Blob([currentText], { type: "text/plain;charset=utf-8" }));
        textDownload.href = currentTextUrl;
        textWrap.classList.remove("hidden");
        fitTextPreview();
        motionPaused = Boolean(reducedMotion?.matches);
        updateMotionButton();
        startAnimation();
      } catch (err) {
        if (version !== requestVersion) return;
        showError(err?.name === "AbortError"
          ? "The check is taking longer than expected. No QR was made available. Try again."
          : navigator.onLine === false
            ? "You're offline. Reconnect and try again."
            : "We couldn't connect. Check your connection and try again.");
      } finally {
        window.clearTimeout(timeout);
        if (activeController === controller) activeController = null;
      }
    }, { label: "Checking URL…" });
  });
  updateMotionButton();
})();
