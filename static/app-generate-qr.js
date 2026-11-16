// Screened QR codes require a complete safety check. Plain QR codes are an
// explicit unchecked choice with no SafeScan mark. The text preview swaps
// whole, independently scannable frames; exported text stays fixed.
(() => {
  const generateBtn = document.getElementById("generateQrButton");
  const urlInputField = document.getElementById("generateQrUrlInput");
  const modeInputs = [...document.querySelectorAll('input[name="generateQrMode"]')];
  const plainWarning = document.getElementById("generateQrPlainWarning");
  const formatInputs = [...document.querySelectorAll('input[name="generateQrFormat"]')];
  const artStyles = document.getElementById("generateQrArtStyles");
  const artStyleInputs = [...document.querySelectorAll('input[name="generateQrArtStyle"]')];
  const wrap = document.getElementById("generatedQrWrap");
  const img = document.getElementById("generatedQrImage");
  const pngStatus = document.getElementById("generatedQrStatus");
  const dl = document.getElementById("generatedQrDownload");
  const textWrap = document.getElementById("generatedAsciiWrap");
  const paper = document.querySelector(".generated-ascii-paper");
  const art = document.getElementById("generatedAsciiArt");
  const asciiStatus = document.getElementById("generatedAsciiStatus");
  const sizeNotice = document.getElementById("generatedAsciiSizeNotice");
  const destination = document.getElementById("generatedAsciiDestination");
  const motionToggle = document.getElementById("generatedAsciiMotionToggle");
  const copyButton = document.getElementById("generatedAsciiCopy");
  const textDownload = document.getElementById("generatedAsciiDownload");
  const actionStatus = document.getElementById("generatedAsciiActionStatus");
  const errEl = document.getElementById("generateQrError");
  if (!generateBtn || !urlInputField || modeInputs.length !== 2 || !plainWarning || formatInputs.length !== 3 || !artStyles || artStyleInputs.length !== 2 || !wrap || !img || !pngStatus || !dl || !textWrap || !paper || !art || !asciiStatus || !sizeNotice || !destination || !motionToggle || !copyButton || !textDownload || !actionStatus || !errEl) return;

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
    wrap.removeAttribute("data-verification");
    wrap.removeAttribute("data-output-format");
    textWrap.removeAttribute("data-verification");
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
  const plainModeSelected = () => modeInputs.find((radio) => radio.checked)?.value === "plain";
  const selectedOutputFormat = () => formatInputs.find((radio) => radio.checked)?.value || "png";
  const updateFormatPresentation = () => {
    artStyles.classList.toggle("hidden", selectedOutputFormat() !== "ascii_art");
  };
  const updateModePresentation = () => {
    const plain = plainModeSelected();
    plainWarning.classList.toggle("hidden", !plain);
    if (plain) generateBtn.setAttribute("aria-describedby", "generateQrPlainWarning");
    else generateBtn.removeAttribute("aria-describedby");
    if (!generateBtn.disabled) generateBtn.textContent = plain ? "Generate plain QR" : "Generate screened QR";
  };

  urlInputField.addEventListener("input", cancelCurrent);
  for (const radio of modeInputs) radio.addEventListener("change", () => {
    cancelCurrent();
    updateModePresentation();
  });
  for (const radio of formatInputs) radio.addEventListener("change", () => {
    cancelCurrent();
    updateFormatPresentation();
  });
  for (const radio of artStyleInputs) radio.addEventListener("change", cancelCurrent);
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

    const plain = plainModeSelected();
    const outputFormat = selectedOutputFormat();
    const artStyle = artStyleInputs.find((radio) => radio.checked)?.value || "cat";
    const version = requestVersion;
    const controller = new AbortController();
    activeController = controller;
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    UIStates.busy(generateBtn, async () => {
      try {
        const payload = outputFormat === "ascii"
          ? { url: normalized, format: "ascii", animation: true }
          : outputFormat === "ascii_art"
            ? { url: normalized, format: "ascii_art", art_style: artStyle }
            : { url: normalized };
        const res = await fetch(plain ? "/api/qr/generate-plain" : "/api/qr/generate", {
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
            if (!plain && body.code === "scan_incomplete") {
              detail = "Screened checks could not finish. No screened QR was made. Choose Plain QR above only if you want a code without safety checks.";
            }
          } catch (_err) {
            /* non-JSON error body */
          }
          if (version !== requestVersion) return;
          showError(detail);
          return;
        }
        const verification = res.headers.get("X-SafeScan-Verification")?.toLowerCase();
        const screenedResponse = res.headers.get("X-SafeScan-Verdict")?.toLowerCase() === "safe"
          && verification === "complete";
        const plainResponse = res.headers.get("X-SafeScan-Mode")?.toLowerCase() === "plain"
          && verification === "not_checked"
          && res.headers.get("X-SafeScan-Verdict") === null;
        const contentType = res.headers.get("Content-Type")?.toLowerCase() || "";
        if (!(plain ? plainResponse : screenedResponse) || (outputFormat !== "ascii" && !contentType.startsWith("image/png"))
          || (outputFormat === "ascii" && !contentType.startsWith("application/json"))) {
          showError(plain
            ? "The plain QR response was not marked as unchecked. No QR was made available."
            : "SafeScan could not confirm a low-risk result for this URL. No QR was made available.");
          return;
        }
        if (outputFormat !== "ascii") {
          const blob = await res.blob();
          if (version !== requestVersion) return;
          currentImageUrl = URL.createObjectURL(blob);
          img.src = currentImageUrl;
          const artName = artStyle === "flame" ? "flame" : "cat";
          img.alt = outputFormat === "ascii_art"
            ? `${plain ? "Plain" : "Screened"} ASCII art QR code with a ${artName} drawing`
            : plain ? "Plain QR code for a link that was not safety checked" : "Screened QR code";
          pngStatus.textContent = outputFormat === "ascii_art"
            ? plain
              ? "Not safety checked. Verify the destination independently before sharing or opening this QR. Download the full-size image for sharing."
              : "Checked when generated. Download the full-size image for sharing; the destination may change later."
            : plain
              ? "Not safety checked. Verify the destination independently before sharing or opening this QR."
              : "Checked when generated. The destination may change, so recheck before opening.";
          dl.download = outputFormat === "ascii_art"
            ? (plain ? "plain-ascii-art-qr.png" : "sqafe-ascii-art-qr.png")
            : (plain ? "plain-qr.png" : "safescan-qr.png");
          dl.href = currentImageUrl;
          wrap.setAttribute("data-verification", plain ? "not_checked" : "complete");
          wrap.setAttribute("data-output-format", outputFormat);
          wrap.classList.remove("hidden");
          return;
        }
        const body = await res.json();
        if (version !== requestVersion) return;
        if (typeof body?.text !== "string" || !body.text || !Array.isArray(body.frames)
          || body.frames.length < 1 || body.frames.length > 8
          || body.frames[0] !== body.text || body.frames.some((frame) => typeof frame !== "string" || !frame)
          || (plain && body.frames.some((frame) => frame.includes("Generated by Sqafe")))) {
          showError("The text QR response was incomplete. No QR was made available.");
          return;
        }
        currentText = body.text;
        frames = body.frames;
        frameIndex = 0;
        art.textContent = currentText;
        destination.textContent = normalized;
        asciiStatus.textContent = plain
          ? "Not safety checked. Verify the destination independently before sharing or opening this QR. Pause the motion if a camera has trouble scanning, and keep spacing and a fixed-width font when sharing the text."
          : "Checked when generated. Pause the motion if your camera has trouble scanning. Keep spacing and a fixed-width font when sharing the text; the destination can change later.";
        currentTextUrl = URL.createObjectURL(new Blob([currentText], { type: "text/plain;charset=utf-8" }));
        textDownload.download = plain ? "plain-qr.txt" : "sqafe-text-qr.txt";
        textDownload.href = currentTextUrl;
        textWrap.setAttribute("data-verification", plain ? "not_checked" : "complete");
        textWrap.classList.remove("hidden");
        fitTextPreview();
        motionPaused = Boolean(reducedMotion?.matches);
        updateMotionButton();
        startAnimation();
      } catch (err) {
        if (version !== requestVersion) return;
        showError(err?.name === "AbortError"
          ? (plain ? "QR generation is taking longer than expected. No QR was made available. Try again." : "The check is taking longer than expected. No QR was made available. Try again.")
          : navigator.onLine === false
            ? "You're offline. Reconnect and try again."
            : "We couldn't connect. Check your connection and try again.");
      } finally {
        window.clearTimeout(timeout);
        if (activeController === controller) activeController = null;
      }
    }, { label: plain ? "Generating QR…" : "Checking URL…" }).finally(updateModePresentation);
  });
  updateModePresentation();
  updateFormatPresentation();
  updateMotionButton();
})();
