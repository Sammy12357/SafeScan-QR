// Screened QR codes require a complete safety check. Plain QR codes are an
// explicit unchecked choice with no SafeScan mark. The text preview swaps
// whole matrices; ASCII motion previews a verified APNG and copies a still text QR.
(() => {
  const generateBtn = document.getElementById("generateQrButton");
  const urlInputField = document.getElementById("generateQrUrlInput");
  const modeInputs = [...document.querySelectorAll('input[name="generateQrMode"]')];
  const plainWarning = document.getElementById("generateQrPlainWarning");
  const formatInputs = [...document.querySelectorAll('input[name="generateQrFormat"]')];
  const gradientOptions = document.getElementById("generateQrGradientOptions");
  const gradientStart = document.getElementById("generateQrGradientStart");
  const gradientEnd = document.getElementById("generateQrGradientEnd");
  const gradientStartValue = document.getElementById("generateQrGradientStartValue");
  const gradientEndValue = document.getElementById("generateQrGradientEndValue");
  const gradientSample = document.getElementById("generateQrGradientSample");
  const gradientPresets = [...document.querySelectorAll("[data-gradient-preset]")];
  const wrap = document.getElementById("generatedQrWrap");
  const img = document.getElementById("generatedQrImage");
  const pngStatus = document.getElementById("generatedQrStatus");
  const dl = document.getElementById("generatedQrDownload");
  const motionHeading = document.getElementById("generatedMotionHeading");
  const imageMotionToggle = document.getElementById("generatedMotionToggle");
  const motionDownloads = document.getElementById("generatedMotionDownloads");
  const motionStillDownload = document.getElementById("generatedMotionStillDownload");
  const motionAnimatedDownload = document.getElementById("generatedMotionAnimatedDownload");
  const motionTextWrap = document.getElementById("generatedMotionTextWrap");
  const motionTextCopy = document.getElementById("generatedMotionTextCopy");
  const motionTextDownload = document.getElementById("generatedMotionTextDownload");
  const motionTextActionStatus = document.getElementById("generatedMotionTextActionStatus");
  const textWrap = document.getElementById("generatedAsciiWrap");
  const paper = textWrap?.querySelector(".generated-ascii-paper");
  const art = document.getElementById("generatedAsciiArt");
  const asciiStatus = document.getElementById("generatedAsciiStatus");
  const sizeNotice = document.getElementById("generatedAsciiSizeNotice");
  const destination = document.getElementById("generatedAsciiDestination");
  const textMotionToggle = document.getElementById("generatedAsciiMotionToggle");
  const copyButton = document.getElementById("generatedAsciiCopy");
  const textDownload = document.getElementById("generatedAsciiDownload");
  const actionStatus = document.getElementById("generatedAsciiActionStatus");
  const errEl = document.getElementById("generateQrError");
  if (!generateBtn || !urlInputField || modeInputs.length !== 2 || !plainWarning || formatInputs.length !== 3 || !gradientOptions || !gradientStart || !gradientEnd || !gradientStartValue || !gradientEndValue || !gradientSample || gradientPresets.length !== 3 || !wrap || !img || !pngStatus || !dl || !motionHeading || !imageMotionToggle || !motionDownloads || !motionStillDownload || !motionAnimatedDownload || !motionTextWrap || !motionTextCopy || !motionTextDownload || !motionTextActionStatus || !textWrap || !paper || !art || !asciiStatus || !sizeNotice || !destination || !textMotionToggle || !copyButton || !textDownload || !actionStatus || !errEl) return;

  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)");
  let currentImageUrl = null;
  let currentAnimatedImageUrl = null;
  let currentTextUrl = null;
  let currentText = "";
  let imageMotionPaused = true;
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
  const updateImageMotionButton = () => {
    imageMotionToggle.textContent = imageMotionPaused ? "Resume motion" : "Pause motion";
    imageMotionToggle.setAttribute("aria-pressed", String(!imageMotionPaused));
  };
  const updateImageMotion = () => {
    const source = !imageMotionPaused && !document.hidden ? currentAnimatedImageUrl : currentImageUrl;
    if (source && img.getAttribute("src") !== source) img.src = source;
  };
  const colorContrastOnWhite = (color) => {
    if (!/^#[0-9a-f]{6}$/i.test(color)) return 0;
    const channels = [1, 3, 5].map((offset) => {
      const value = parseInt(color.slice(offset, offset + 2), 16) / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    });
    return 1.05 / (0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2] + 0.05);
  };
  const updateGradientPresentation = () => {
    const top = gradientStart.value.toUpperCase();
    const bottom = gradientEnd.value.toUpperCase();
    gradientStartValue.textContent = top;
    gradientEndValue.textContent = bottom;
    gradientSample.style.setProperty("--gradient-start", top);
    gradientSample.style.setProperty("--gradient-end", bottom);
    for (const preset of gradientPresets) {
      preset.setAttribute("aria-pressed", String(preset.dataset.gradientStart === top && preset.dataset.gradientEnd === bottom));
    }
  };
  const decodePngBase64 = (value) => {
    if (typeof value !== "string" || value.length < 16 || value.length > 20000000) return null;
    try {
      const binary = window.atob(value);
      const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      const signature = [137, 80, 78, 71, 13, 10, 26, 10];
      return signature.every((byte, index) => bytes[index] === byte) ? bytes : null;
    } catch (_err) {
      return null;
    }
  };
  const updateMotionButton = () => {
    textMotionToggle.textContent = motionPaused ? "Play motion" : "Pause motion";
    textMotionToggle.setAttribute("aria-pressed", String(!motionPaused));
    textMotionToggle.disabled = frames.length < 2;
  };
  const startAnimation = () => {
    stopAnimation();
    if (motionPaused || frames.length < 2 || document.hidden) return;
    animationTimer = window.setInterval(() => {
      frameIndex = (frameIndex + 1) % frames.length;
      art.textContent = frames[frameIndex];
    }, 3000);
  };
  const fitOneTextPreview = (surface, preview, notice) => {
    if (!preview.textContent) return;
    preview.style.removeProperty("font-size");
    const style = window.getComputedStyle(surface);
    const available = surface.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    if (preview.scrollWidth > available) {
      const baseSize = parseFloat(window.getComputedStyle(preview).fontSize);
      preview.style.fontSize = `${Math.max(10, baseSize * available / preview.scrollWidth * 0.96)}px`;
    }
    notice.classList.toggle("hidden", preview.scrollWidth <= available + 1);
  };
  const fitTextPreview = () => {
    if (!textWrap.classList.contains("hidden")) fitOneTextPreview(paper, art, sizeNotice);
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
    dl.classList.remove("hidden");
    motionHeading.classList.add("hidden");
    motionDownloads.classList.add("hidden");
    motionTextWrap.classList.add("hidden");
    motionStillDownload.removeAttribute("href");
    motionAnimatedDownload.removeAttribute("href");
    motionTextDownload.removeAttribute("href");
    textDownload.removeAttribute("href");
    motionTextActionStatus.textContent = "";
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
    imageMotionPaused = true;
    updateImageMotionButton();
    if (currentImageUrl) URL.revokeObjectURL(currentImageUrl);
    if (currentAnimatedImageUrl) URL.revokeObjectURL(currentAnimatedImageUrl);
    if (currentTextUrl) URL.revokeObjectURL(currentTextUrl);
    currentImageUrl = null;
    currentAnimatedImageUrl = null;
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
    gradientOptions.classList.toggle("hidden", selectedOutputFormat() !== "ascii_motion");
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
  for (const preset of gradientPresets) preset.addEventListener("click", () => {
    if (gradientStart.value.toUpperCase() === preset.dataset.gradientStart
      && gradientEnd.value.toUpperCase() === preset.dataset.gradientEnd) return;
    gradientStart.value = preset.dataset.gradientStart;
    gradientEnd.value = preset.dataset.gradientEnd;
    cancelCurrent();
    updateGradientPresentation();
  });
  for (const input of [gradientStart, gradientEnd]) input.addEventListener("input", () => {
    cancelCurrent();
    updateGradientPresentation();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopAnimation();
    else startAnimation();
    updateImageMotion();
  });
  window.addEventListener("resize", fitTextPreview);
  reducedMotion?.addEventListener?.("change", (event) => {
    if (event.matches && frames.length) {
      motionPaused = true;
      frameIndex = 0;
      art.textContent = frames[0];
      updateMotionButton();
      stopAnimation();
    }
    if (currentAnimatedImageUrl) {
      imageMotionPaused = event.matches;
      updateImageMotionButton();
      updateImageMotion();
    }
  });
  imageMotionToggle.addEventListener("click", () => {
    if (!currentAnimatedImageUrl) return;
    imageMotionPaused = !imageMotionPaused;
    updateImageMotionButton();
    updateImageMotion();
  });
  textMotionToggle.addEventListener("click", () => {
    if (frames.length < 2) return;
    motionPaused = !motionPaused;
    if (motionPaused) {
      frameIndex = 0;
      art.textContent = frames[0];
    }
    updateMotionButton();
    startAnimation();
  });
  const copyCurrentText = async (status) => {
    if (!currentText) return;
    try {
      await navigator.clipboard.writeText(currentText);
      status.textContent = "Text QR copied. Keep its spacing and use a fixed-width font.";
    } catch (_err) {
      status.textContent = "Could not copy automatically. Use Download .txt instead.";
    }
  };
  copyButton.addEventListener("click", () => copyCurrentText(actionStatus));
  const richAsciiFrame = (frame) => {
    const preview = document.createElement("pre");
    preview.style.cssText = "display:inline-block;width:max-content;max-width:none;overflow:visible;white-space:pre;font-family:Menlo,monospace;font-size:24px;font-weight:700;line-height:12px;letter-spacing:0;font-variant-ligatures:none;margin:0;background:#fff;color:#05080d";
    preview.textContent = frame;
    return preview.outerHTML;
  };
  motionTextCopy.addEventListener("click", async () => {
    // The text export is the stable first ASCII frame of the same QR payload.
    const snapshot = currentText;
    if (!snapshot) return;
    try {
      if (navigator.clipboard.write && window.ClipboardItem) {
        await navigator.clipboard.write([new ClipboardItem({
          "text/plain": new Blob([snapshot], { type: "text/plain" }),
          "text/html": new Blob([richAsciiFrame(snapshot)], { type: "text/html" }),
        })]);
      } else {
        await navigator.clipboard.writeText(snapshot);
      }
      motionTextActionStatus.textContent = "ASCII text QR copied. Apps that keep formatting preserve its scan-ready spacing.";
    } catch (_err) {
      try {
        await navigator.clipboard.writeText(snapshot);
        motionTextActionStatus.textContent = "ASCII text QR copied. Use bold monospace at 24px with 12px line spacing and no wrapping.";
      } catch (_fallbackError) {
        motionTextActionStatus.textContent = "Could not copy automatically. Use Download .txt instead.";
      }
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
    const topColor = gradientStart.value.toUpperCase();
    const bottomColor = gradientEnd.value.toUpperCase();
    if (outputFormat === "ascii_motion"
      && (colorContrastOnWhite(topColor) < 7 || colorContrastOnWhite(bottomColor) < 7)) {
      showError("Choose two darker gradient colors so the QR can be scanned on white. Try a preset or adjust the colors.");
      return;
    }
    const version = requestVersion;
    const controller = new AbortController();
    activeController = controller;
    const timeout = window.setTimeout(() => controller.abort(), outputFormat === "ascii_motion" ? 30000 : 15000);
    UIStates.busy(generateBtn, async () => {
      try {
        const payload = outputFormat === "ascii"
          ? { url: normalized, format: "ascii", animation: true }
          : outputFormat === "ascii_motion"
            ? { url: normalized, format: "ascii_motion", gradient_start: topColor, gradient_end: bottomColor }
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
            if (outputFormat === "ascii_motion" && body.code === "invalid_request"
              && (body.field === "gradient_start" || body.field === "gradient_end")) {
              detail = (body.field === "gradient_start" ? "Top color: " : "Bottom color: ") + (body.error || detail);
            } else if (outputFormat === "ascii_motion" && body.code === "qr_generation_unscannable" && body.hint) {
              detail += " " + body.hint;
            }
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
        if (!(plain ? plainResponse : screenedResponse) || (outputFormat === "png" && !contentType.startsWith("image/png"))
          || (outputFormat !== "png" && !contentType.startsWith("application/json"))) {
          showError(plain
            ? "The plain QR response was not marked as unchecked. No QR was made available."
            : "SafeScan could not confirm a low-risk result for this URL. No QR was made available.");
          return;
        }
        if (outputFormat === "png") {
          const blob = await res.blob();
          if (version !== requestVersion) return;
          currentImageUrl = URL.createObjectURL(blob);
          img.src = currentImageUrl;
          img.alt = plain ? "Plain QR code for a link that was not safety checked" : "Screened QR code";
          pngStatus.textContent = plain
            ? "Not safety checked. Verify the destination independently before sharing or opening this QR."
            : "Checked when generated. The destination may change, so recheck before opening.";
          dl.download = plain ? "plain-qr.png" : "safescan-qr.png";
          dl.href = currentImageUrl;
          wrap.setAttribute("data-verification", plain ? "not_checked" : "complete");
          wrap.setAttribute("data-output-format", outputFormat);
          wrap.classList.remove("hidden");
          return;
        }
        if (outputFormat === "ascii_motion") {
          const body = await res.json();
          if (version !== requestVersion) return;
          const stillBytes = decodePngBase64(body?.still_png_base64);
          const animatedBytes = decodePngBase64(body?.animated_png_base64);
          if (!stillBytes || !animatedBytes
            || !Array.isArray(body?.ascii_frames) || body.ascii_frames.length !== 4
            || body.frame_count !== 4 || body.frame_duration_ms !== 350
            || body.ascii_frames.some((frame) => typeof frame !== "string" || !frame
              || frame.length > 100000 || !/^[\x20-\x7e\n]+$/.test(frame))
            || new Set(body.ascii_frames).size !== 4
            || body.ascii_frames.some((frame) => frame.length !== body.ascii_frames[0].length)
            || (plain && body.ascii_frames.some((frame) => frame.includes("Generated by Sqafe")))) {
            showError("The animated ASCII QR response was incomplete. Try generating it again.");
            return;
          }
          currentImageUrl = URL.createObjectURL(new Blob([stillBytes], { type: "image/png" }));
          currentAnimatedImageUrl = URL.createObjectURL(new Blob([animatedBytes], { type: "image/png" }));
          currentText = body.ascii_frames[0];
          currentTextUrl = URL.createObjectURL(new Blob([currentText], { type: "text/plain;charset=utf-8" }));
          motionTextDownload.download = plain ? "plain-ascii-motion-qr.txt" : "sqafe-ascii-motion-qr.txt";
          motionTextDownload.href = currentTextUrl;
          img.alt = plain
            ? "Plain animated ASCII motion QR for a link that was not safety checked"
            : "Screened animated ASCII motion QR";
          pngStatus.textContent = plain
            ? "Not safety checked. Verify the destination independently before sharing or opening this QR."
            : "Checked when generated. The destination may change, so recheck before opening.";
          motionStillDownload.download = plain ? "plain-ascii-motion-qr.png" : "sqafe-ascii-motion-qr.png";
          motionAnimatedDownload.download = plain ? "plain-ascii-motion-qr-animated.png" : "sqafe-ascii-motion-qr-animated.png";
          motionStillDownload.href = currentImageUrl;
          motionAnimatedDownload.href = currentAnimatedImageUrl;
          dl.classList.add("hidden");
          motionHeading.classList.remove("hidden");
          motionDownloads.classList.remove("hidden");
          motionTextWrap.classList.remove("hidden");
          wrap.setAttribute("data-verification", plain ? "not_checked" : "complete");
          wrap.setAttribute("data-output-format", "ascii_motion");
          imageMotionPaused = Boolean(reducedMotion?.matches);
          updateImageMotionButton();
          updateImageMotion();
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
          ? (outputFormat === "ascii_motion"
            ? "The animated QR is taking longer than expected. Try again."
            : plain ? "QR generation is taking longer than expected. No QR was made available. Try again." : "The check is taking longer than expected. No QR was made available. Try again.")
          : navigator.onLine === false
            ? "You're offline. Reconnect and try again."
            : "We couldn't connect. Check your connection and try again.");
      } finally {
        window.clearTimeout(timeout);
        if (activeController === controller) activeController = null;
      }
    }, { label: outputFormat === "ascii_motion" ? (plain ? "Rendering QR…" : "Checking and rendering QR…") : plain ? "Generating QR…" : "Checking URL…" }).finally(updateModePresentation);
  });
  updateModePresentation();
  updateFormatPresentation();
  updateGradientPresentation();
  updateMotionButton();
  updateImageMotionButton();
})();
