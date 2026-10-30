// app-generate-qr.js — Generate a QR only after the server reports a low-risk URL verdict.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
// The image identifies the service that generated it, not a permanent safety
// certification. The server must enforce the verdict; this UI also checks the
// response before making a generated image available for download.
(() => {
  const generateBtn = document.getElementById("generateQrButton");
  const urlInputField = document.getElementById("generateQrUrlInput");
  const wrap = document.getElementById("generatedQrWrap");
  const img = document.getElementById("generatedQrImage");
  const dl = document.getElementById("generatedQrDownload");
  const errEl = document.getElementById("generateQrError");
  if (!generateBtn || !urlInputField || !wrap || !img || !errEl) return;
  let currentObjectUrl = null;

  const clearImage = () => {
    wrap.classList.add("hidden");
    img.removeAttribute("src");
    if (dl) dl.removeAttribute("href");
    if (currentObjectUrl) URL.revokeObjectURL(currentObjectUrl);
    currentObjectUrl = null;
  };

  const showError = (message) => {
    errEl.textContent = message;
    errEl.classList.remove("hidden");
    clearImage();
  };
  const clearError = () => {
    errEl.textContent = "";
    errEl.classList.add("hidden");
  };

  generateBtn.addEventListener("click", async () => {
    clearError();
    clearImage();
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

    generateBtn.disabled = true;
    generateBtn.textContent = "Generating...";
    try {
      const res = await fetch("/api/qr/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized })
      });
      if (!res.ok) {
        let detail = "Could not generate QR.";
        try {
          const body = await res.json();
          detail = body.detail || body.error || detail;
        } catch (_err) {
          /* non-JSON 4xx body */
        }
        showError(detail);
        return;
      }
      if (res.headers.get("X-SafeScan-Verdict")?.toLowerCase() !== "safe" || !res.headers.get("Content-Type")?.toLowerCase().startsWith("image/png")) {
        showError("SafeScan could not confirm a low-risk result for this URL. No QR was made available.");
        return;
      }
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      currentObjectUrl = objectUrl;
      img.src = objectUrl;
      dl.href = objectUrl;
      wrap.classList.remove("hidden");
    } catch (err) {
      showError("Network error while generating QR.");
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = "Generate QR";
    }
  });
})();
