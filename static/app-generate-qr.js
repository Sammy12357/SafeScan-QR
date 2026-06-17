// app-generate-qr.js — Generate-QR tool: render a SafeScan-verified QR for a typed URL.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
// Generate QR: takes whatever URL is currently typed into the paste-URL
// input and asks the backend to render a SafeScan-verified QR PNG for it.
// The backend runs the URL through the full risk pipeline and refuses to
// render anything flagged as suspicious or dangerous, so the button is a
// "publish a safe QR" tool, not a generic QR maker.
(() => {
  const generateBtn = document.getElementById("generateQrButton");
  const urlInputField = document.getElementById("generateQrUrlInput");
  const wrap = document.getElementById("generatedQrWrap");
  const img = document.getElementById("generatedQrImage");
  const dl = document.getElementById("generatedQrDownload");
  const errEl = document.getElementById("generateQrError");
  if (!generateBtn || !urlInputField || !wrap || !img || !errEl) return;

  const showError = (message) => {
    errEl.textContent = message;
    errEl.classList.remove("hidden");
    wrap.classList.add("hidden");
  };
  const clearError = () => {
    errEl.textContent = "";
    errEl.classList.add("hidden");
  };

  generateBtn.addEventListener("click", async () => {
    clearError();
    const raw = urlInputField.value.trim();
    if (!raw) {
      showError("Paste a URL above first.");
      return;
    }
    let normalized = raw;
    if (!/^https?:\/\//i.test(normalized)) normalized = `https://${normalized}`;
    try {
      new URL(normalized);
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
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
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
