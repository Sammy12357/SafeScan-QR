// Start the hero model when visible, with a visible recovery control.
const showcase = document.querySelector(".spline-showcase");
const activation = document.getElementById("modelActivation");
const canvas = document.getElementById("safeScanModel");

if (showcase && activation && canvas && !showcase.dataset.splineSrc?.trim()) {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let loading = false;
  let ready = false;
  let attempts = 0;
  let reloadOnRetry = false;
  let observer;

  function showAction(label) {
    activation.hidden = false;
    activation.textContent = label;
    activation.classList.add("model-activation-action");
    activation.removeAttribute("aria-label");
  }

  function showRetry() {
    showAction("Retry 3D model");
  }

  if (reducedMotion.matches) {
    showAction("Play 3D model");
  }

  async function startModel() {
    if (loading || ready) return;
    if (reloadOnRetry) {
      window.location.reload();
      return;
    }
    loading = true;
    observer?.disconnect();
    activation.setAttribute("aria-disabled", "true");
    activation.setAttribute("aria-busy", "true");
    activation.setAttribute("aria-label", "Loading 3D model");
    if (attempts || reducedMotion.matches) activation.textContent = "Loading 3D model";

    try {
      const retry = attempts++ ? `&retry=${attempts}` : "";
      await import(`/static/safescan-3d.js?v=phone-model-recovery-v1${retry}`);
      if (!showcase.classList.contains("webgl-ready")) {
        throw new Error("3D model unavailable");
      }
      canvas.tabIndex = 0;
      canvas.setAttribute("aria-label", "Interactive Sqafe 3D security model. Use arrow keys to rotate it.");
      const transferFocus = document.activeElement === activation;
      activation.hidden = true;
      if (transferFocus) canvas.focus({ preventScroll: true });
      ready = true;
    } catch (_error) {
      showcase.classList.add("webgl-fallback");
      showRetry();
    } finally {
      loading = false;
      activation.removeAttribute("aria-disabled");
      activation.removeAttribute("aria-busy");
    }
  }

  activation.addEventListener("click", startModel);
  showcase.addEventListener("sqafe:model-fallback", (event) => {
    reloadOnRetry = true;
    if (!ready) return;
    ready = false;
    canvas.tabIndex = -1;
    const transferFocus = event.detail?.hadCanvasFocus || document.activeElement === canvas;
    showRetry();
    if (transferFocus) activation.focus({ preventScroll: true });
  });

  if (!reducedMotion.matches) {
    if ("IntersectionObserver" in window) {
      observer = new IntersectionObserver((entries) => {
        if (entries.some((entry) => entry.isIntersecting)) startModel();
      }, { threshold: 0.5 });
      observer.observe(showcase);
    } else {
      startModel();
    }
  }
}
