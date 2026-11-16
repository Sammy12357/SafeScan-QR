// Load the optional model when it enters view, after the scanner can render.
const showcase = document.querySelector(".spline-showcase");
const activation = document.getElementById("modelActivation");
const canvas = document.getElementById("safeScanModel");

if (showcase && activation && canvas && !showcase.dataset.splineSrc?.trim()) {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let loading = false;
  let ready = false;
  let attempts = 0;
  let observer;

  if (reducedMotion.matches) {
    activation.hidden = true;
  } else {
    async function startModel() {
      if (loading || ready) return;
      loading = true;
      observer?.disconnect();
      activation.setAttribute("aria-disabled", "true");
      activation.setAttribute("aria-busy", "true");
      activation.setAttribute("aria-label", "Loading interactive Sqafe 3D model");
      if (attempts) activation.textContent = "Loading 3D model";

      try {
        const retry = attempts++ ? `&retry=${attempts}` : "";
        await import(`/static/safescan-3d.js?v=phone-model-autostart-v1${retry}`);
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
        activation.textContent = "Retry 3D model";
        activation.classList.add("model-activation-retry");
        activation.setAttribute("aria-label", "Retry interactive Sqafe 3D model");
      } finally {
        loading = false;
        activation.removeAttribute("aria-disabled");
        activation.removeAttribute("aria-busy");
      }
    }

    activation.addEventListener("click", startModel);
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
