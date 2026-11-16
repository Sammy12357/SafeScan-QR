// Keep the static hero visible until someone wants to use the 3D model.
const showcase = document.querySelector(".spline-showcase");
const activation = document.getElementById("modelActivation");
const canvas = document.getElementById("safeScanModel");

if (showcase && activation && canvas && !showcase.dataset.splineSrc?.trim()) {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let started = false;

  if (reducedMotion.matches) {
    activation.hidden = true;
  } else {
    async function startModel() {
      if (started) return;
      started = true;
      const keyboardActivation = document.activeElement === activation;

      try {
        await import("/static/safescan-3d.js?v=seo-performance-v1");
        if (!showcase.classList.contains("webgl-ready")) {
          throw new Error("3D model unavailable");
        }
        canvas.tabIndex = 0;
        canvas.setAttribute("aria-label", "Interactive SafeScan QR 3D security model. Use arrow keys to rotate it.");
        activation.hidden = true;
        if (keyboardActivation) canvas.focus({ preventScroll: true });
      } catch (_error) {
        showcase.classList.add("webgl-fallback");
        activation.setAttribute("aria-label", "Interactive 3D model unavailable; still image shown");
        activation.setAttribute("aria-disabled", "true");
      }
    }

    showcase.addEventListener("pointerenter", startModel, { once: true });
    activation.addEventListener("click", startModel);
  }
}
