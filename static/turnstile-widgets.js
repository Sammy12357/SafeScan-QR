// One explicitly rendered widget per action. Form widgets use Turnstile's
// automatic cf-turnstile-response input; fetch-based reports read by action.
(() => {
  const widgets = new Map();
  const renderWidgets = () => {
    if (!window.turnstile) return;
    document.querySelectorAll(".safescan-turnstile-widget").forEach((container) => {
      const action = container.dataset.action || "";
      const sitekey = container.dataset.sitekey || "";
      if (!action || !sitekey || widgets.has(action)) return;
      const widgetId = window.turnstile.render(container, {
        sitekey,
        action,
        theme: "auto",
        size: "compact",
        appearance: "interaction-only"
      });
      widgets.set(action, widgetId);
    });
  };
  window.safeScanTurnstile = {
    token(action) {
      const id = widgets.get(action);
      return id !== undefined ? window.turnstile.getResponse(id) || "" : "";
    },
    reset(action) {
      const id = widgets.get(action);
      if (id !== undefined) window.turnstile.reset(id);
    }
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderWidgets, { once: true });
  } else {
    renderWidgets();
  }
})();
