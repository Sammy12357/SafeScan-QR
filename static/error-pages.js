(() => {
  const button = document.querySelector("[data-retry-button]");
  if (!button) return;

  const countdown = document.querySelector("[data-retry-countdown]");
  if (countdown) {
    let remaining = Number.parseInt(countdown.textContent || "", 10);
    if (!Number.isFinite(remaining) || remaining < 1) remaining = 1;
    const timer = window.setInterval(() => {
      remaining -= 1;
      countdown.textContent = String(Math.max(remaining, 0));
      if (remaining <= 0) {
        window.clearInterval(timer);
        button.disabled = false;
      }
    }, 1000);
  }

  button.addEventListener("click", () => {
    if (document.body.dataset.errorMethod === "POST") {
      if (window.history.length > 1) window.history.back();
      else window.location.assign("/");
      return;
    }
    window.location.reload();
  });
})();
