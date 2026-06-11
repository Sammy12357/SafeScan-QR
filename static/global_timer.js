// Live "uptime" counters. Finds every [data-runtime-timer] element and ticks
// it once a second, formatting elapsed seconds as a human-readable
// d/h/m/s string.
const runtimeNodes = Array.from(document.querySelectorAll("[data-runtime-timer]"));

function formatRuntime(totalSeconds) {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  const segments = [];
  if (days) segments.push(`${days}d`);
  segments.push(`${hours}h`, `${minutes}m`, `${secs}s`);
  return segments.join(" ");
}

function renderRuntime(seconds) {
  runtimeNodes.forEach((node) => {
    node.textContent = `Runtime: ${formatRuntime(seconds)}`;
  });
}

async function startRuntimeTimer() {
  if (!runtimeNodes.length) return;
  try {
    const response = await fetch("/api/app-runtime", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Runtime unavailable");
    const data = await response.json();
    const startedAt = new Date(data.startedAt).getTime();
    const serverNow = new Date(data.serverNow).getTime();
    const skew = Number.isFinite(serverNow) ? serverNow - Date.now() : 0;
    const fallback = Number(data.uptimeSeconds || 0);
    const tick = () => {
      const runtime = Number.isFinite(startedAt)
        ? Math.floor((Date.now() + skew - startedAt) / 1000)
        : fallback;
      renderRuntime(runtime);
    };
    tick();
    window.setInterval(tick, 1000);
  } catch {
    renderRuntime(0);
  }
}

startRuntimeTimer();
