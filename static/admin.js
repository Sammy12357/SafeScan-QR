// Admin activity feed enhancer.
// On the admin "activity" page, resolves the short actor labels shown in the
// audit feed into full email addresses (looked up via the admin API and cached
// in sessionStorage to avoid repeat requests).
const themeToggle = document.querySelector("[data-theme-toggle]");
if (themeToggle) {
  const themeText = themeToggle.querySelector("[data-theme-toggle-text]");
  const setTheme = (theme) => {
    const isLight = theme === "light";
    document.documentElement.setAttribute("data-theme", isLight ? "light" : "dark");
    themeToggle.setAttribute("aria-pressed", String(isLight));
    themeToggle.setAttribute("aria-label", isLight ? "Switch to dark mode" : "Switch to light mode");
    if (themeText) themeText.textContent = isLight ? "Light" : "Dark";
    try { window.localStorage.setItem("safescan_theme", isLight ? "light" : "dark"); } catch { /* Storage can be disabled. */ }
  };

  setTheme(document.documentElement.getAttribute("data-theme"));
  themeToggle.addEventListener("click", () => {
    setTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
  });
}

const feed = document.querySelector(".activity-feed");
if (feed) {
  let actorLookupWarningShown = false;
  const showActorLookupWarning = () => {
    if (actorLookupWarningShown || !window.UIStates) return;
    actorLookupWarningShown = true;
    const host = document.createElement("div");
    feed.prepend(host);
    UIStates.notice(host, { type: "warning", message: "Some actor names couldn't be expanded. Refresh later to retry." });
  };
  const resolveActorEmail = async (actorLabel) => {
    const rawActor = actorLabel.textContent.trim();
    if (!rawActor || rawActor === "system" || rawActor.includes("@")) return;

    const cacheKey = `safescan:actor-email:${rawActor}`;
    let cachedEmail = null;
    try { cachedEmail = window.sessionStorage.getItem(cacheKey); } catch { /* Storage is optional. */ }
    if (cachedEmail) {
      actorLabel.textContent = cachedEmail;
      return;
    }

    try {
      const response = await fetch(`/admin/users?search=${encodeURIComponent(rawActor)}`, {
        credentials: "same-origin",
      });
      if (!response.ok) throw new Error("Actor lookup unavailable");

      const html = await response.text();
      const doc = new DOMParser().parseFromString(html, "text/html");
      const email = doc.querySelector(".admin-table tbody tr td:nth-child(2)")?.textContent?.trim();
      if (email && email.includes("@")) {
        try { window.sessionStorage.setItem(cacheKey, email); } catch { /* Storage is optional. */ }
        actorLabel.textContent = email;
      }
    } catch {
      showActorLookupWarning();
    }
  };

  feed.querySelectorAll(".activity b").forEach((actorLabel) => {
    resolveActorEmail(actorLabel);
  });

  window.setInterval(() => {
    if (!document.hidden) window.location.reload();
  }, 30000);
}

document.querySelectorAll("form").forEach((form) => {
  form.addEventListener("submit", (event) => {
    const explicitConfirm = event.submitter?.matches("button[data-confirm]") ? event.submitter : null;
    if (explicitConfirm && !window.confirm(explicitConfirm.dataset.confirm || "Confirm this admin action?")) {
      event.preventDefault();
      return;
    }
    const dangerous = event.submitter?.matches("button[name='status'][value='disqualified'], button[name='outcome'][value='disqualified']");
    if (dangerous && !window.confirm("Confirm this admin action?")) {
      event.preventDefault();
    }
  });
});
