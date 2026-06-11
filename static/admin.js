// Admin activity feed enhancer.
// On the admin "activity" page, resolves the short actor labels shown in the
// audit feed into full email addresses (looked up via the admin API and cached
// in sessionStorage to avoid repeat requests).
const feed = document.querySelector(".activity-feed");
if (feed) {
  const resolveActorEmail = async (actorLabel) => {
    const rawActor = actorLabel.textContent.trim();
    if (!rawActor || rawActor === "system" || rawActor.includes("@")) return;

    const cacheKey = `safescan:actor-email:${rawActor}`;
    const cachedEmail = window.sessionStorage.getItem(cacheKey);
    if (cachedEmail) {
      actorLabel.textContent = cachedEmail;
      return;
    }

    try {
      const response = await fetch(`/admin/users?search=${encodeURIComponent(rawActor)}`, {
        credentials: "same-origin",
      });
      if (!response.ok) return;

      const html = await response.text();
      const doc = new DOMParser().parseFromString(html, "text/html");
      const email = doc.querySelector(".admin-table tbody tr td:nth-child(2)")?.textContent?.trim();
      if (email && email.includes("@")) {
        window.sessionStorage.setItem(cacheKey, email);
        actorLabel.textContent = email;
      }
    } catch {
      // Leave the original actor ID in place if the admin lookup is unavailable.
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
    const explicitConfirm = form.querySelector("button[data-confirm]");
    if (explicitConfirm && !window.confirm(explicitConfirm.dataset.confirm || "Confirm this admin action?")) {
      event.preventDefault();
      return;
    }
    const dangerous = form.querySelector("button[name='status'][value='disqualified'], button[name='outcome'][value='disqualified']");
    if (dangerous && !window.confirm("Confirm this admin action?")) {
      event.preventDefault();
    }
  });
});
