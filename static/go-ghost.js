const brokers = [
  ["fastpeoplesearch", "FastPeopleSearch", "High traffic", "https://www.fastpeoplesearch.com/removal", (p) => `https://www.fastpeoplesearch.com/name/${encodeURIComponent(p.name || "")}${p.location ? `_${encodeURIComponent(p.location)}` : ""}`],
  ["whitepages", "Whitepages", "High traffic", "https://www.whitepages.com/suppression-requests", (p) => `https://www.whitepages.com/name/${encodeURIComponent(p.name || "")}${p.location ? `/${encodeURIComponent(p.location)}` : ""}`],
  ["spokeo", "Spokeo", "High traffic", "https://www.spokeo.com/optout", (p) => `https://www.spokeo.com/${nameSlug(p.name)}`],
  ["beenverified", "BeenVerified", "High traffic", "https://www.beenverified.com/app/optout/search", (p) => `https://www.beenverified.com/app/optout/search?fn=${encodeURIComponent(p.name || "")}`],
  ["truepeoplesearch", "TruePeopleSearch", "High traffic", "https://www.truepeoplesearch.com/removal", (p) => `https://www.truepeoplesearch.com/results?name=${encodeURIComponent(p.name || "")}&citystatezip=${encodeURIComponent(p.location || "")}`],
  ["thatsthem", "Thatsthem", "Address and phone", "https://thatsthem.com/optout", (p) => `https://thatsthem.com/name/${encodeURIComponent(p.name || "")}`],
  ["nuwber", "Nuwber", "Profile-link based", "https://nuwber.com/removal/link", (p) => `https://nuwber.com/search?name=${encodeURIComponent(p.name || "")}&location=${encodeURIComponent(p.location || "")}`],
  ["radaris", "Radaris", "Duplicate profiles", "https://radaris.com/page/how-to-remove", (p) => `https://radaris.com/p/${encodeURIComponent(p.name || "")}/${encodeURIComponent(p.location || "")}`],
];

const keys = {
  profile: "safeScanGoGhostProfile",
  progress: "safeScanGoGhostProgress",
  consent: "safeScanGoGhostConsent",
};

const memoryStore = {};
const store = {
  getItem(key) {
    try {
      return window.localStorage?.getItem(key) ?? memoryStore[key] ?? null;
    } catch {
      return memoryStore[key] ?? null;
    }
  },
  setItem(key, value) {
    memoryStore[key] = value;
    try {
      window.localStorage?.setItem(key, value);
    } catch {}
  },
  removeItem(key) {
    delete memoryStore[key];
    try {
      window.localStorage?.removeItem(key);
    } catch {}
  },
};

const byId = (id) => document.getElementById(id);

function nameSlug(value) {
  return String(value || "")
    .trim()
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function read(key, fallback) {
  try {
    return JSON.parse(store.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

function write(key, value) {
  store.setItem(key, JSON.stringify(value));
}

function escapeHtml(value) {
  return String(value || "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  }[char]));
}

function getProfile() {
  return read(keys.profile, { name: "", location: "", identifier: "" });
}

function getProgress() {
  return read(keys.progress, {});
}

function updateProgress() {
  const state = getProgress();
  const removed = brokers.filter(([id]) => state[id]?.removed).length;
  byId("ghostProgressCount").textContent = `${removed} / ${brokers.length}`;
}

function renderBrokers() {
  const profile = getProfile();
  const state = getProgress();
  byId("goGhostBrokerList").innerHTML = brokers.map(([id, name, priority, removalUrl, search]) => {
    const item = state[id] || {};
    const searchUrl = profile.name
      ? search(profile)
      : `https://www.google.com/search?q=${encodeURIComponent([profile.name, profile.location, name].filter(Boolean).join(" "))}`;
    return `<article class="broker"><div><span class="priority">${escapeHtml(priority)}</span><h3>${escapeHtml(name)}</h3></div><div class="broker-actions"><a class="button" href="${searchUrl}" target="_blank" rel="noopener noreferrer" data-search-link="${id}">Search</a><a class="button primary" href="${removalUrl}" target="_blank" rel="noopener noreferrer">Opt out</a></div><div class="broker-checks"><label><input type="checkbox" data-site="${id}" data-field="submitted" ${item.submitted ? "checked" : ""}> Submitted</label><label><input type="checkbox" data-site="${id}" data-field="removed" ${item.removed ? "checked" : ""}> Removed</label></div></article>`;
  }).join("");
  updateProgress();
}

function updateLinkStatus(message, ready = false) {
  const status = byId("ghostLinkStatus");
  if (!status) return;
  status.textContent = message;
  status.classList.toggle("ready", ready);
}

function hydrateProfile() {
  const profile = getProfile();
  byId("ghostNameInput").value = profile.name || "";
  byId("ghostLocationInput").value = profile.location || "";
  byId("ghostIdentifierInput").value = profile.identifier || "";
}

function startGoGhost() {
  write(keys.consent, { acceptedAt: new Date().toISOString() });
  byId("goGhostConsentModal").classList.add("hidden");
  byId("goGhostWorkspace").hidden = false;
  hydrateProfile();
  renderBrokers();
  updateLinkStatus("Search links are ready.", false);
}

byId("startGoGhostButton").addEventListener("click", startGoGhost);
byId("goGhostProfileForm").addEventListener("submit", (event) => {
  event.preventDefault();
  write(keys.profile, {
    name: byId("ghostNameInput").value.trim(),
    location: byId("ghostLocationInput").value.trim(),
    identifier: byId("ghostIdentifierInput").value.trim(),
  });
  renderBrokers();
  const profile = getProfile();
  updateLinkStatus(profile.name ? "Search links updated with your details." : "Add a name to personalize the search links.", Boolean(profile.name));
});

["ghostNameInput", "ghostLocationInput", "ghostIdentifierInput"].forEach((id) => {
  byId(id).addEventListener("input", () => {
    write(keys.profile, {
      name: byId("ghostNameInput").value.trim(),
      location: byId("ghostLocationInput").value.trim(),
      identifier: byId("ghostIdentifierInput").value.trim(),
    });
    renderBrokers();
    const profile = getProfile();
    updateLinkStatus(profile.name ? "Search links updated." : "Add a name to personalize the search links.", Boolean(profile.name));
  });
});

byId("clearGhostDataButton").addEventListener("click", () => {
  store.removeItem(keys.profile);
  store.removeItem(keys.progress);
  byId("ghostNameInput").value = "";
  byId("ghostLocationInput").value = "";
  byId("ghostIdentifierInput").value = "";
  renderBrokers();
  updateLinkStatus("Search links cleared.", false);
});

byId("goGhostBrokerList").addEventListener("change", (event) => {
  const checkbox = event.target.closest("[data-site][data-field]");
  if (!checkbox) return;
  const state = getProgress();
  state[checkbox.dataset.site] = {
    ...(state[checkbox.dataset.site] || {}),
    [checkbox.dataset.field]: checkbox.checked,
    updatedAt: new Date().toISOString(),
  };
  write(keys.progress, state);
  updateProgress();
});

if (read(keys.consent, null)) {
  startGoGhost();
}
