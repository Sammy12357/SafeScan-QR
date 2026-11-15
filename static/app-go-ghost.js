// app-go-ghost.js — Go Ghost data-broker removal: DOM refs, storage, broker logic helpers.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
const goGhostWorkspace = document.getElementById("goGhostWorkspace");
const GO_GHOST_BROWSER_AUTOMATION_AVAILABLE = goGhostWorkspace?.dataset.browserAutomationAvailable === "true";
const goGhostConsentModal = document.getElementById("goGhostConsentModal");
const startGoGhostButton = document.getElementById("startGoGhostButton");
const goGhostProfileForm = document.getElementById("goGhostProfileForm");
const clearGhostDataButton = document.getElementById("clearGhostDataButton");
const goGhostBrokerList = document.getElementById("goGhostBrokerList");
const goGhostAutomationRows = document.getElementById("goGhostAutomationRows");
const goGhostScopeModal = document.getElementById("goGhostScopeModal");
const goGhostScopeTitle = document.getElementById("goGhostScopeTitle");
const goGhostScopePriority = document.getElementById("goGhostScopePriority");
const goGhostScopeDescription = document.getElementById("goGhostScopeDescription");
const goGhostScopeKeywords = document.getElementById("goGhostScopeKeywords");
const goGhostScopeDetails = document.getElementById("goGhostScopeDetails");
const goGhostScopeSearchButton = document.getElementById("goGhostScopeSearchButton");
const goGhostScopeOptOutButton = document.getElementById("goGhostScopeOptOutButton");
const goGhostScopeAutoFillButton = document.getElementById("goGhostScopeAutoFillButton");
const goGhostScopeFinishButton = document.getElementById("goGhostScopeFinishButton");
const goGhostScopeNoMatchButton = document.getElementById("goGhostScopeNoMatchButton");
const goGhostScopeSubmittedButton = document.getElementById("goGhostScopeSubmittedButton");
const goGhostScopeRemovedButton = document.getElementById("goGhostScopeRemovedButton");
const goGhostScopeResetButton = document.getElementById("goGhostScopeResetButton");
const goGhostScopeCopyButton = document.getElementById("goGhostScopeCopyButton");
const startGhostQueueButton = document.getElementById("startGhostQueueButton");
const openNextGhostBrokerButton = document.getElementById("openNextGhostBrokerButton");
const ghostProgressCount = document.getElementById("ghostProgressCount");
const ghostNameInput = document.getElementById("ghostNameInput");
const ghostLocationInput = document.getElementById("ghostLocationInput");
const ghostAddressInput = document.getElementById("ghostAddressInput");
const ghostPhoneInput = document.getElementById("ghostPhoneInput");
const ghostEmailInput = document.getElementById("ghostEmailInput");
const goGhostDeviceNotice = document.getElementById("goGhostDeviceNotice");
const GO_GHOST_PROFILE_KEY = "safeScanGoGhostProfile";
const GO_GHOST_PROGRESS_KEY = "safeScanGoGhostProgress";
const GO_GHOST_CONSENT_KEY = "safeScanGoGhostConsent";
let activeGhostScopeBrokerId = "";
const goGhostAutomationControllers = new Map();

function ghostSearchFromRegistry(broker, profile) {
  const search = broker.search;
  if (search.kind === "path") {
    const name = ghostPathSlug(profile.name);
    const location = ghostPathSlug(profile.location);
    return `${search.baseUrl}${name}${location ? `${search.locationSeparator}${location}` : ""}`;
  }
  if (search.kind === "query") {
    const url = new URL(search.baseUrl);
    url.searchParams.set(search.nameParam, profile.name || "");
    url.searchParams.set(search.locationParam, profile.location || "");
    return url.toString();
  }
  if (search.kind === "google") {
    return ghostBrokerGoogleSearch(profile, broker.name, search.domain);
  }
  return search.url;
}

function loadGoGhostBrokerRegistry() {
  // The server embeds its validated registry in the Go Ghost page. Other pages
  // load this shared script without a broker directory or a network request.
  const node = document.getElementById("goGhostBrokerRegistry");
  if (!node) return [];
  try {
    const records = JSON.parse(node.textContent);
    if (!Array.isArray(records)) return [];
    return records.map((broker) => ({
      ...broker,
      searchUrl: (profile) => ghostSearchFromRegistry(broker, profile)
    }));
  } catch {
    return [];
  }
}

const goGhostBrokers = loadGoGhostBrokerRegistry();

function readJsonStorage(key, fallback) {
  try {
    return JSON.parse(window.localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

function writeJsonStorage(key, value) {
  window.localStorage.setItem(key, JSON.stringify(value));
}

function cleanGhostText(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function ghostPathSlug(value) {
  return cleanGhostText(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function getGhostProfile() {
  const profile = readJsonStorage(GO_GHOST_PROFILE_KEY, { name: "", location: "", address: "", phone: "", email: "", identifier: "" });
  const currentProfile = {
    ...profile,
    name: ghostNameInput ? cleanGhostText(ghostNameInput.value) : cleanGhostText(profile.name),
    location: ghostLocationInput ? cleanGhostText(ghostLocationInput.value) : cleanGhostText(profile.location),
    address: ghostAddressInput ? cleanGhostText(ghostAddressInput.value) : cleanGhostText(profile.address),
    phone: ghostPhoneInput ? cleanGhostText(ghostPhoneInput.value) : cleanGhostText(profile.phone),
    email: ghostEmailInput ? cleanGhostText(ghostEmailInput.value) : cleanGhostText(profile.email),
    identifier: profile.identifier || ""
  };
  currentProfile.phone = currentProfile.phone || currentProfile.identifier || "";
  currentProfile.email = currentProfile.email || "";
  return currentProfile;
}

function getGhostProgress() {
  return readJsonStorage(GO_GHOST_PROGRESS_KEY, {});
}

function setGhostProgress(siteId, field, checked) {
  const progress = getGhostProgress();
  progress[siteId] = {
    ...(progress[siteId] || {}),
    [field]: checked,
    ...(checked && (field === "submitted" || field === "removed") ? { noMatch: false, finishReason: "" } : {}),
    updatedAt: new Date().toISOString()
  };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
}

function ghostHasNoMatch(state) {
  // Older clients saved no-match as `removed: true` with a finish reason.
  return Boolean(state?.noMatch || state?.finishReason);
}

function setGhostManualStatus(siteId, status) {
  if (!goGhostBrokers.some((broker) => broker.id === siteId)) return;
  const progress = getGhostProgress();
  progress[siteId] = {
    ...(progress[siteId] || {}),
    submitted: status === "submitted" || status === "removed",
    removed: status === "removed",
    noMatch: status === "no_match",
    finishReason: status === "no_match" ? "No matching profile found in search results." : "",
    automation: null,
    updatedAt: new Date().toISOString()
  };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
}

function finishGhostBroker(siteId, detail = "No matching profile found.") {
  const progress = getGhostProgress();
  progress[siteId] = {
    ...(progress[siteId] || {}),
    submitted: false,
    removed: false,
    noMatch: true,
    finishReason: detail,
    automation: null,
    updatedAt: new Date().toISOString()
  };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
}

function updateGhostAutomationState(siteId, automation) {
  const progress = getGhostProgress();
  progress[siteId] = { ...(progress[siteId] || {}), automation, updatedAt: new Date().toISOString() };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
}

function formatGhostAutomationStatus(status) {
  const labels = {
    captcha_required: "CAPTCHA checkpoint",
    email_required: "Confirm by email",
    needs_profile_url: "Pick your listing",
    filled: "Form filled",
    opened: "Opt-out tab opened",
    cancelled: "Cancelled",
    submitted: "Submitted",
    unavailable: "Automation unavailable",
    failed: "Automation failed",
    running: "Running"
  };
  return labels[status] || "Updated";
}

// Brokers known to gate submission behind a CAPTCHA. Used only as a pre-run
// hint for the effort badge; the live run status is the source of truth.
const GHOST_CAPTCHA_BROKERS = new Set(["fastpeoplesearch", "truepeoplesearch", "thatsthem"]);

// Pre-run estimate of how much the human still has to do for a broker, so the
// UI can promise "we did the tedious part" honestly. The actual run status
// (submitted / email_required / captcha_required / needs_profile_url) refines
// this afterwards. lane "auto" = backend submits and only an email click is
// left; lane "step" = one short human action (CAPTCHA tick or listing pick).
function ghostEffortLane(broker) {
  if (!GO_GHOST_BROWSER_AUTOMATION_AVAILABLE || !broker.automationEnabled) {
    return { key: "manual", label: "Manual", you: "You submit", lane: "step" };
  }
  const info = (broker.requiredInfo || []).join(" ").toLowerCase();
  if (/profile url|matching profile|matching record/.test(info)) {
    return { key: "listing", label: "Pick listing", you: "~30s", lane: "step" };
  }
  if (GHOST_CAPTCHA_BROKERS.has(broker.id)) {
    return { key: "captcha", label: "CAPTCHA", you: "~10s", lane: "step" };
  }
  return { key: "auto", label: "Auto", you: "Check email", lane: "auto" };
}

// Maps a backend run status to a plain "what you do now" line. action:true
// means the next step is the one-click "Finish in browser" handoff. The
// backend-filled browser cannot be transferred to the user's browser, so the
// handoff opens the broker page and copies the details packet for quick paste.
function ghostStatusGuidance(status) {
  switch (status) {
    case "submitted":
      return { tone: "done", text: "Submitted on your behalf — nothing left to do." };
    case "email_required":
      return { tone: "done", text: "Submitted. Open the broker's confirmation email and click the link to finish." };
    case "captcha_required":
      return { tone: "action", action: true, text: "Backend autofill reached a CAPTCHA. Finish in your browser with your details copied for quick paste, then solve the CAPTCHA and submit." };
    case "needs_profile_url":
      return { tone: "action", action: true, text: "This broker needs your exact listing. Finish in your browser with your details copied, pick your record, then submit." };
    case "filled":
      return { tone: "action", action: true, text: "Backend autofill found the form, but could not submit. Finish in your browser with your details copied for quick paste." };
    case "running":
      return { tone: "info", text: "Filling the form on a server-side browser…" };
    case "unavailable":
      return { tone: "info", text: "Backend automation isn't available here — use Opt out to do it manually." };
    case "cancelled":
      return { tone: "info", text: "Run cancelled." };
    case "failed":
      return { tone: "info", text: "Automation couldn't finish. Use Opt out to complete it manually." };
    default:
      return { tone: "info", text: "" };
  }
}

function goGhostAutomationScope(broker) {
  const requiresProfileUrl = (broker.requiredInfo || []).some((item) => /profile url/i.test(item));
  const requiresEmail = (broker.requiredInfo || []).some((item) => /email/i.test(item));
  return {
    search: requiresProfileUrl ? "Profile" : "Auto",
    submit: requiresProfileUrl ? "URL" : "Auto",
    manual: requiresEmail ? "Email" : "Review"
  };
}

// Use only a recognized region from the free-text city/state field. A street
// address entered there must not be sent to a search engine in the URL.
const ghostSearchRegionCodes = new Set("AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY".split(" "));
const ghostSearchRegionNames = new Set("alabama|alaska|arizona|arkansas|california|colorado|connecticut|delaware|district of columbia|florida|georgia|hawaii|idaho|illinois|indiana|iowa|kansas|kentucky|louisiana|maine|maryland|massachusetts|michigan|minnesota|mississippi|missouri|montana|nebraska|nevada|new hampshire|new jersey|new mexico|new york|north carolina|north dakota|ohio|oklahoma|oregon|pennsylvania|rhode island|south carolina|south dakota|tennessee|texas|utah|vermont|virginia|washington|west virginia|wisconsin|wyoming".split("|"));

function ghostSearchRegion(location) {
  const candidate = String(location || "").split(",").pop().trim();
  if (/^[A-Z]{2}$/i.test(candidate)) return ghostSearchRegionCodes.has(candidate.toUpperCase()) ? candidate.toUpperCase() : "";
  return ghostSearchRegionNames.has(candidate.toLowerCase()) ? candidate : "";
}

function ghostSearchFallback(profile, brokerName) {
  const query = [profile.name, ghostSearchRegion(profile.location), brokerName].filter(Boolean).join(" ");
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

function ghostBrokerGoogleSearch(profile, brokerName, domain) {
  const query = [profile.name, ghostSearchRegion(profile.location), brokerName, `site:${domain}`].filter(Boolean).join(" ");
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

function goGhostBrokerOptOutUrl(broker) {
  // Open the published form without putting profile details in its URL.
  return broker.removalUrl;
}

function goGhostCopyPacket(broker, profile, searchUrl) {
  const optOutUrl = goGhostBrokerOptOutUrl(broker);
  return [
    `${broker.name} opt-out packet`,
    `Name: ${profile.name || ""}`,
    `Street address: ${profile.address || ""}`,
    `City/state: ${profile.location || ""}`,
    `Phone: ${profile.phone || profile.identifier || ""}`,
    `Email: ${profile.email || ""}`,
    `Search link: ${searchUrl}`,
    `Opt-out link: ${optOutUrl}`,
    `Needed: ${(broker.requiredInfo || []).join(", ")}`,
    `Next step: ${GO_GHOST_BROWSER_AUTOMATION_AVAILABLE ? (broker.automationNote || "Open the matching profile and complete the broker opt-out form.") : "Open the broker opt-out page and complete the request in your browser."}`,
  ].join("\n");
}

function goGhostBrokerSearchUrl(broker, profile) {
  return profile.name ? broker.searchUrl(profile) : ghostSearchFallback(profile, broker.name);
}

function openGhostUrl(url) {
  const opened = window.open(url, "_blank", "noopener,noreferrer");
  if (opened) opened.opener = null;
  return Boolean(opened);
}

async function openGhostOptOutWithPacket(broker, profile, searchUrl) {
  const copiedPromise = copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
  const opened = openGhostUrl(goGhostBrokerOptOutUrl(broker));
  const copied = await copiedPromise;
  if (opened && copied) return `${broker.name}: opened + details copied`;
  if (opened) return `Opened ${broker.name}; copy details if the form is blank`;
  if (copied) return `${broker.name} details copied`;
  return `Open ${broker.name} manually and use Copy details`;
}

function hasGhostSearchProfile(profile) {
  return Boolean((profile.name || "").trim());
}

function nextPendingGhostBroker() {
  const progress = getGhostProgress();
  return goGhostBrokers.find((broker) => {
    const state = progress[broker.id];
    return !state?.submitted && !state?.removed && !ghostHasNoMatch(state);
  }) || null;
}

function scrollToGhostProfile() {
  goGhostProfileForm?.scrollIntoView({ behavior: "smooth", block: "center" });
  ghostNameInput?.focus({ preventScroll: true });
}

function scrollToGhostBroker(broker) {
  const row = broker ? goGhostAutomationRows?.querySelector(`[data-ghost-scope="${broker.id}"]`) : goGhostAutomationRows;
  row?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function getGhostFormProfile() {
  return {
    name: ghostNameInput?.value?.trim() || "",
    location: ghostLocationInput?.value?.trim() || "",
    address: ghostAddressInput?.value?.trim() || "",
    phone: ghostPhoneInput?.value?.trim() || "",
    email: ghostEmailInput?.value?.trim() || ""
  };
}

function applyGoGhostDeviceFormatting() {
  if (!goGhostWorkspace) return;
  const mobile = isMobileDevice() || window.matchMedia("(max-width: 900px)").matches;
  document.body.classList.toggle("go-ghost-mobile", mobile);
  document.body.classList.toggle("go-ghost-desktop", !mobile);
  if (goGhostDeviceNotice) {
    goGhostDeviceNotice.textContent = GO_GHOST_BROWSER_AUTOMATION_AVAILABLE
      ? (mobile ? "Mobile layout detected. Go Ghost will stack actions, enlarge tap targets, and keep local automation fields easy to edit." : "Desktop layout active. Automation scope is kept beside the broker workflow.")
      : (mobile ? "Mobile layout active. Search and opt-out actions are ready below." : "Desktop layout active. Search and opt-out actions are ready below.");
  }
}

let ghostQueueRunning = false;
let ghostQueueStopRequested = false;

const GHOST_MANUAL_STATUSES = ["captcha_required", "email_required", "needs_profile_url"];

// Runs backend Playwright autofill across every automation-enabled broker that
// is not already submitted/removed, one after another. Brokers that need a
// human step (CAPTCHA, email confirmation, or picking your own listing) are
// recorded as checkpoints so you can finish them, while the queue keeps moving
// through the rest so all 8 trackers are attempted in a single pass.
async function startGhostAssistedQueue() {
  if (!GO_GHOST_BROWSER_AUTOMATION_AVAILABLE) return;
  const profile = getGhostProfile();
  if (!hasGhostSearchProfile(profile)) {
    scrollToGhostProfile();
    showCopyToast("Add a name first");
    return;
  }
  if (!profile.email?.trim()) {
    scrollToGhostProfile();
    ghostEmailInput?.focus({ preventScroll: true });
    showCopyToast("Add an email first");
    return;
  }
  if (ghostQueueRunning) {
    ghostQueueStopRequested = true;
    showCopyToast("Stopping after current broker");
    return;
  }

  const progress = getGhostProgress();
  const queue = goGhostBrokers.filter(
    (broker) => broker.automationEnabled && !progress[broker.id]?.submitted && !progress[broker.id]?.removed
  );
  if (!queue.length) {
    showCopyToast("All automated brokers tracked");
    return;
  }

  ghostQueueRunning = true;
  ghostQueueStopRequested = false;
  if (startGhostQueueButton) {
    startGhostQueueButton.textContent = "Stop queue";
    startGhostQueueButton.setAttribute("aria-pressed", "true");
  }

  let manualCheckpoints = 0;
  let completed = 0;
  try {
    for (const broker of queue) {
      if (ghostQueueStopRequested) break;
      scrollToGhostBroker(broker);
      showCopyToast(`Running ${broker.name}…`);
      const result = await runGhostBrokerAutomation(broker, null);
      if (!result) continue;
      if (GHOST_MANUAL_STATUSES.includes(result.status)) manualCheckpoints += 1;
      else if (result.status === "submitted") completed += 1;
    }
  } finally {
    ghostQueueRunning = false;
    ghostQueueStopRequested = false;
    if (startGhostQueueButton) {
      startGhostQueueButton.textContent = "Start assisted queue";
      startGhostQueueButton.removeAttribute("aria-pressed");
    }
    renderGoGhostAutomationScope();
    renderGoGhostProgress();
  }

  if (manualCheckpoints) {
    showCopyToast(`Queue done — ${manualCheckpoints} need a manual step`);
  } else {
    showCopyToast(`Queue complete — ${completed} submitted`);
  }
}

