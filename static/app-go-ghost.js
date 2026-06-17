// app-go-ghost.js — Go Ghost data-broker removal: DOM refs, storage, broker logic helpers.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
const goGhostWorkspace = document.getElementById("goGhostWorkspace");
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

const goGhostBrokers = [
  {
    id: "fastpeoplesearch",
    name: "FastPeopleSearch",
    priority: "High traffic",
    priorityDescription: "One of the most visible people-search sites, so it is a good place to remove first.",
    removalUrl: "https://www.fastpeoplesearch.com/optout",
    prefillMap: { name: "name", address: "address", location: "citystate", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "Street address", "City/state", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: fill the opt-out form and pause for CAPTCHA or email confirmation.",
    searchUrl: ({ name, location }) => `https://www.fastpeoplesearch.com/name/${ghostPathSlug(name)}${location ? `_${ghostPathSlug(location)}` : ""}`
  },
  {
    id: "whitepages",
    name: "Whitepages",
    priority: "High traffic",
    priorityDescription: "One of the most visible people-search sites, so it is a good place to remove first.",
    removalUrl: "https://www.whitepages.com/suppression-requests",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Matching profile", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: opens the suppression form and fills your details. Whitepages needs you to pick your matching listing and confirm by email.",
    searchUrl: ({ name, location }) => `https://www.whitepages.com/name/${ghostPathSlug(name)}${location ? `/${ghostPathSlug(location)}` : ""}`
  },
  {
    id: "spokeo",
    name: "Spokeo",
    priority: "High traffic",
    priorityDescription: "One of the most visible people-search sites, so it is a good place to remove first.",
    removalUrl: "https://www.spokeo.com/optout",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Profile URL", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: opens Spokeo opt-out and fills your email. Spokeo removes by listing URL, so use Search to find your profile, paste its URL, then verify by email.",
    searchUrl: ({ name, location }) => `https://www.spokeo.com/${ghostPathSlug(name)}${location ? `/${ghostPathSlug(location)}` : ""}`
  },
  {
    id: "beenverified",
    name: "BeenVerified",
    priority: "High traffic",
    priorityDescription: "One of the most visible people-search sites, so it is a good place to remove first.",
    removalUrl: "https://www.beenverified.com/app/optout/search/",
    prefillMap: { name: "fn", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "State/city", "Matching record", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: opens the opt-out search and fills your name. BeenVerified needs you to choose your matching record and confirm by email.",
    searchUrl: ({ name }) => `https://www.beenverified.com/app/optout/search?fn=${encodeURIComponent(name || "")}`
  },
  {
    id: "truepeoplesearch",
    name: "TruePeopleSearch",
    priority: "High traffic",
    priorityDescription: "One of the most visible people-search sites, so it is a good place to remove first.",
    removalUrl: "https://www.truepeoplesearch.com/removal",
    prefillMap: { name: "name", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Matching profile", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: opens the removal flow and fills your details. TruePeopleSearch needs you to confirm the matching record and clear a CAPTCHA.",
    searchUrl: ({ name, location }) => `https://www.truepeoplesearch.com/results?name=${encodeURIComponent(name || "")}&citystatezip=${encodeURIComponent(location || "")}`
  },
  {
    id: "thatsthem",
    name: "Thatsthem",
    priority: "Address match",
    priorityDescription: "This site often finds records through address or phone details.",
    removalUrl: "https://thatsthem.com/optout",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "Street address or phone", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: fills the opt-out form with your name, email, and address, then pauses for any CAPTCHA or email confirmation.",
    searchUrl: ({ name, location }) => `https://thatsthem.com/name/${ghostPathSlug(name)}${location ? `/${ghostPathSlug(location)}` : ""}`
  },
  {
    id: "nuwber",
    name: "Nuwber",
    priority: "Profile link",
    priorityDescription: "This opt-out usually needs the exact profile URL before removal can be submitted.",
    removalUrl: "https://nuwber.com/removal/link",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Profile URL", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: opens the removal form and fills your email. Nuwber removes by profile URL, so use Search to find your listing, paste its URL, then verify by email.",
    searchUrl: ({ name, location }) => `https://nuwber.com/search?name=${encodeURIComponent(name || "")}&location=${encodeURIComponent(location || "")}`
  },
  {
    id: "radaris",
    name: "Radaris",
    priority: "Duplicate check",
    priorityDescription: "This site can show multiple records for one person, so check for duplicates before marking it removed.",
    removalUrl: "https://radaris.com/control/privacy",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Profile URL", "Matching record", "Email confirmation"],
    automationEnabled: true,
    automationNote: "Backend assisted: opens the Radaris privacy control and fills your email. Radaris removes by listing, so use Search to find your record, confirm the exact profile, then verify by email.",
    searchUrl: ({ name, location }) => ghostBrokerGoogleSearch({ name, location }, "Radaris", "radaris.com")
  },
  {
    id: "peoplefinders",
    name: "PeopleFinders",
    priority: "Second wave",
    priorityDescription: "A high-volume data broker that often needs name plus location to find matching records.",
    removalUrl: "https://www.peoplefinders.com/opt-out",
    prefillMap: { name: "name", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then confirm the matching record.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "PeopleFinders", "peoplefinders.com")
  },
  {
    id: "intelius",
    name: "Intelius",
    priority: "Second wave",
    priorityDescription: "A people-search broker that can require enough detail to distinguish similar names.",
    removalUrl: "https://www.intelius.com/opt-out/submit/",
    prefillMap: { name: "name", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then complete any confirmation steps.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "Intelius", "intelius.com")
  },
  {
    id: "ussearch",
    name: "US Search",
    priority: "Second wave",
    priorityDescription: "A people-search broker that often needs name plus location to narrow matches.",
    removalUrl: "https://www.ussearch.com/opt-out/submit/",
    prefillMap: { name: "name", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then complete any confirmation steps.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "US Search", "ussearch.com")
  },
  {
    id: "instantcheckmate",
    name: "Instant Checkmate",
    priority: "Second wave",
    priorityDescription: "A background-check broker whose removal flow can use identity-matching details.",
    removalUrl: "https://www.instantcheckmate.com/opt-out/submit/",
    prefillMap: { name: "name", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then complete any confirmation steps.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "Instant Checkmate", "instantcheckmate.com")
  },
  {
    id: "truthfinder",
    name: "TruthFinder",
    priority: "Second wave",
    priorityDescription: "A background-check broker where similar names may require careful record matching.",
    removalUrl: "https://www.truthfinder.com/opt-out/submit/",
    prefillMap: { name: "name", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then complete any confirmation steps.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "TruthFinder", "truthfinder.com")
  },
  {
    id: "peoplelooker",
    name: "PeopleLooker",
    priority: "Second wave",
    priorityDescription: "A people-search broker with an opt-out submission flow similar to related sites.",
    removalUrl: "https://www.peoplelooker.com/opt-out/submit/",
    prefillMap: { name: "name", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then complete any confirmation steps.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "PeopleLooker", "peoplelooker.com")
  },
  {
    id: "neighborwho",
    name: "NeighborWho",
    priority: "Second wave",
    priorityDescription: "An address-heavy broker where street address and city/state help identify the right record.",
    removalUrl: "https://www.neighborwho.com/opt-out/",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "Street address", "City/state", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then confirm the matching address record.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "NeighborWho", "neighborwho.com")
  },
  {
    id: "clustrmaps",
    name: "ClustrMaps",
    priority: "Second wave",
    priorityDescription: "An address and profile broker where multiple entries can exist for one person.",
    removalUrl: "https://clustrmaps.com/bl/opt-out",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "Street address", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then confirm the matching profile.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "ClustrMaps", "clustrmaps.com")
  },
  {
    id: "familytreenow",
    name: "FamilyTreeNow",
    priority: "Second wave",
    priorityDescription: "A genealogy-style people-search site that commonly starts removal from a record search.",
    removalUrl: "https://www.familytreenow.com/optout",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "City/state", "Matching profile"],
    automationNote: "Assisted: search for the matching record, then complete the opt-out flow.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "FamilyTreeNow", "familytreenow.com")
  },
  {
    id: "cyberbackgroundchecks",
    name: "CyberBackgroundChecks",
    priority: "Second wave",
    priorityDescription: "A profile-specific background-check site where exact record matching matters.",
    removalUrl: "https://www.cyberbackgroundchecks.com/removal",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "Street address", "Matching profile", "Email confirmation"],
    automationNote: "Assisted: pass saved details into the opt-out URL, then verify the exact profile before submission.",
    searchUrl: (profile) => ghostBrokerGoogleSearch(profile, "CyberBackgroundChecks", "cyberbackgroundchecks.com")
  }
];

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
  progress[siteId] = { ...(progress[siteId] || {}), [field]: checked, updatedAt: new Date().toISOString() };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
  renderGoGhostProgress();
}

function finishGhostBroker(siteId, detail = "No matching profile found.") {
  const progress = getGhostProgress();
  progress[siteId] = {
    ...(progress[siteId] || {}),
    submitted: true,
    removed: true,
    finishReason: detail,
    updatedAt: new Date().toISOString()
  };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
  renderGoGhostProgress();
}

function updateGhostAutomationState(siteId, automation) {
  const progress = getGhostProgress();
  progress[siteId] = { ...(progress[siteId] || {}), automation, updatedAt: new Date().toISOString() };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
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
  if (!broker.automationEnabled) {
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

function ghostSearchFallback(profile, brokerName) {
  const query = [profile.name, profile.address, profile.location, brokerName].filter(Boolean).join(" ");
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

function ghostBrokerGoogleSearch(profile, brokerName, domain) {
  const query = [profile.name, profile.address, profile.location, brokerName, `site:${domain}`].filter(Boolean).join(" ");
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

function goGhostBrokerOptOutUrl(broker, profile) {
  const entries = [
    ["name", profile.name],
    ["address", profile.address],
    ["location", profile.location],
    ["phone", profile.phone || profile.identifier],
    ["email", profile.email],
  ].filter(([, value]) => Boolean(value));
  if (!entries.length) return broker.removalUrl;

  const url = new URL(broker.removalUrl);
  entries.forEach(([field, value]) => {
    const param = broker.prefillMap?.[field] || field;
    url.searchParams.set(param, value);
  });
  url.searchParams.set("safescan_prefill", "1");
  return url.toString();
}

function goGhostCopyPacket(broker, profile, searchUrl) {
  const optOutUrl = goGhostBrokerOptOutUrl(broker, profile);
  const requesterType = broker.id === "fastpeoplesearch" ? ["Requester type: I am the subject of this request"] : [];
  return [
    `${broker.name} opt-out packet`,
    ...requesterType,
    `Name: ${profile.name || ""}`,
    `Street address: ${profile.address || ""}`,
    `City/state: ${profile.location || ""}`,
    `Phone: ${profile.phone || profile.identifier || ""}`,
    `Email: ${profile.email || ""}`,
    `Search link: ${searchUrl}`,
    `Opt-out link: ${optOutUrl}`,
    `Needed: ${(broker.requiredInfo || []).join(", ")}`,
    `Next step: ${broker.automationNote || "Open the matching profile and complete the broker opt-out form."}`,
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
  const opened = openGhostUrl(goGhostBrokerOptOutUrl(broker, profile));
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
  return goGhostBrokers.find((broker) => !progress[broker.id]?.submitted && !progress[broker.id]?.removed) || null;
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
    goGhostDeviceNotice.textContent = mobile
      ? "Mobile layout detected. Go Ghost will stack actions, enlarge tap targets, and keep local automation fields easy to edit."
      : "Desktop layout active. Automation scope is kept beside the broker workflow.";
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

