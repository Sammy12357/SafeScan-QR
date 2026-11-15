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
const ghostFirstNameInput = document.getElementById("ghostFirstNameInput");
const ghostMiddleNameInput = document.getElementById("ghostMiddleNameInput");
const ghostLastNameInput = document.getElementById("ghostLastNameInput");
const ghostCityInput = document.getElementById("ghostCityInput");
const ghostStateInput = document.getElementById("ghostStateInput");
const ghostBirthYearInput = document.getElementById("ghostBirthYearInput");
const ghostAddressInput = document.getElementById("ghostAddressInput");
const ghostPhoneInput = document.getElementById("ghostPhoneInput");
const ghostEmailInput = document.getElementById("ghostEmailInput");
const ghostPreviousCitiesInput = document.getElementById("ghostPreviousCitiesInput");
const ghostOtherNamesInput = document.getElementById("ghostOtherNamesInput");
const ghostProfileReviewNotice = document.getElementById("ghostProfileReviewNotice");
const ghostSavedProfileHint = document.getElementById("ghostSavedProfileHint");
const ghostAccountNameHint = document.getElementById("ghostAccountNameHint");
const goGhostDeviceNotice = document.getElementById("goGhostDeviceNotice");
const goGhostSessionNotice = document.getElementById("goGhostSessionNotice");
const goGhostLegacyNotice = document.getElementById("goGhostLegacyNotice");
const goGhostLegacyActions = document.getElementById("goGhostLegacyActions");
const eraseGhostLegacyButton = document.getElementById("eraseGhostLegacyButton");
const ghostSubjectSelect = document.getElementById("ghostSubjectSelect");
const addGhostFamilyButton = document.getElementById("addGhostFamilyButton");
const removeGhostSubjectButton = document.getElementById("removeGhostSubjectButton");
const ghostFamilyAttestationLabel = document.getElementById("ghostFamilyAttestationLabel");
const ghostFamilyAttestationInput = document.getElementById("ghostFamilyAttestationInput");
const GO_GHOST_PROFILE_KEY = "safeScanGoGhostProfile";
const GO_GHOST_PROGRESS_KEY = "safeScanGoGhostProgress";
const GO_GHOST_CONSENT_KEY = "safeScanGoGhostConsent";
const GO_GHOST_LEGACY_KEYS = [GO_GHOST_PROFILE_KEY, GO_GHOST_PROGRESS_KEY, GO_GHOST_CONSENT_KEY];
// The old keys have no owner. Erase them without reading or importing values.
const goGhostAccountId = goGhostWorkspace?.dataset.accountId || "";
const goGhostAccountName = goGhostWorkspace?.dataset.accountName || "";
const goGhostAccountEmail = goGhostWorkspace?.dataset.accountEmail || "";
const GO_GHOST_STORE_KEY = goGhostAccountId
  ? `safeScanGoGhostV2:account:${encodeURIComponent(goGhostAccountId)}`
  : "safeScanGoGhostV2:guest";
function ghostStorageForScope() {
  if (!goGhostWorkspace) return null;
  try { return goGhostAccountId ? window.localStorage : window.sessionStorage; }
  catch { return null; }
}
const goGhostStorageArea = ghostStorageForScope();
const goGhostFamilyAttestedThisVisit = new Set();
let goGhostStoreLocked = false;
let goGhostState = null;
let activeGhostScopeBrokerId = "";
const goGhostAutomationControllers = new Map();

function ghostSearchFromRegistry(broker) {
  // These are fixed broker pages. A name or location must never be placed in
  // a URL constructed by SafeScan; the person enters it on the broker site.
  return broker.search.url;
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
      searchUrl: () => ghostSearchFromRegistry(broker)
    }));
  } catch {
    return [];
  }
}

const goGhostBrokers = loadGoGhostBrokerRegistry();

function readJsonStorage(key, fallback, area) {
  if (!area) return fallback;
  try {
    return JSON.parse(area.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

function writeJsonStorage(key, value, area) {
  if (!area) throw new Error("Browser storage is unavailable.");
  area.setItem(key, JSON.stringify(value));
}

function ghostEmptyProfile() {
  return {
    firstName: "", middleName: "", lastName: "", city: "", state: "", email: "",
    birthYear: "", address: "", phone: "", previousCities: "", otherNames: "",
    // `name` and `location` preserve account-scoped v2 values until the user
    // reviews the split fields. They are never used for an action while unreviewed.
    name: "", location: "", identifier: "", reviewedAt: ""
  };
}

function ghostNewSubject(kind) {
  let id = window.crypto?.randomUUID?.();
  if (!id && window.crypto?.getRandomValues) {
    const bytes = window.crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  if (!id) throw new Error("A secure browser is required to create a Go Ghost profile.");
  return { id, kind, profile: ghostEmptyProfile(), progress: {}, consentAcceptedAt: "", familyAttestedAt: "" };
}

function ghostNormalizeState(value) {
  const state = { version: 2, activeSubjectId: "", subjects: {} };
  if (!value || value.version !== 2 || typeof value.subjects !== "object" || Array.isArray(value.subjects)) return state;
  for (const [id, subject] of Object.entries(value.subjects).slice(0, 20)) {
    if (!/^[0-9a-f-]{36}$/i.test(id) || !subject || !["self", "family"].includes(subject.kind)) continue;
    const source = subject.profile && typeof subject.profile === "object" ? subject.profile : {};
    const profile = ghostEmptyProfile();
    for (const field of Object.keys(profile)) {
      profile[field] = cleanGhostText(typeof source[field] === "string" ? source[field] : "").slice(0, 220);
    }
    state.subjects[id] = {
      id,
      kind: subject.kind,
      profile,
      progress: subject.progress && typeof subject.progress === "object" && !Array.isArray(subject.progress) ? subject.progress : {},
      consentAcceptedAt: typeof subject.consentAcceptedAt === "string" ? subject.consentAcceptedAt : "",
      familyAttestedAt: typeof subject.familyAttestedAt === "string" ? subject.familyAttestedAt : ""
    };
  }
  state.activeSubjectId = Object.hasOwn(state.subjects, value.activeSubjectId)
    ? value.activeSubjectId : Object.keys(state.subjects)[0] || "";
  return state;
}

function ghostCurrentState() {
  if (goGhostStoreLocked) return { version: 2, activeSubjectId: "", subjects: {} };
  if (!goGhostState) goGhostState = ghostNormalizeState(readJsonStorage(GO_GHOST_STORE_KEY, null, goGhostStorageArea));
  return goGhostState;
}

function ghostCurrentSubject() {
  const state = ghostCurrentState();
  if (!state.activeSubjectId) {
    const subject = ghostNewSubject("self");
    state.subjects[subject.id] = subject;
    state.activeSubjectId = subject.id;
  }
  return state.subjects[state.activeSubjectId];
}

function ghostSaveState() {
  if (goGhostStoreLocked || !goGhostStorageArea) return false;
  try {
    writeJsonStorage(GO_GHOST_STORE_KEY, ghostCurrentState(), goGhostStorageArea);
    return true;
  } catch {
    if (goGhostDeviceNotice) goGhostDeviceNotice.textContent = "Browser storage is unavailable. Details will be lost when this page closes.";
    return false;
  }
}

function ghostSaveProfile(profile) {
  if (goGhostStoreLocked) return;
  const next = ghostEmptyProfile();
  for (const field of Object.keys(next)) next[field] = cleanGhostText(profile[field]).slice(0, 220);
  ghostCurrentSubject().profile = next;
  ghostSaveState();
}

const GHOST_PROFILE_FORM_FIELDS = [
  "firstName", "middleName", "lastName", "city", "state", "email", "birthYear",
  "address", "phone", "previousCities", "otherNames"
];

function ghostFormValues() {
  return {
    firstName: cleanGhostText(ghostFirstNameInput?.value),
    middleName: cleanGhostText(ghostMiddleNameInput?.value),
    lastName: cleanGhostText(ghostLastNameInput?.value),
    city: cleanGhostText(ghostCityInput?.value),
    state: cleanGhostText(ghostStateInput?.value),
    email: cleanGhostText(ghostEmailInput?.value),
    birthYear: cleanGhostText(ghostBirthYearInput?.value),
    address: cleanGhostText(ghostAddressInput?.value),
    phone: cleanGhostText(ghostPhoneInput?.value),
    previousCities: cleanGhostText(ghostPreviousCitiesInput?.value),
    otherNames: cleanGhostText(ghostOtherNamesInput?.value)
  };
}

function ghostValidProfileFields(values) {
  // Constrain URL-bound name/city values to text rather than address or URL
  // fragments. A region is selected from the reviewed U.S. list or Outside US.
  const personText = /^[\p{L}\p{M}][\p{L}\p{M} .'-]*$/u;
  const cityText = /^[\p{L}\p{M}][\p{L}\p{M} .'-]*$/u;
  const state = values.state;
  const year = values.birthYear;
  return personText.test(values.firstName) && values.firstName.length <= 80
    && personText.test(values.lastName) && values.lastName.length <= 100
    && (!values.middleName || (personText.test(values.middleName) && values.middleName.length <= 100))
    && cityText.test(values.city) && values.city.length <= 100
    && (ghostSearchRegionCodes.has(state) || state === "OUTSIDE_US")
    && values.email.length <= 180 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)
    && (!year || (/^\d{4}$/.test(year) && Number(year) >= 1900 && Number(year) <= new Date().getFullYear()));
}

function ghostProfileIsReviewed() {
  if (goGhostStoreLocked || !goGhostWorkspace) return false;
  const saved = ghostCurrentSubject().profile;
  const form = ghostFormValues();
  const reviewedAt = saved.reviewedAt;
  const validReviewTime = typeof reviewedAt === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(reviewedAt)
    && !Number.isNaN(Date.parse(reviewedAt)) && new Date(reviewedAt).toISOString() === reviewedAt;
  return validReviewTime && ghostValidProfileFields(form)
    && GHOST_PROFILE_FORM_FIELDS.every((field) => form[field] === saved[field]);
}

function ghostActionProfile() {
  const values = ghostFormValues();
  const reviewed = ghostProfileIsReviewed();
  const name = reviewed ? `${values.firstName} ${values.lastName}` : "";
  const location = reviewed && values.state !== "OUTSIDE_US" ? `${values.city}, ${values.state}` : "";
  return { ...values, name, location, identifier: "" };
}

function ghostSaveProgress(progress) {
  if (goGhostStoreLocked) return;
  ghostCurrentSubject().progress = progress;
  ghostSaveState();
}

function ghostEraseLegacyData() {
  let eraseFailed = false;
  try {
    const area = window.localStorage;
    const presentKeys = () => {
      const names = new Set();
      for (let index = 0; index < area.length; index += 1) {
        const name = area.key(index);
        if (GO_GHOST_LEGACY_KEYS.includes(name)) names.add(name);
      }
      return names;
    };
    for (const key of presentKeys()) area.removeItem(key);
    eraseFailed = presentKeys().size > 0;
  } catch {
    eraseFailed = true;
  }
  if (goGhostLegacyNotice) goGhostLegacyNotice.hidden = !eraseFailed;
  if (goGhostLegacyActions) goGhostLegacyActions.hidden = !eraseFailed;
  return !eraseFailed;
}

// This shared script also loads on the account profile page. Erase as soon as
// either page opens, without waiting for consent or reading the legacy values.
ghostEraseLegacyData();

function cleanGhostText(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function getGhostProfile() {
  if (goGhostStoreLocked || !goGhostWorkspace) return ghostEmptyProfile();
  return ghostActionProfile();
}

function getGhostProgress() {
  if (goGhostStoreLocked || !goGhostWorkspace) return {};
  return ghostCurrentSubject().progress;
}

function setGhostProgress(siteId, field, checked) {
  const progress = getGhostProgress();
  progress[siteId] = {
    ...(progress[siteId] || {}),
    [field]: checked,
    ...(checked && (field === "submitted" || field === "removed") ? { noMatch: false, finishReason: "" } : {}),
    updatedAt: new Date().toISOString()
  };
  ghostSaveProgress(progress);
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
  ghostSaveProgress(progress);
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
  ghostSaveProgress(progress);
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
}

function updateGhostAutomationState(siteId, automation) {
  const progress = getGhostProgress();
  progress[siteId] = { ...(progress[siteId] || {}), automation, updatedAt: new Date().toISOString() };
  ghostSaveProgress(progress);
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

// Only a reviewed state code can be selected in the profile form.
const ghostSearchRegionCodes = new Set("AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY".split(" "));

function goGhostBrokerOptOutUrl(broker) {
  // Open the published form without putting profile details in its URL.
  return broker.removalUrl;
}

function goGhostCopyPacket(broker, profile, searchUrl) {
  const optOutUrl = goGhostBrokerOptOutUrl(broker);
  return [
    `${broker.name} opt-out packet`,
    `Name: ${profile.name || ""}`,
    `City/state: ${profile.location || ""}`,
    `Email: ${profile.email || ""}`,
    `Search link: ${searchUrl}`,
    `Opt-out link: ${optOutUrl}`,
    `Needed: ${(broker.requiredInfo || []).join(", ")}`,
    "Optional address, phone, birth year, and aliases are not copied. Add them only if this broker requires them.",
    `Next step: ${GO_GHOST_BROWSER_AUTOMATION_AVAILABLE ? (broker.automationNote || "Open the matching profile and complete the broker opt-out form.") : "Open the broker opt-out page and complete the request in your browser."}`,
  ].join("\n");
}

function goGhostBrokerSearchUrl(broker, profile) {
  if (profile.state === "OUTSIDE_US") return broker.removalUrl;
  return broker.searchUrl();
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

function nextPendingGhostBroker(allowed = () => true) {
  const progress = getGhostProgress();
  return goGhostBrokers.find((broker) => {
    const state = progress[broker.id];
    return allowed(broker) && !state?.submitted && !state?.removed && !ghostHasNoMatch(state);
  }) || null;
}

function scrollToGhostProfile() {
  goGhostProfileForm?.scrollIntoView({ behavior: "smooth", block: "center" });
  ghostFirstNameInput?.focus({ preventScroll: true });
}

function scrollToGhostBroker(broker) {
  const row = broker ? goGhostAutomationRows?.querySelector(`[data-ghost-scope="${broker.id}"]`) : goGhostAutomationRows;
  row?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function getGhostFormProfile() {
  return { ...ghostCurrentSubject().profile, ...ghostFormValues() };
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
  if (ghostCurrentSubject().kind === "family") {
    showCopyToast("Assisted submissions are unavailable for family requests");
    return;
  }
  if (!ghostCanAct()) return;
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

