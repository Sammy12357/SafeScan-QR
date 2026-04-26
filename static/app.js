const sampleUrls = {
  safe: "https://www.apple.com/iphone",
  shortener: "https://bit.ly/3secure-deal",
  lookalike: "https://paypaI-verification-login.com/secure",
  encoded: "https://verify-account-example.net/login?redirect=%68%74%74%70%73%3A%2F%2Fevil.example",
  malware: "http://download-secure-update.top/update-app/installer.apk?payload=1",
  wifi: "WIFI:T:WPA;S:Airport_Free_WiFi;P:guest1234;H:false;;",
  vcard: "BEGIN:VCARD\nVERSION:3.0\nFN:IT Help Desk\nTEL:+18005550123\nURL:https://verify-account-example.net/login\nEND:VCARD",
  sms: "SMSTO:5551234:VERIFY your account at https://paypaI-verification-login.com/secure",
  crypto: "solana:Bpdt7Hey78HeEEr9Q6x19gYAns5n6w44LdjJhxN3pump?amount=2.5&label=SafeScan%20Claim",
  json: "{\"type\":\"airdrop\",\"ref\":\"SAFE-DEMO\",\"action\":\"open\",\"url\":\"https://bit.ly/3secure-deal\"}"
};

const GOOGLE_CLIENT_ID = "PASTE_YOUR_GOOGLE_CLIENT_ID_HERE";
const AIRDROP_REGISTER_ENDPOINT = "";
const PUBLIC_SITE_URL = "https://josephhomza.github.io/hackathon-ideas/phishproof-qr-demo/";
const AIRDROP_STORAGE_KEY = "phishproofAirdropProfile";
const REFERRAL_STORAGE_KEY = "safescanIncomingReferral";
const REFERRAL_ATTRIBUTIONS_STORAGE_KEY = "safescanReferralAttributions";
let googleInitAttempts = 0;

const dom = {
  urlInput: document.getElementById("urlInput"),
  analyzeButton: document.getElementById("analyzeButton"),
  clearButton: document.getElementById("clearButton"),
  sampleButtons: Array.from(document.querySelectorAll(".sample-button")),
  simulateScanButton: document.getElementById("simulateScanButton"),
  qrImageInput: document.getElementById("qrImageInput"),
  uploadPreview: document.getElementById("uploadPreview"),
  previewImage: document.getElementById("previewImage"),
  scanStatus: document.getElementById("scanStatus"),
  qrFrame: document.getElementById("qrFrame"),
  resultsSection: document.getElementById("resultsSection"),
  resultTitle: document.getElementById("resultTitle"),
  verdictBadge: document.getElementById("verdictBadge"),
  finalUrl: document.getElementById("finalUrl"),
  actionText: document.getElementById("actionText"),
  threatTags: document.getElementById("threatTags"),
  redirectChain: document.getElementById("redirectChain"),
  riskReasons: document.getElementById("riskReasons"),
  scoreValue: document.getElementById("scoreValue"),
  signalList: document.getElementById("signalList"),
  actionGate: document.getElementById("actionGate"),
  threatClass: document.getElementById("threatClass"),
  recommendedAction: document.getElementById("recommendedAction"),
  continueButton: document.getElementById("continueButton"),
  copyButton: document.getElementById("copyButton"),
  autoContinueToggle: document.getElementById("autoContinueToggle"),
  tokenAddress: document.getElementById("tokenAddress"),
  copyTokenAddressButton: document.getElementById("copyTokenAddressButton"),
  googleSignInButton: document.getElementById("googleSignInButton"),
  demoGoogleButton: document.getElementById("demoGoogleButton"),
  topCopyReferralButton: document.getElementById("topCopyReferralButton"),
  topConnectWalletButton: document.getElementById("topConnectWalletButton"),
  airdropStatus: document.getElementById("airdropStatus"),
  airdropProfile: document.getElementById("airdropProfile"),
  profileName: document.getElementById("profileName"),
  profileEmail: document.getElementById("profileEmail"),
  profileTier: document.getElementById("profileTier"),
  signOutButton: document.getElementById("signOutButton"),
  demoAccountModal: document.getElementById("demoAccountModal"),
  closeAccountModal: document.getElementById("closeAccountModal"),
  accountOptions: Array.from(document.querySelectorAll(".account-option")),
  currentTierName: document.getElementById("currentTierName"),
  currentTierSummary: document.getElementById("currentTierSummary"),
  scanProgressValue: document.getElementById("scanProgressValue"),
  referralProgressValue: document.getElementById("referralProgressValue"),
  walletStatus: document.getElementById("walletStatus"),
  connectWalletButton: document.getElementById("connectWalletButton"),
  disconnectWalletButton: document.getElementById("disconnectWalletButton"), // Updated field
  demoWalletButton: document.getElementById("demoWalletButton"),
  referralLink: document.getElementById("referralLink"),
  incomingReferral: document.getElementById("incomingReferral"),
  referralAttribution: document.getElementById("referralAttribution"),
  copyReferralButton: document.getElementById("copyReferralButton"),
  shareReferralButton: document.getElementById("shareReferralButton"),
  demoReferralButton: document.getElementById("demoReferralButton"),
  tierOneCard: document.getElementById("tierOneCard"),
  tierTwoCard: document.getElementById("tierTwoCard"),
  tierThreeCard: document.getElementById("tierThreeCard")
};

let lastAnalysis = null;
let scanCount = Number(document.getElementById("scanProgressValue")?.getAttribute("data-backend-count") || "0");

function isUrlLike(value) {
  return /^https?:\/\//i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(value);
}

function normalizeUrl(raw) {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Paste a URL to analyze.");
  if (!/^https?:\/\//i.test(trimmed)) return new URL(`https://${trimmed}`);
  return new URL(trimmed);
}

function decodeIfNeeded(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

function buildRedirectChain(urlString) {
  const redirects = [urlString];
  if (urlString.includes("bit.ly")) {
    redirects.push("https://offer-checkpoint.net/landing");
    redirects.push("https://secure-apple-support.help/check");
  } else if (urlString.includes("me-qr.com") || urlString.includes("qrco.de") || urlString.includes("qrs.ly")) {
    redirects.push("https://shared-docs-captcha.top/verify-human");
    redirects.push("https://cdnimg.jeayacrai.in.net/outlook-session-check");
  } else if (urlString.includes("verify-account-example.net")) {
    redirects.push("https://verify-account-example.net/continue");
    redirects.push("https://evil.example/credential-harvest");
  } else if (urlString.includes("update-app")) {
    redirects.push("http://download-secure-update.top/payload/start");
    redirects.push("http://cdn-secure-package.top/app-release.apk");
  } else if (urlString.includes("pay-parking-now-secure.top")) {
    redirects.push("https://pay-parking-now-secure.top/session");
    redirects.push("https://pay-parking-now-secure.top/card-entry");
  } else {
    redirects.push(urlString);
  }
  return redirects;
}

function detectPayload(rawValue) {
  const raw = rawValue.trim();
  const upper = raw.toUpperCase();

  if (!raw) throw new Error("Paste decoded QR text to analyze.");
  if (isUrlLike(raw)) return { type: "URL", action: "Open website", normalized: normalizeUrl(raw).toString() };
  if (upper.startsWith("WIFI:")) return { type: "Wi-Fi", action: "Join Wi-Fi network", normalized: raw };
  if (upper.includes("BEGIN:VCARD")) return { type: "Contact card", action: "Import contact", normalized: raw };
  if (upper.startsWith("SMSTO:") || upper.startsWith("SMS:")) return { type: "SMS", action: "Open prefilled text message", normalized: raw };
  if (upper.startsWith("MAILTO:")) return { type: "Email", action: "Open prefilled email", normalized: raw };
  if (upper.startsWith("SOLANA:") || upper.startsWith("BITCOIN:") || upper.startsWith("ETHEREUM:")) return { type: "Crypto/payment", action: "Open wallet or payment request", normalized: raw };
  if (upper.startsWith("BEGIN:VEVENT") || upper.includes("BEGIN:VCALENDAR")) return { type: "Calendar", action: "Add calendar event", normalized: raw };

  try {
    JSON.parse(raw);
    return { type: "JSON/custom", action: "Run app-specific data flow", normalized: raw };
  } catch {
    return { type: "Plain text", action: "Display text payload", normalized: raw };
  }
}

function analyzeUrl(rawValue) {
  const parsed = normalizeUrl(rawValue);
  const urlString = parsed.toString();
  const lowerUrl = urlString.toLowerCase();
  const decodedPath = decodeIfNeeded(`${parsed.pathname}${parsed.search}`);
  const reasons = [];
  const tags = [];
  let score = 0;
  let threatClass = "Low-risk web destination";

  if (parsed.hostname.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
    score += 30;
    reasons.push("The QR code points to a raw IP address instead of a recognizable domain.");
    tags.push("IP host");
  }

  const suspiciousTlds = [".zip", ".top", ".click", ".shop", ".help"];
  if (suspiciousTlds.some((tld) => parsed.hostname.endsWith(tld))) {
    score += 18;
    reasons.push("The destination uses a high-risk top-level domain that is often abused.");
    tags.push("Suspicious TLD");
  }

  const knownShorteners = ["bit.ly", "tinyurl", "t.co", "qrco.de", "me-qr.com", "qrs.ly"];
  if (knownShorteners.some((domain) => parsed.hostname.includes(domain))) {
    score += 22;
    reasons.push("The link uses a shortener, which hides the real destination.");
    tags.push("Shortener");
  }

  if (decodedPath !== `${parsed.pathname}${parsed.search}`) {
    score += 12;
    reasons.push("The URL contains encoded characters that can hide the true destination.");
    tags.push("Encoded URL");
  }

  if (/[I1l]{2,}/.test(parsed.hostname) || parsed.hostname.includes("paypaI")) {
    score += 34;
    reasons.push("The domain looks like a brand impersonation attempt or a lookalike typo.");
    tags.push("Lookalike domain");
  }

  if (parsed.search.includes("redirect=")) {
    score += 14;
    reasons.push("The URL contains a redirect parameter, which can conceal the final destination.");
    tags.push("Redirect parameter");
  }

  if (parsed.username || parsed.password) {
    score += 28;
    reasons.push("The URL contains embedded credentials, which is a classic phishing trick.");
    tags.push("Embedded credentials");
  }

  if (parsed.protocol !== "https:") {
    score += 20;
    reasons.push("The destination is not using HTTPS, so the connection is less trustworthy.");
    tags.push("No HTTPS");
  }

  if ((parsed.hostname.match(/-/g) || []).length >= 3) {
    score += 10;
    reasons.push("The hostname uses many hyphens, which is common in throwaway phishing domains.");
    tags.push("Hyphen-heavy host");
  }

  const fileShareIndicators = ["drive", "shared", "cdn", "files", "docs", "download"];
  if (fileShareIndicators.filter((keyword) => lowerUrl.includes(keyword)).length >= 2) {
    score += 14;
    reasons.push("The destination looks like a file-sharing or CDN-style flow, which is commonly abused for malware and phishing chains.");
    tags.push("File-sharing chain");
  }

  const captchaIndicators = ["captcha", "verify-human", "robot", "recaptcha"];
  if (captchaIndicators.some((keyword) => lowerUrl.includes(keyword))) {
    score += 14;
    reasons.push("The redirect chain includes CAPTCHA-style gating, which attackers often use to make malicious flows look legitimate.");
    tags.push("CAPTCHA gate");
  }

  const phishingKeywords = ["verify", "secure", "login", "account", "update", "wallet", "password"];
  const keywordHits = phishingKeywords.filter((keyword) => lowerUrl.includes(keyword));
  if (keywordHits.length >= 3) {
    score += 18;
    reasons.push("The URL combines several urgency or account-related keywords often seen in phishing attacks.");
    tags.push("Phishing keywords");
  }

  const malwareKeywords = ["apk", "download", "installer", "update-app", "payload"];
  const malwareHits = malwareKeywords.filter((keyword) => lowerUrl.includes(keyword));
  if (malwareHits.length >= 2) {
    score += 20;
    reasons.push("The URL looks like it may be pushing a download or payload delivery flow.");
    tags.push("Malware delivery");
  }

  const contextKeywords = ["parking", "meter", "menu", "restaurant", "atm", "crypto"];
  if (contextKeywords.some((keyword) => lowerUrl.includes(keyword))) {
    score += 10;
    reasons.push("This looks like a high-risk public QR context such as parking, menus, or payment flows where physical tampering is common.");
    tags.push("Quishing context");
  }

  const calendarContactKeywords = ["vcard", "contact", "calendar", "invite", "ics"];
  if (calendarContactKeywords.some((keyword) => lowerUrl.includes(keyword))) {
    score += 14;
    reasons.push("The payload appears to involve contact or calendar content, which can hide malicious URLs or unsafe downloads.");
    tags.push("Contact/calendar payload");
  }

  const redirects = buildRedirectChain(urlString);
  if (redirects.length > 2) {
    score += 12;
    reasons.push("The scan leads through multiple redirects before reaching the final page.");
    tags.push("Multi-hop redirect");
  }

  if (parsed.hostname.endsWith("apple.com") || parsed.hostname.endsWith("microsoft.com")) {
    score -= 18;
    reasons.push("The destination matches a well-known domain with a lower apparent risk profile.");
    tags.push("Trusted brand");
  }

  if (reasons.length === 0) {
    reasons.push("No obvious phishing or malware signals were detected in this demo analysis.");
    tags.push("No major signals");
  }

  let verdict = "Safe";
  if (score >= 65) verdict = "Dangerous";
  else if (score >= 35) verdict = "Caution";

  if (tags.includes("Malware delivery") || tags.includes("File-sharing chain")) {
    threatClass = "Possible malware delivery";
  } else if (tags.includes("Lookalike domain") || tags.includes("Embedded credentials") || tags.includes("Phishing keywords")) {
    threatClass = "Likely phishing attempt";
  } else if (verdict === "Safe") {
    threatClass = "Low-risk web destination";
  } else {
    threatClass = "Suspicious web destination";
  }

  return {
    verdict,
    score,
    urlString,
    redirects,
    reasons,
    tags,
    threatClass,
    canAutoContinue: verdict === "Safe",
    recommendedAction: verdict === "Safe"
      ? "No suspicious signals were found in the demo analysis. You can continue to the destination."
      : "Do not auto-open this QR destination. Review the reasons carefully and only continue if you trust the source."
  };
}

function analyzePayload(rawValue) {
  const payload = detectPayload(rawValue);
  if (payload.type === "URL") return analyzeUrl(payload.normalized);

  const lowerPayload = payload.normalized.toLowerCase();
  const reasons = [];
  const tags = [payload.type];
  const actions = [payload.action, payload.normalized];
  let score = 0;
  let threatClass = `${payload.type} payload`;

  if (payload.type === "Wi-Fi") {
    score += 16;
    reasons.push("The QR code attempts to join a Wi-Fi network, which can route traffic through an untrusted network.");
    tags.push("Network join");
    if (lowerPayload.includes("nopass") || lowerPayload.includes("t:;")) {
      score += 14;
      reasons.push("The Wi-Fi payload appears to use no password or an unclear security type.");
      tags.push("Open network");
    }
  }

  if (payload.type === "Contact card") {
    score += 12;
    reasons.push("The QR code tries to add contact details. Contact cards can hide links, phone numbers, or impersonated support identities.");
    tags.push("Contact import");
  }

  if (payload.type === "SMS" || payload.type === "Email") {
    score += 18;
    reasons.push("The QR code opens a prefilled message, which can trick users into sending sensitive information or subscribing to unwanted messages.");
    tags.push("Prefilled message");
  }

  if (payload.type === "Crypto/payment") {
    score += 32;
    reasons.push("The QR code opens a wallet or payment request. Any transfer should require manual review before approval.");
    tags.push("Payment request");
  }

  if (payload.type === "Calendar") {
    score += 14;
    reasons.push("Calendar invites can hide URLs, reminders, or social-engineering instructions.");
    tags.push("Calendar import");
  }

  if (payload.type === "JSON/custom") {
    score += 18;
    reasons.push("The QR code contains app-specific structured data. SafeScan should show the fields before any app acts on them.");
    tags.push("Structured payload");
  }

  if (payload.type === "Plain text") {
    reasons.push("The QR code contains plain text and does not directly request a browser, wallet, message, contact, calendar, or Wi-Fi action.");
    tags.push("No direct action");
  }

  const embeddedUrls = payload.normalized.match(/https?:\/\/[^\s"<>]+/gi) || [];
  embeddedUrls.forEach((url) => {
    const urlResult = analyzeUrl(url);
    score += Math.min(urlResult.score, 45);
    reasons.push(`Embedded link found: ${url}`);
    reasons.push(...urlResult.reasons.slice(0, 2));
    tags.push(...urlResult.tags.slice(0, 3));
    actions.push(`Embedded link: ${url}`);
    if (urlResult.threatClass !== "Low-risk web destination") threatClass = urlResult.threatClass;
  });

  const sensitiveWords = ["password", "verify", "login", "wallet", "seed", "recovery", "bank", "urgent"];
  const sensitiveHits = sensitiveWords.filter((word) => lowerPayload.includes(word));
  if (sensitiveHits.length >= 2) {
    score += 18;
    reasons.push("The payload includes urgency, credential, payment, or wallet language commonly used in social engineering.");
    tags.push("Social engineering text");
  }

  const uniqueTags = [...new Set(tags)];
  const verdict = score >= 65 ? "Dangerous" : score >= 35 ? "Caution" : "Safe";
  const canAutoContinue = verdict === "Safe" && ["Plain text"].includes(payload.type);

  return {
    verdict,
    score,
    urlString: payload.normalized,
    redirects: actions,
    reasons,
    tags: uniqueTags,
    threatClass,
    canAutoContinue,
    recommendedAction: canAutoContinue
      ? "This payload does not request a sensitive action. You can view it safely."
      : "Pause before continuing. Review the decoded payload and only proceed if you trust the source and action."
  };
}

function renderList(listElement, values) {
  listElement.innerHTML = "";
  values.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    listElement.appendChild(item);
  });
}

function renderTags(tags) {
  dom.threatTags.innerHTML = "";
  tags.forEach((tag) => {
    const chip = document.createElement("span");
    chip.className = "threat-tag";
    chip.textContent = tag;
    dom.threatTags.appendChild(chip);
  });
}

function renderAnalysis(result) {
  lastAnalysis = result;
  dom.resultsSection.classList.remove("hidden");
  dom.resultTitle.textContent = result.verdict === "Safe" ? "Low-risk result" : `${result.verdict} result`;
  dom.verdictBadge.textContent = result.verdict;
  dom.verdictBadge.className = "verdict-badge";
  dom.verdictBadge.classList.add(
    result.verdict === "Safe" ? "verdict-safe" : result.verdict === "Caution" ? "verdict-caution" : "verdict-dangerous"
  );

  dom.finalUrl.textContent = result.urlString;
  dom.actionText.textContent = result.canAutoContinue
    ? "Decoded action: low-risk payload. This can be continued from the same screen."
    : "Decoded action: sensitive or external action. Manual review is recommended before continuing.";

  renderTags(result.tags);
  renderList(dom.redirectChain, result.redirects);
  renderList(dom.riskReasons, result.reasons);
  renderList(dom.signalList, result.reasons.slice(0, 3));
  dom.scoreValue.textContent = String(Math.max(result.score, 0));
  dom.actionGate.textContent = result.canAutoContinue
    ? "Eligible for low-risk continuation. If safe mode is enabled, the app can move forward without rescanning."
    : "Manual approval required. The app should pause and explain the risk before any action executes.";
  dom.threatClass.textContent = result.threatClass;

  dom.recommendedAction.textContent = result.recommendedAction;
  dom.continueButton.textContent = result.canAutoContinue && dom.autoContinueToggle?.checked
    ? "Auto-continue triggered"
    : "Continue safely";

  if (result.canAutoContinue && dom.autoContinueToggle?.checked) {
    dom.recommendedAction.textContent = "Safe mode is enabled, so the app would continue automatically without a second scan.";
  }
}

function getAirdropTier() {
  const profile = getStoredAirdropProfile();
  const referralCount = profile?.referralCount || 0;

  if (referralCount >= 3 && scanCount >= 50) {
    return {
      name: "Tier 3: Guardian",
      description: "5x allocation unlocked with multiple referrals and 50 QR scans."
    };
  }

  if (referralCount >= 1) {
    return {
      name: "Tier 2: Referrer",
      description: "2x allocation unlocked after your first referral."
    };
  }

  if (profile && scanCount >= 5) {
    return {
      name: "Tier 1: Scanner",
      description: "Base allocation unlocked after account creation and 5 QR scans."
    };
  }

  if (profile) {
    return {
      name: "Registered",
      description: "Scan 5 QR codes to unlock Tier 1."
    };
  }

  return {
    name: "Not registered",
    description: "Sign in to start earning airdrop progress."
  };
}

function getReferralCode(profile) {
  const source = profile.googleSubject || profile.email || "safescan-user";
  let hash = 0;
  for (let index = 0; index < source.length; index += 1) {
    hash = ((hash << 5) - hash + source.charCodeAt(index)) | 0;
  }
  return `SAFE-${Math.abs(hash).toString(36).toUpperCase()}`;
}

function buildReferralLink(profile) {
  const url = new URL(PUBLIC_SITE_URL);
  url.searchParams.set("ref", profile.referralCode || getReferralCode(profile));
  url.hash = "airdrop";
  return url.toString();
}

function captureIncomingReferral() {
  const params = new URLSearchParams(window.location.search);
  const referralCode = params.get("ref")?.trim();
  if (referralCode) window.localStorage.setItem(REFERRAL_STORAGE_KEY, referralCode);
  return referralCode || window.localStorage.getItem(REFERRAL_STORAGE_KEY);
}

function getReferralAttributions() {
  try {
    return JSON.parse(window.localStorage.getItem(REFERRAL_ATTRIBUTIONS_STORAGE_KEY)) || [];
  } catch {
    return [];
  }
}

function saveReferralAttribution(profile) {
  if (!profile.referredBy) return;

  const attributions = getReferralAttributions();
  const alreadySaved = attributions.some((item) => item.referredEmail === profile.email);
  if (alreadySaved) return;

  attributions.push({
    referrerCode: profile.referredBy,
    referredEmail: profile.email,
    referredName: profile.name,
    referredGoogleSubject: profile.googleSubject,
    referredAt: profile.registeredAt
  });
  window.localStorage.setItem(REFERRAL_ATTRIBUTIONS_STORAGE_KEY, JSON.stringify(attributions));
}

function decodeJwtPayload(token) {
  const [, payload] = token.split(".");
  if (!payload) throw new Error("Google sign-in did not return a valid credential.");
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(window.atob(normalized));
}

function getStoredAirdropProfile() {
  try {
    return JSON.parse(window.localStorage.getItem(AIRDROP_STORAGE_KEY));
  } catch {
    return null;
  }
}

async function saveAirdropProfile(profile) {
  window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(profile));
  saveReferralAttribution(profile);

  if (!AIRDROP_REGISTER_ENDPOINT) return;

  await fetch(AIRDROP_REGISTER_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...profile,
      accountLink: {
        email: profile.email,
        googleSubject: profile.googleSubject,
        walletAddress: profile.walletAddress || null,
        walletProvider: profile.walletProvider || null
      },
      referralCredit: profile.referredBy
        ? {
            creditToReferralCode: profile.referredBy,
            creditedByEmail: profile.email,
            creditedByGoogleSubject: profile.googleSubject,
            creditedAt: profile.registeredAt
          }
        : null,
      referralAttribution: profile.referredBy
        ? {
            referrerCode: profile.referredBy,
            referredEmail: profile.email,
            referredGoogleSubject: profile.googleSubject
          }
        : null
    })
  });
}

function renderAirdropProfile(profile) {
  if (!profile) {
    dom.airdropStatus?.classList.remove("signed-in");
    if (dom.airdropStatus) dom.airdropStatus.textContent = "Not signed in";
    dom.airdropProfile?.classList.add("hidden");
    dom.googleSignInButton?.classList.remove("hidden");
    updateAirdropProgress();
    return;
  }

  const tier = getAirdropTier();
  if (dom.airdropStatus) dom.airdropStatus.textContent = "Registered";
  dom.airdropStatus?.classList.add("signed-in");
  dom.airdropProfile?.classList.remove("hidden");
  dom.googleSignInButton?.classList.add("hidden");
  dom.demoGoogleButton?.classList.remove("is-visible");
  if (dom.profileName) dom.profileName.textContent = `Name: ${profile.name}`;
  if (dom.profileEmail) dom.profileEmail.textContent = `Email: ${profile.email}`;
  if (dom.profileTier) dom.profileTier.textContent = tier.name;
  
  renderWalletState(profile);
  updateAirdropProgress();
}

function renderWalletState(profile = getStoredAirdropProfile()) {
  if (!profile || !profile.walletAddress) {
    if (dom.walletStatus) dom.walletStatus.textContent = "Sign in to unlock wallet connection.";
    if (dom.connectWalletButton) dom.connectWalletButton.textContent = "Connect wallet";
    if (dom.topConnectWalletButton) dom.topConnectWalletButton.textContent = "Connect wallet";
    if (dom.connectWalletButton) dom.connectWalletButton.classList.remove("hidden");
    if (dom.topConnectWalletButton) dom.topConnectWalletButton.classList.remove("hidden");
    if (dom.disconnectWalletButton) dom.disconnectWalletButton.classList.add("hidden");
    if (dom.connectWalletButton) dom.connectWalletButton.disabled = false;
    if (dom.topConnectWalletButton) dom.topConnectWalletButton.disabled = false;
    if (dom.demoWalletButton) dom.demoWalletButton.disabled = false;
    return;
  }

  if (dom.walletStatus) dom.walletStatus.textContent = `Connected: ${profile.walletAddress}`;
  if (dom.connectWalletButton) dom.connectWalletButton.classList.add("hidden");
  if (dom.topConnectWalletButton) dom.topConnectWalletButton.classList.add("hidden");
  if (dom.disconnectWalletButton) dom.disconnectWalletButton.classList.remove("hidden");
  if (dom.demoWalletButton) dom.demoWalletButton.disabled = true;
}

async function attachWalletToProfile(walletAddress, provider = "solana") {
  const profile = getStoredAirdropProfile();
  if (!profile) {
    window.alert("Sign in with Google before connecting a wallet.");
    return;
  }

  const updatedProfile = {
    ...profile,
    walletAddress,
    walletProvider: provider,
    walletConnectedAt: new Date().toISOString()
  };

  await saveAirdropProfile(updatedProfile);
  renderAirdropProfile(updatedProfile);
}

function getSolanaWalletProvider() {
  const providers = [];
  if (window.phantom?.solana) providers.push({ name: "phantom", provider: window.phantom.solana });
  if (window.solflare) providers.push({ name: "solflare", provider: window.solflare });
  if (window.braveSolana) providers.push({ name: "brave", provider: window.braveSolana });
  if (window.solana) {
    const providerName = window.solana.isPhantom
      ? "phantom"
      : window.solana.isSolflare
        ? "solflare"
        : window.solana.isBraveWallet
          ? "brave"
          : "solana";
    providers.push({ name: providerName, provider: window.solana });
  }

  return providers.find(({ provider }) => provider?.connect) || null;
}

function updateAirdropProgress() {
  const profile = getStoredAirdropProfile();
  const tier = getAirdropTier();
  const referralCount = profile?.referralCount || 0;
  const incomingReferral = captureIncomingReferral();
  const tierCards = [dom.tierOneCard, dom.tierTwoCard, dom.tierThreeCard];
  const unlocked = [
    Boolean(profile && scanCount >= 5),
    referralCount >= 1,
    referralCount >= 3 && scanCount >= 50
  ];

  if (dom.currentTierName) dom.currentTierName.textContent = tier.name;
  if (dom.currentTierSummary) dom.currentTierSummary.textContent = tier.description;
  if (dom.scanProgressValue) dom.scanProgressValue.textContent = `${scanCount} / ${scanCount >= 50 ? 50 : 5}`;
  if (dom.referralProgressValue) dom.referralProgressValue.textContent = String(referralCount);

  tierCards.forEach((card, index) => {
    card?.classList.toggle("unlocked", unlocked[index]);
    card?.classList.remove("current");
  });

  if (tier.name.includes("Tier 3")) dom.tierThreeCard?.classList.add("current");
  else if (tier.name.includes("Tier 2")) dom.tierTwoCard?.classList.add("current");
  else if (tier.name.includes("Tier 1")) dom.tierOneCard?.classList.add("current");

  if (profile) {
    const referralCode = profile.referralCode || getReferralCode(profile);
    const updatedProfile = { ...profile, referralCode, tier: tier.name, tierDescription: tier.description };
    window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(updatedProfile));
    if (dom.referralLink) dom.referralLink.textContent = "Your referral link is ready. Copy it with one click.";
    if (dom.topCopyReferralButton) dom.topCopyReferralButton.textContent = "Referral link";

    if (updatedProfile.referredBy) {
      dom.referralAttribution?.classList.remove("hidden");
      if (dom.referralAttribution) dom.referralAttribution.textContent = `This account was referred by ${updatedProfile.referredBy}.`;
    } else {
      dom.referralAttribution?.classList.add("hidden");
    }
  } else {
    if (dom.referralLink) dom.referralLink.textContent = "Sign in to unlock your referral link.";
    if (dom.topCopyReferralButton) dom.topCopyReferralButton.textContent = "Referral link";
    dom.referralAttribution?.classList.add("hidden");
  }

  if (incomingReferral) {
    dom.incomingReferral?.classList.remove("hidden");
    if (dom.incomingReferral) dom.incomingReferral.textContent = `Referral detected: ${incomingReferral}. If this user signs in, that referrer code is saved with their account.`;
  }
}

async function connectWallet() {
  const profile = getStoredAirdropProfile();
  if (!profile) {
    window.alert("Sign in with Google before connecting a wallet.");
    return;
  }

  const detectedWallet = getSolanaWalletProvider();
  if (!detectedWallet) {
    window.alert("No Phantom, Solflare, or Brave Solana wallet was detected. Install a wallet or use the demo wallet for local testing.");
    return;
  }

  try {
    const response = await detectedWallet.provider.connect();
    const publicKey = response?.publicKey || detectedWallet.provider.publicKey;
    await attachWalletToProfile(publicKey.toString(), detectedWallet.name);
  } catch {
    window.alert("Wallet connection was cancelled or failed.");
  }
}

async function copyReferralLink(button = dom.copyReferralButton) {
  const profile = getStoredAirdropProfile();
  if (!profile) {
    window.alert("Sign in first to generate your referral link.");
    return;
  }

  try {
    await navigator.clipboard.writeText(buildReferralLink(profile));
    const defaultText = button === dom.topCopyReferralButton ? "Referral link" : "Copy referral link";
    if (button) button.textContent = "Copied link";
    setTimeout(() => { if (button) button.textContent = defaultText; }, 1200);
  } catch {
    window.alert("Clipboard copy failed in this browser.");
  }
}

async function registerAirdropUser(googleProfile) {
  if (!googleProfile.email) {
    window.alert("Google sign-in did not return an email address.");
    return;
  }

  const tier = getAirdropTier();
  const incomingReferral = captureIncomingReferral();
  const referralCode = getReferralCode(googleProfile);
  const referredBy = incomingReferral && incomingReferral !== referralCode ? incomingReferral : null;
  const profile = {
    email: googleProfile.email,
    name: googleProfile.name || googleProfile.email,
    googleSubject: googleProfile.sub || "demo-google-user",
    referralCode,
    referralCount: 0,
    referredBy,
    tier: tier.name,
    tierDescription: tier.description,
    registeredAt: new Date().toISOString()
  };

  try {
    await saveAirdropProfile(profile);
    renderAirdropProfile(profile);
  } catch {
    window.alert("Registration could not reach the database endpoint. The profile was saved locally for this demo.");
    renderAirdropProfile(profile);
  }
}

function handleGoogleCredential(response) {
  try {
    const googleProfile = decodeJwtPayload(response.credential);
    registerAirdropUser(googleProfile);
  } catch (error) {
    window.alert(error.message);
  }
}

function openDemoAccountChooser() {
  dom.demoAccountModal?.classList.remove("hidden");
  dom.demoAccountModal?.setAttribute("aria-hidden", "false");
}

function closeDemoAccountChooser() {
  dom.demoAccountModal?.classList.add("hidden");
  dom.demoAccountModal?.setAttribute("aria-hidden", "true");
}

function initGoogleSignIn() {
  if (getStoredAirdropProfile()) return;

  const hasRealClientId = GOOGLE_CLIENT_ID && !GOOGLE_CLIENT_ID.includes("PASTE_YOUR");

  if (!hasRealClientId) {
    dom.demoGoogleButton?.classList.add("is-visible");
    return;
  }

  if (!window.google?.accounts?.id) {
    googleInitAttempts += 1;
    if (googleInitAttempts < 8) {
      window.setTimeout(initGoogleSignIn, 300);
      return;
    }
    dom.demoGoogleButton?.classList.add("is-visible");
    return;
  }

  window.google.accounts.id.initialize({
    client_id: GOOGLE_CLIENT_ID,
    callback: handleGoogleCredential,
    cancel_on_tap_outside: true,
    use_fedcm_for_prompt: true
  });

  window.google.accounts.id.renderButton(dom.googleSignInButton, {
    theme: "filled_black",
    size: "large",
    shape: "rectangular",
    text: "signin_with",
    logo_alignment: "left",
    width: 240
  });

  window.google.accounts.id.prompt((notification) => {
    if (notification.isNotDisplayed?.() || notification.isSkippedMoment?.()) {
      dom.googleSignInButton?.classList.remove("hidden");
    }
  });
}

function recordScan() {
  // The Python backend handles the real math and duplicate blocking now.
  updateAirdropProgress();
}

function runAnalysis({ countScan = true } = {}) {
  try {
    if (dom.scanStatus) dom.scanStatus.textContent = "QR decoded. Classifying payload and running risk checks.";
    const result = analyzePayload(dom.urlInput.value);
    if (countScan) recordScan();
    renderAnalysis(result);
    window.requestAnimationFrame(() => {
      dom.resultsSection?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  } catch (error) {
    window.alert(error.message);
  }
}

// --------------------------------------------------------
// SAFE EVENT LISTENERS (Optional Chaining)
// --------------------------------------------------------

dom.analyzeButton?.addEventListener("click", runAnalysis);

dom.clearButton?.addEventListener("click", () => {
  if (dom.urlInput) dom.urlInput.value = "";
  dom.resultsSection?.classList.add("hidden");
  dom.uploadPreview?.classList.add("hidden");
  dom.previewImage?.removeAttribute("src");
  if (dom.scanStatus) dom.scanStatus.textContent = "Waiting for a scan or pasted QR payload.";
  lastAnalysis = null;
});

dom.sampleButtons?.forEach((button) => {
  button.addEventListener("click", () => {
    if (dom.urlInput) dom.urlInput.value = sampleUrls[button.dataset.sample];
    runAnalysis({ countScan: false });
  });
});

dom.simulateScanButton?.addEventListener("click", () => {
  if (dom.scanStatus) dom.scanStatus.textContent = "Mobile camera locked onto QR code. Decoding payload...";
  dom.qrFrame?.classList.add("scanning");
  if (dom.urlInput) dom.urlInput.value = sampleUrls.safe;
  window.setTimeout(() => {
    if (dom.scanStatus) dom.scanStatus.textContent = "QR payload found. Preparing safety analysis.";
    dom.qrFrame?.classList.remove("scanning");
    runAnalysis({ countScan: false });
  }, 1400);
});

dom.qrImageInput?.addEventListener("change", (event) => {
  const [file] = event.target.files || [];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    if(dom.previewImage) dom.previewImage.src = reader.result;
    dom.uploadPreview?.classList.remove("hidden");
    if(dom.scanStatus) dom.scanStatus.textContent = "Camera or photo input received. On a mobile device, the full product would decode the QR directly from this capture flow.";
  };
  reader.readAsDataURL(file);
});

dom.copyButton?.addEventListener("click", async () => {
  if (!lastAnalysis) return;
  try {
    await navigator.clipboard.writeText(lastAnalysis.urlString);
    if (dom.copyButton) dom.copyButton.textContent = "Copied";
    setTimeout(() => { if (dom.copyButton) dom.copyButton.textContent = "Copy payload"; }, 1200);
  } catch {
    window.alert("Clipboard copy failed in this browser.");
  }
});

dom.copyTokenAddressButton?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(dom.tokenAddress?.textContent || "");
    if (dom.copyTokenAddressButton) dom.copyTokenAddressButton.textContent = "Copied";
    setTimeout(() => { if (dom.copyTokenAddressButton) dom.copyTokenAddressButton.textContent = "Copy"; }, 1200);
  } catch {
    window.alert("Clipboard copy failed in this browser.");
  }
});

dom.continueButton?.addEventListener("click", () => {
  if (!lastAnalysis) return;
  if (!lastAnalysis.canAutoContinue) {
    window.alert("In the real app, sensitive QR payloads would require explicit confirmation before any action runs.");
    return;
  }
  window.alert(`Demo action: continue with ${lastAnalysis.urlString}`);
});

dom.demoGoogleButton?.addEventListener("click", () => {
  openDemoAccountChooser();
});

dom.accountOptions?.forEach((button) => {
  button.addEventListener("click", () => {
    closeDemoAccountChooser();
    registerAirdropUser({
      email: button.dataset.demoEmail,
      name: button.dataset.demoName,
      sub: `demo-${button.dataset.demoEmail}`
    });
  });
});

dom.closeAccountModal?.addEventListener("click", closeDemoAccountChooser);

dom.demoAccountModal?.addEventListener("click", (event) => {
  if (event.target === dom.demoAccountModal) closeDemoAccountChooser();
});

dom.signOutButton?.addEventListener("click", () => {
  window.localStorage.removeItem(AIRDROP_STORAGE_KEY);
  renderAirdropProfile(null);
  renderWalletState(null);
  initGoogleSignIn();
});

dom.topConnectWalletButton?.addEventListener("click", connectWallet);
dom.connectWalletButton?.addEventListener("click", connectWallet);

dom.disconnectWalletButton?.addEventListener("click", async () => {
  const profile = getStoredAirdropProfile();
  if (!profile) return;

  // Clear the wallet data from the profile
  const updatedProfile = { ...profile };
  delete updatedProfile.walletAddress;
  delete updatedProfile.walletProvider;

  await saveAirdropProfile(updatedProfile);
  renderAirdropProfile(updatedProfile);
  window.alert("Wallet disconnected. You can now connect a different wallet.");
});

dom.demoWalletButton?.addEventListener("click", () => {
  attachWalletToProfile("DemoSQRWallet11111111111111111111111111111", "demo");
});

dom.topCopyReferralButton?.addEventListener("click", () => copyReferralLink(dom.topCopyReferralButton));
dom.copyReferralButton?.addEventListener("click", () => copyReferralLink(dom.copyReferralButton));

dom.shareReferralButton?.addEventListener("click", async () => {
  const profile = getStoredAirdropProfile();
  if (!profile) {
    window.alert("Sign in first to share your referral link.");
    return;
  }

  const referralLink = buildReferralLink(profile);
  if (navigator.share) {
    await navigator.share({
      title: "Join the SafeScan QR airdrop",
      text: "Register for SafeScan QR and start earning airdrop tiers.",
      url: referralLink
    });
    return;
  }

  await navigator.clipboard.writeText(referralLink);
  window.alert("Referral link copied.");
});

dom.demoReferralButton?.addEventListener("click", () => {
  const profile = getStoredAirdropProfile();
  if (!profile) {
    window.alert("Sign in first to track referrals.");
    return;
  }

  const updatedProfile = {
    ...profile,
    referralCount: (profile.referralCount || 0) + 1
  };
  window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(updatedProfile));
  renderAirdropProfile(updatedProfile);
});

captureIncomingReferral();
renderAirdropProfile(getStoredAirdropProfile());
window.addEventListener("load", initGoogleSignIn);
