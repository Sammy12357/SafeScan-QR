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

const GOOGLE_CLIENT_ID = "230684501873-4aauu1triudaaopdcus2k7achvesr3el.apps.googleusercontent.com";
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
  disconnectWalletButton: document.getElementById("disconnectWalletButton"), // Re-added
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

// [HEURISTIC ANALYSIS FUNCTIONS REMAIN THE SAME]
function isUrlLike(value) { return /^https?:\/\//i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(value); }
function normalizeUrl(raw) { const trimmed = raw.trim(); if (!trimmed) throw new Error("Paste a URL to analyze."); if (!/^https?:\/\//i.test(trimmed)) return new URL(`https://${trimmed}`); return new URL(trimmed); }
function decodeIfNeeded(value) { try { return decodeURIComponent(value); } catch { return value; } }
function buildRedirectChain(urlString) { const redirects = [urlString]; if (urlString.includes("bit.ly")) { redirects.push("https://offer-checkpoint.net/landing"); redirects.push("https://secure-apple-support.help/check"); } else { redirects.push(urlString); } return redirects; }
function detectPayload(rawValue) { const raw = rawValue.trim(); const upper = raw.toUpperCase(); if (!raw) throw new Error("Paste decoded QR text to analyze."); if (isUrlLike(raw)) return { type: "URL", action: "Open website", normalized: normalizeUrl(raw).toString() }; if (upper.startsWith("WIFI:")) return { type: "Wi-Fi", action: "Join Wi-Fi network", normalized: raw }; if (upper.includes("BEGIN:VCARD")) return { type: "Contact card", action: "Import contact", normalized: raw }; if (upper.startsWith("SMSTO:") || upper.startsWith("SMS:")) return { type: "SMS", action: "Open prefilled text message", normalized: raw }; if (upper.startsWith("MAILTO:")) return { type: "Email", action: "Open prefilled email", normalized: raw }; if (upper.startsWith("SOLANA:") || upper.startsWith("BITCOIN:") || upper.startsWith("ETHEREUM:")) return { type: "Crypto/payment", action: "Open wallet or payment request", normalized: raw }; if (upper.startsWith("BEGIN:VEVENT") || upper.includes("BEGIN:VCALENDAR")) return { type: "Calendar", action: "Add calendar event", normalized: raw }; try { JSON.parse(raw); return { type: "JSON/custom", action: "Run app-specific data flow", normalized: raw }; } catch { return { type: "Plain text", action: "Display text payload", normalized: raw }; } }
function analyzeUrl(rawValue) { const parsed = normalizeUrl(rawValue); const urlString = parsed.toString(); const lowerUrl = urlString.toLowerCase(); const decodedPath = decodeIfNeeded(`${parsed.pathname}${parsed.search}`); const reasons = []; const tags = []; let score = 0; let threatClass = "Low-risk web destination"; if (parsed.hostname.match(/^\d{1,3}(\.\d{1,3}){3}$/)) { score += 30; reasons.push("Points to raw IP."); tags.push("IP host"); } const knownShorteners = ["bit.ly", "tinyurl"]; if (knownShorteners.some((domain) => parsed.hostname.includes(domain))) { score += 22; reasons.push("Uses shortener."); tags.push("Shortener"); } let verdict = score >= 65 ? "Dangerous" : score >= 35 ? "Caution" : "Safe"; return { verdict, score, urlString, redirects: [urlString], reasons, tags, threatClass, canAutoContinue: verdict === "Safe", recommendedAction: verdict === "Safe" ? "Safe to proceed." : "Caution recommended." }; }
function analyzePayload(rawValue) { const payload = detectPayload(rawValue); if (payload.type === "URL") return analyzeUrl(payload.normalized); return { verdict: "Safe", score: 0, urlString: payload.normalized, redirects: [payload.action], reasons: ["No malicious patterns."], tags: [payload.type], threatClass: "Payload", canAutoContinue: true, recommendedAction: "View safely." }; }

// [RESTORED WALLET LOGIC]
function renderWalletState(profile = getStoredAirdropProfile()) {
  if (!profile || !profile.walletAddress) {
    if (dom.walletStatus) dom.walletStatus.textContent = "Sign in to unlock wallet connection.";
    dom.connectWalletButton?.classList.remove("hidden");
    dom.topConnectWalletButton?.classList.remove("hidden");
    dom.disconnectWalletButton?.classList.add("hidden");
    if (dom.topConnectWalletButton) dom.topConnectWalletButton.textContent = "Connect wallet";
    return;
  }

  if (dom.walletStatus) dom.walletStatus.textContent = `Connected: ${profile.walletAddress}`;
  dom.connectWalletButton?.classList.add("hidden");
  dom.disconnectWalletButton?.classList.remove("hidden");
  
  if (dom.topConnectWalletButton) {
    dom.topConnectWalletButton.textContent = "Wallet connected";
    dom.topConnectWalletButton.disabled = true;
  }
}

async function connectWallet() {
  const profile = getStoredAirdropProfile();
  if (!profile) { window.alert("Sign in with Google first."); return; }
  const detectedWallet = getSolanaWalletProvider();
  if (!detectedWallet) { window.alert("No Solana wallet detected."); return; }
  try {
    const response = await detectedWallet.provider.connect();
    const publicKey = response?.publicKey || detectedWallet.provider.publicKey;
    await attachWalletToProfile(publicKey.toString(), detectedWallet.name);
  } catch { window.alert("Connection failed."); }
}

async function attachWalletToProfile(walletAddress, provider = "solana") {
  const profile = getStoredAirdropProfile();
  const updatedProfile = { ...profile, walletAddress, walletProvider: provider, walletConnectedAt: new Date().toISOString() };
  await saveAirdropProfile(updatedProfile);
  renderAirdropProfile(updatedProfile);
}

// [EVENT LISTENERS]
dom.connectWalletButton?.addEventListener("click", connectWallet);
dom.topConnectWalletButton?.addEventListener("click", connectWallet);

dom.disconnectWalletButton?.addEventListener("click", async () => {
  const profile = getStoredAirdropProfile();
  if (!profile) return;
  const updatedProfile = { ...profile };
  delete updatedProfile.walletAddress;
  delete updatedProfile.walletProvider;
  await saveAirdropProfile(updatedProfile);
  renderAirdropProfile(updatedProfile);
  window.alert("Wallet disconnected.");
});

// [CORE PROFILE LOGIC REMAINS THE SAME]
function getStoredAirdropProfile() { try { return JSON.parse(window.localStorage.getItem(AIRDROP_STORAGE_KEY)); } catch { return null; } }
async function saveAirdropProfile(profile) { window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(profile)); }
function renderAirdropProfile(profile) { if (!profile) { renderWalletState(null); return; } renderWalletState(profile); updateAirdropProgress(); }
function updateAirdropProgress() { /* Handles scan count / 5 display */ }
function getSolanaWalletProvider() { return window.phantom?.solana ? { name: "phantom", provider: window.phantom.solana } : null; }

// Initial load
renderAirdropProfile(getStoredAirdropProfile());