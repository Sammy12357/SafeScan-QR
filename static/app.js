const GOOGLE_CLIENT_ID = "230684501873-4aauu1triudaaopdcus2k7achvesr3el.apps.googleusercontent.com";
const AIRDROP_STORAGE_KEY = "phishproofAirdropProfile";

const dom = {
  hiddenWalletInput: document.getElementById("hiddenWalletInput"),
  deviceFingerprintInput: document.getElementById("deviceFingerprintInput"),
  qrForm: document.getElementById("qrForm"),
  walletStatus: document.getElementById("walletStatus"),
  connectWalletButton: document.getElementById("connectWalletButton"),
  disconnectWalletButton: document.getElementById("disconnectWalletButton"),
  topConnectWalletButton: document.getElementById("topConnectWalletButton"),
  airdropProfile: document.getElementById("airdropProfile"),
  airdropStatus: document.getElementById("airdropStatus"),
  googleSignInButton: document.getElementById("googleSignInButton"),
  demoWalletButton: document.getElementById("demoWalletButton")
};

const splineShowcase = document.querySelector(".spline-showcase");
const splineEmbed = document.getElementById("splineEmbed");
const riskModal = document.getElementById("riskVerdictModal");
const blockReportButton = document.getElementById("blockReportButton");
const continueSafelyButton = document.getElementById("continueSafelyButton");
const reportStatus = document.getElementById("reportStatus");
const analysisLoadingState = document.getElementById("analysisLoadingState");
const cookieConsentBanner = document.getElementById("cookieConsentBanner");
const loadingSteps = [
  "Tracing redirects...",
  "Checking domain age...",
  "Running reputation scan...",
  "Consulting AI analyst..."
];

async function sha256(value) {
  if (!crypto?.subtle) return "";
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function getCanvasFingerprint() {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 160;
    canvas.height = 40;
    const ctx = canvas.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "16px Arial";
    ctx.fillStyle = "#7c3aed";
    ctx.fillText("SafeScan QR", 4, 4);
    return canvas.toDataURL();
  } catch {
    return "canvas-unavailable";
  }
}

async function getDeviceFingerprint() {
  const fingerprint = {
    userAgent: navigator.userAgent,
    language: navigator.language,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screenRes: `${screen.width}x${screen.height}`,
    colorDepth: screen.colorDepth,
    platform: navigator.platform,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory || "",
    canvas: getCanvasFingerprint()
  };
  return sha256(JSON.stringify(fingerprint));
}

let deviceFingerprint = "";
getDeviceFingerprint().then((hash) => {
  deviceFingerprint = hash;
  if (dom.deviceFingerprintInput) dom.deviceFingerprintInput.value = hash;
}).catch(() => {});

const nativeFetch = window.fetch.bind(window);
window.fetch = (input, init = {}) => {
  const headers = new Headers(init.headers || {});
  if (deviceFingerprint) headers.set("X-Device-Fingerprint", deviceFingerprint);
  return nativeFetch(input, { ...init, headers });
};

function hydrateSplineShowcase() {
  const sceneUrl = splineShowcase?.dataset.splineSrc?.trim();
  if (!sceneUrl || !splineEmbed) return;

  const frame = document.createElement("iframe");
  frame.src = sceneUrl;
  frame.title = "Interactive SafeScan QR 3D model";
  frame.loading = "lazy";
  frame.allow = "autoplay; fullscreen; xr-spatial-tracking";
  splineEmbed.replaceChildren(frame);
  splineShowcase?.classList.add("spline-loaded");
}

function getStoredAirdropProfile() { 
  try { return JSON.parse(window.localStorage.getItem(AIRDROP_STORAGE_KEY)); } catch { return null; } 
}

function renderWalletState(profile = getStoredAirdropProfile()) {
  const walletAddr = profile?.walletAddress || "";
  
  // Update hidden field for backend recording
  if (dom.hiddenWalletInput) dom.hiddenWalletInput.value = walletAddr;

  if (!profile || !walletAddr) {
    if (dom.walletStatus) dom.walletStatus.textContent = "Sign in to unlock wallet connection.";
    dom.connectWalletButton?.classList.remove("hidden");
    dom.topConnectWalletButton?.classList.remove("hidden");
    dom.disconnectWalletButton?.classList.add("hidden");
    if (dom.topConnectWalletButton) {
        dom.topConnectWalletButton.textContent = "Connect wallet";
        dom.topConnectWalletButton.disabled = false;
    }
    return;
  }

  if (dom.walletStatus) dom.walletStatus.textContent = `Connected: ${walletAddr}`;
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
  
  const detectedWallet = window.phantom?.solana || window.solana;
  if (!detectedWallet) { window.alert("No Solana wallet detected."); return; }

  try {
    const response = await detectedWallet.connect();
    const publicKey = response?.publicKey || detectedWallet.publicKey;
    
    const updatedProfile = { ...profile, walletAddress: publicKey.toString() };
    window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(updatedProfile));
    renderWalletState(updatedProfile);
  } catch { window.alert("Connection failed."); }
}

dom.connectWalletButton?.addEventListener("click", connectWallet);
dom.topConnectWalletButton?.addEventListener("click", connectWallet);

dom.disconnectWalletButton?.addEventListener("click", () => {
  const profile = getStoredAirdropProfile();
  if (!profile) return;
  const updatedProfile = { ...profile };
  delete updatedProfile.walletAddress;
  window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(updatedProfile));
  renderWalletState(updatedProfile);
  window.alert("Wallet disconnected.");
});

dom.demoWalletButton?.addEventListener("click", () => {
  const profile = getStoredAirdropProfile();
  const updatedProfile = { ...profile, walletAddress: "DemoSQRWallet111111111111111111111" };
  window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(updatedProfile));
  renderWalletState(updatedProfile);
});

dom.qrForm?.addEventListener("submit", (e) => {
  if (!dom.hiddenWalletInput.value) {
    e.preventDefault();
    window.alert("Please connect your wallet first to track scan rewards!");
    return;
  }

  if (analysisLoadingState) {
    let index = 0;
    analysisLoadingState.textContent = loadingSteps[index];
    analysisLoadingState.classList.remove("hidden");
    window.setInterval(() => {
      index = Math.min(index + 1, loadingSteps.length - 1);
      analysisLoadingState.textContent = loadingSteps[index];
    }, 900);
  }
});

function renderAirdropProfile(profile) {
  if (!profile) {
    if (dom.airdropStatus) dom.airdropStatus.textContent = "Not signed in";
    dom.airdropProfile?.classList.add("hidden");
    renderWalletState(null);
    return;
  }
  dom.airdropProfile?.classList.remove("hidden");
  renderWalletState(profile);
}

renderAirdropProfile(getStoredAirdropProfile());
hydrateSplineShowcase();

if (riskModal) {
  document.body.style.overflow = "hidden";
  const scoreGauge = riskModal.querySelector(".score-gauge");
  const finalScore = Number(scoreGauge?.dataset.score || 0);
  if (scoreGauge) {
    const start = performance.now();
    const animateGauge = (now) => {
      const progress = Math.min((now - start) / 1000, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      scoreGauge.style.setProperty("--score", String(Math.round(finalScore * eased)));
      if (progress < 1) window.requestAnimationFrame(animateGauge);
    };
    window.requestAnimationFrame(animateGauge);
  }

  riskModal.addEventListener("click", (event) => {
    if (event.target === riskModal) {
      event.preventDefault();
      riskModal.querySelector(".risk-modal-card")?.animate(
        [{ transform: "scale(1)" }, { transform: "scale(0.992)" }, { transform: "scale(1)" }],
        { duration: 180, easing: "ease-out" }
      );
    }
  });

  riskModal.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      if (reportStatus) reportStatus.textContent = "Use Block & Report or Continue Safely to leave this verdict.";
    }
  });

  window.setTimeout(() => {
    blockReportButton?.focus();
  }, 0);
}

blockReportButton?.addEventListener("click", async () => {
  const payload = document.querySelector(".decoded-box .mono")?.textContent?.trim() || "";
  const reports = JSON.parse(window.localStorage.getItem("safeScanReports") || "[]");
  reports.push({ payload, reportedAt: new Date().toISOString(), verdict: riskModal?.dataset.verdict || "UNKNOWN" });
  window.localStorage.setItem("safeScanReports", JSON.stringify(reports.slice(-25)));
  try {
    await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: payload, reason: "phishing" })
    });
    if (reportStatus) reportStatus.textContent = "Blocked and sent to the SafeScan review queue.";
  } catch {
    if (reportStatus) reportStatus.textContent = "Blocked locally and added to your report queue.";
  }
});

continueSafelyButton?.addEventListener("click", () => {
  document.body.style.overflow = "";
  riskModal?.classList.add("hidden");
});

function storedConsentIsFresh(record) {
  if (!record?.timestamp) return false;
  const acceptedAt = new Date(record.timestamp).getTime();
  return Number.isFinite(acceptedAt) && Date.now() - acceptedAt < 365 * 24 * 60 * 60 * 1000;
}

function showConsentBannerIfNeeded() {
  if (!cookieConsentBanner) return;
  let storedConsent = null;
  try {
    storedConsent = JSON.parse(window.localStorage.getItem("safeScanConsent"));
  } catch {
    storedConsent = null;
  }
  if (!storedConsentIsFresh(storedConsent)) {
    cookieConsentBanner.classList.remove("hidden");
  }
}

cookieConsentBanner?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-consent-choice]");
  if (!button) return;
  const consentType = button.dataset.consentChoice;
  const bannerVersion = cookieConsentBanner.dataset.version || "consent-v1";
  const record = { consentType, bannerVersion, timestamp: new Date().toISOString() };
  window.localStorage.setItem("safeScanConsent", JSON.stringify(record));
  cookieConsentBanner.classList.add("hidden");

  try {
    const response = await fetch("/api/consent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ consentType, bannerVersion })
    });
    const body = await response.json();
    if (body.id) window.localStorage.setItem("safeScanConsentId", body.id);
  } catch {
    cookieConsentBanner.classList.remove("hidden");
  }
});

showConsentBannerIfNeeded();
