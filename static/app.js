const GOOGLE_CLIENT_ID = "230684501873-4aauu1triudaaopdcus2k7achvesr3el.apps.googleusercontent.com";

// Disable browser scroll restoration so a POST-back to / (e.g. after
// submitting the scan form) does NOT inherit the previous page's
// scroll offset. Without this, the risk modal can open scrolled past
// its verdict header on some browsers because the underlying document
// scroll position was restored from history.
if ("scrollRestoration" in window.history) {
  window.history.scrollRestoration = "manual";
}
const AIRDROP_STORAGE_KEY = "phishproofAirdropProfile";
const PHANTOM_BROWSE_BASE = "https://phantom.app/ul/browse/";
const PHANTOM_DOWNLOAD_URL = "https://phantom.app/download";

const dom = {
  hiddenWalletInput: document.getElementById("hiddenWalletInput"),
  deviceFingerprintInput: document.getElementById("deviceFingerprintInput"),
  qrForm: document.getElementById("qrForm"),
  walletStatus: document.getElementById("walletStatus"),
  connectWalletButton: document.getElementById("connectWalletButton"),
  disconnectWalletButton: document.getElementById("disconnectWalletButton"),
  topConnectWalletButton: document.getElementById("topConnectWalletButton"),
  topCopyReferralButton: document.getElementById("topCopyReferralButton"),
  tokenAddress: document.getElementById("tokenAddress"),
  copyTokenAddressButton: document.getElementById("copyTokenAddressButton"),
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
const riskModalCloseButton = document.getElementById("riskModalCloseButton");
const reportStatus = document.getElementById("reportStatus");
const analysisLoadingState = document.getElementById("analysisLoadingState");
const cookieConsentBanner = document.getElementById("cookieConsentBanner");
const loadingSteps = [
  "Tracing redirects...",
  "Checking domain age...",
  "Running reputation scan...",
  "Consulting AI analyst..."
];
let copyToastTimer = 0;

function showCopyToast(message = "Copied") {
  let toast = document.getElementById("copyToast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "copyToast";
    toast.className = "copy-toast";
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(copyToastTimer);
  copyToastTimer = window.setTimeout(() => {
    toast.classList.remove("visible");
  }, 1400);
}

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

function setStoredAirdropProfile(profile) {
  if (!profile) {
    window.localStorage.removeItem(AIRDROP_STORAGE_KEY);
    return;
  }
  window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(profile));
}

function getCurrentProfile() {
  const stored = getStoredAirdropProfile() || {};
  const profileEmail = document.querySelector(".profile-email");
  const email = profileEmail?.dataset?.email || profileEmail?.textContent?.trim();
  if (!email) return null;
  const profile = { ...stored, email };
  setStoredAirdropProfile(profile);
  return profile;
}

function truncateAddress(address) {
  return address ? `${address.slice(0, 4)}...${address.slice(-4)}` : "";
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value || "";
  return div.innerHTML;
}

async function copyTextToClipboard(value) {
  if (!value) return false;
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return true;
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-1000px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  textarea.setSelectionRange(0, value.length);
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } finally {
    textarea.remove();
  }
  return copied;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const value = digits[i] * 256 + carry;
      digits[i] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = "";
  for (const byte of bytes) {
    if (byte === 0) output += "1";
    else break;
  }
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    output += BASE58_ALPHABET[digits[i]];
  }
  return output;
}

function delay(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function isMobileDevice() {
  const ua = navigator.userAgent || "";
  const touchCapableMac = navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1;
  return /Android|iPhone|iPad|iPod|Mobile/i.test(ua) || touchCapableMac;
}

function isIosDevice() {
  const ua = navigator.userAgent || "";
  return /iPhone|iPad|iPod/i.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

function getWalletConnectTargetUrl() {
  const target = new URL(window.location.href);
  target.searchParams.set("walletConnect", "phantom");
  target.hash = "airdrop";
  return target.toString();
}

function getPhantomBrowseUrl() {
  return `${PHANTOM_BROWSE_BASE}${encodeURIComponent(getWalletConnectTargetUrl())}?ref=${encodeURIComponent(window.location.origin)}`;
}

function walletInstallLinksHtml(includePhantomBrowse = false) {
  const openPhantomLink = includePhantomBrowse
    ? `<a class="wallet-open-phantom-link" href="${getPhantomBrowseUrl()}">Open in Phantom</a>`
    : "";
  return `<div class="wallet-install-links">${openPhantomLink}<a href="${PHANTOM_DOWNLOAD_URL}" target="_blank" rel="noopener">Install Phantom</a><a href="https://solflare.com/" target="_blank" rel="noopener">Install Solflare</a></div>`;
}

function mobileWalletHelpText() {
  if (isIosDevice()) {
    return "On iPhone, Phantom connects websites from its in-app browser. Open this page in Phantom, sign in there if needed, then connect again.";
  }
  return "On mobile, open this page inside your wallet browser, sign in there if needed, then connect again.";
}

function normalizeSignature(signatureBytes) {
  if (typeof signatureBytes === "string") return signatureBytes;
  if (signatureBytes instanceof Uint8Array) return base58Encode(signatureBytes);
  if (Array.isArray(signatureBytes)) return base58Encode(new Uint8Array(signatureBytes));
  if (signatureBytes?.data && Array.isArray(signatureBytes.data)) return base58Encode(new Uint8Array(signatureBytes.data));
  return base58Encode(signatureBytes || []);
}

function walletProviderName(provider, fallbackName) {
  const candidate = [
    provider?.walletName,
    provider?._walletName,
    provider?.displayName,
    provider?.name,
    provider?.constructor?.name
  ].find((value) => typeof value === "string" && value.trim());
  const normalized = (candidate || "").toLowerCase();
  if (provider?.isBraveWallet || provider?.isBrave || normalized.includes("brave")) return "Brave Wallet";
  if (provider?.isSolflare || normalized.includes("solflare")) return "Solflare";
  if (provider?.isBackpack || normalized.includes("backpack")) return "Backpack";
  if (provider?.isCoinbaseWallet || normalized.includes("coinbase")) return "Coinbase Wallet";
  if (provider?.isGlow || normalized.includes("glow")) return "Glow";
  if (provider?.isExodus || normalized.includes("exodus")) return "Exodus";
  if (provider?.isPhantom || normalized.includes("phantom")) return "Phantom";
  return fallbackName;
}

function walletDisconnectButtonHtml(wallet, index) {
  const profile = getCurrentProfile();
  if (typeof wallet?.provider?.disconnect !== "function" && !profile?.walletVerified) return "";
  return `<button class="secondary-button wallet-disconnect-button" data-wallet-disconnect-index="${index}" type="button">Disconnect wallet</button>`;
}

function detectedSolanaWallets() {
  const wallets = [];
  const seen = new Set();
  const add = (name, provider, url) => {
    if (!provider || seen.has(provider)) return;
    seen.add(provider);
    wallets.push({ name: walletProviderName(provider, name), provider, url });
  };
  add("Brave Wallet", window.brave?.solana || window.braveSolana || (window.solana?.isBraveWallet || window.solana?.isBrave ? window.solana : null), "https://wallet.brave.com/");
  add("Phantom", window.phantom?.solana || (window.solana?.isPhantom ? window.solana : null), "https://phantom.app/");
  add("Solflare", window.solflare || (window.solana?.isSolflare ? window.solana : null), "https://solflare.com/");
  add("Backpack", window.backpack?.solana, "https://backpack.app/");
  add("Solana Wallet", window.solana, "https://phantom.app/");
  return wallets;
}

async function waitForSolanaWallets(timeoutMs = 900) {
  const started = performance.now();
  let wallets = detectedSolanaWallets();
  while (!wallets.length && performance.now() - started < timeoutMs) {
    await delay(100);
    wallets = detectedSolanaWallets();
  }
  return wallets;
}

function removeWalletModal() {
  document.querySelector(".wallet-modal")?.remove();
}

function showWalletModal(content) {
  removeWalletModal();
  const modal = document.createElement("div");
  modal.className = "wallet-modal";
  modal.innerHTML = `<div class="wallet-modal-card"><button class="wallet-modal-close" type="button" aria-label="Close wallet dialog" style="position:absolute;top:12px;right:12px;display:grid;place-items:center;width:34px;height:34px;border:1px solid rgba(255,110,127,0.72);border-radius:8px;background:rgba(255,110,127,0.16);color:#ff6e7f;font-family:inherit;font-size:1rem;font-weight:900;line-height:1;cursor:pointer;z-index:3;">X</button>${content}</div>`;
  modal.addEventListener("click", (event) => {
    if (event.target === modal) removeWalletModal();
  });
  modal.querySelector(".wallet-modal-close")?.addEventListener("click", removeWalletModal);
  document.body.appendChild(modal);
  return modal;
}

function showSignInWalletModal(message = "Sign in first to connect and verify a wallet.") {
  const next = encodeURIComponent(`${window.location.pathname}${window.location.search}${window.location.hash}`);
  showWalletModal(`<h3>Sign in required</h3><p>${escapeHtml(message)}</p><div class="wallet-modal-actions"><a class="primary-button" href="/login?next=${next}">Sign in / Sign up</a></div>`);
}

function setWalletBusy(message) {
  if (dom.walletStatus) dom.walletStatus.textContent = message;
  if (dom.connectWalletButton) dom.connectWalletButton.disabled = true;
  if (dom.topConnectWalletButton) dom.topConnectWalletButton.disabled = true;
}

function clearWalletBusy() {
  if (dom.connectWalletButton) dom.connectWalletButton.disabled = false;
  if (dom.topConnectWalletButton) dom.topConnectWalletButton.disabled = false;
}

function renderWalletState(profile = getCurrentProfile()) {
  const walletAddr = profile?.walletAddress || "";
  const verified = Boolean(profile?.walletVerified);

  if (dom.hiddenWalletInput) dom.hiddenWalletInput.value = verified ? walletAddr : "";

  if (!profile) {
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

  if (!walletAddr || !verified) {
    if (dom.walletStatus) dom.walletStatus.textContent = "Connect and sign a wallet message to verify ownership.";
    dom.connectWalletButton?.classList.remove("hidden");
    dom.topConnectWalletButton?.classList.remove("hidden");
    dom.disconnectWalletButton?.classList.add("hidden");
    if (dom.topConnectWalletButton) {
      dom.topConnectWalletButton.textContent = "Connect wallet";
      dom.topConnectWalletButton.disabled = false;
    }
    return;
  }

  if (dom.walletStatus) {
    dom.walletStatus.innerHTML = `Connected: <a href="https://solscan.io/account/${walletAddr}" target="_blank" rel="noopener">${truncateAddress(walletAddr)}</a>`;
  }
  dom.connectWalletButton?.classList.add("hidden");
  dom.disconnectWalletButton?.classList.remove("hidden");

  if (dom.topConnectWalletButton) {
    dom.topConnectWalletButton.textContent = "Wallet connected";
    dom.topConnectWalletButton.disabled = true;
  }
}

async function syncWalletFromServer() {
  const profile = getCurrentProfile();
  if (!profile) {
    renderWalletState(null);
    return;
  }
  try {
    const response = await fetch("/api/wallet");
    if (!response.ok) throw new Error("wallet status unavailable");
    const body = await response.json();
    const updatedProfile = { ...profile };
    if (body.connected && body.walletAddress) {
      updatedProfile.walletAddress = body.walletAddress;
      updatedProfile.walletVerified = true;
    } else {
      delete updatedProfile.walletAddress;
      delete updatedProfile.walletVerified;
    }
    setStoredAirdropProfile(updatedProfile);
    renderWalletState(updatedProfile);
  } catch {
    renderWalletState(profile);
  }
}

async function verifySelectedWallet(wallet) {
  const profile = getCurrentProfile();
  if (!profile) {
    showSignInWalletModal("Sign in in this browser first, then connect your wallet for airdrop verification.");
    return;
  }
  try {
    setWalletBusy("Requesting verification challenge...");
    showWalletModal("<h3>Connecting wallet</h3><p>Requesting verification challenge...</p><div class='wallet-spinner'></div>");
    const connectResponse = await wallet.provider.connect();
    const publicKey = connectResponse?.publicKey || wallet.provider.publicKey;
    const walletAddress = publicKey?.toString();
    if (!walletAddress) throw new Error("Wallet did not return a public key.");

    const nonceResponse = await fetch("/api/wallet/nonce", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ walletAddress })
    });
    const nonceBody = await nonceResponse.json();
    if (!nonceResponse.ok) throw new Error(nonceBody.error || "Could not create wallet challenge.");

    setWalletBusy("Check your wallet and approve the signature request.");
    showWalletModal("<h3>Approve signature</h3><p>Check your wallet. This is free and does not send a transaction.</p><div class='wallet-spinner'></div>");
    if (typeof wallet.provider.signMessage !== "function") {
      throw new Error("This wallet does not support message signing.");
    }
    const messageBytes = new TextEncoder().encode(nonceBody.message);
    const signed = await wallet.provider.signMessage(messageBytes, "utf8");
    const signatureBytes = signed?.signature || signed;
    const signature = normalizeSignature(signatureBytes);

    setWalletBusy("Verifying signature...");
    showWalletModal("<h3>Verifying wallet</h3><p>SafeScan is checking the signature server-side...</p><div class='wallet-spinner'></div>");
    const verifyResponse = await fetch("/api/wallet/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ walletAddress, signature })
    });
    const verifyBody = await verifyResponse.json();
    if (!verifyResponse.ok) throw new Error(verifyBody.error || "Wallet connection failed.");

    const updatedProfile = { ...profile, walletAddress: verifyBody.walletAddress, walletVerified: true };
    setStoredAirdropProfile(updatedProfile);
    renderWalletState(updatedProfile);
    showWalletModal(`<h3>Wallet connected</h3><div class="wallet-success-spacer" aria-hidden="true"></div><button class="primary-button wallet-close-button" type="button">Done</button>`);
    document.querySelector(".wallet-close-button")?.addEventListener("click", removeWalletModal);
  } catch (error) {
    renderWalletState(getCurrentProfile());
    showWalletModal(`<h3>Wallet connection failed</h3><p class="wallet-error">${escapeHtml(error.message || "Signature rejected. Try again.")}</p><button class="primary-button wallet-retry-button" type="button">Try Again</button>`);
    document.querySelector(".wallet-retry-button")?.addEventListener("click", connectWallet);
  } finally {
    clearWalletBusy();
  }
}

async function connectWallet() {
  const profile = getCurrentProfile();
  if (!profile) {
    showSignInWalletModal("Sign in first. If you opened from iPhone Safari, open this page in Phantom and sign in there before connecting.");
    return;
  }
  showWalletModal("<h3>Looking for wallet</h3><p>Checking for a Solana wallet provider...</p><div class='wallet-spinner'></div>");
  const wallets = await waitForSolanaWallets();
  if (!wallets.length) {
    const mobileCopy = isMobileDevice()
      ? `<p>${mobileWalletHelpText()}</p>${!window.isSecureContext ? "<p class='wallet-hint'>Wallet browsers only inject providers on HTTPS, localhost, or 127.0.0.1.</p>" : ""}`
      : "<p>Install a Solana wallet extension, then refresh this page and connect again.</p>";
    showWalletModal(`<h3>No Solana wallet detected</h3>${mobileCopy}${walletInstallLinksHtml(isMobileDevice())}<button class="secondary-button wallet-retry-button" type="button">Check again</button>`);
    document.querySelector(".wallet-retry-button")?.addEventListener("click", connectWallet);
    return;
  }
  const modal = showWalletModal(`<h3>Select wallet</h3><div class="wallet-choice-list">${wallets.map((wallet, index) => `<div class="wallet-choice-row"><button class="secondary-button wallet-choice-button" data-wallet-index="${index}" type="button">${escapeHtml(wallet.name)}</button>${walletDisconnectButtonHtml(wallet, index)}</div>`).join("")}</div>`);
  modal.querySelectorAll("[data-wallet-index]").forEach((button) => {
    button.addEventListener("click", () => verifySelectedWallet(wallets[Number(button.dataset.walletIndex)]));
  });
  modal.querySelectorAll("[data-wallet-disconnect-index]").forEach((button) => {
    button.addEventListener("click", () => disconnectWalletConnection(wallets[Number(button.dataset.walletDisconnectIndex)], { closeModal: true }));
  });
}

dom.connectWalletButton?.addEventListener("click", connectWallet);
dom.topConnectWalletButton?.addEventListener("click", connectWallet);

async function disconnectWalletConnection(wallet = null, options = {}) {
  const { closeModal = false, notify = true } = options;
  const profile = getCurrentProfile();
  try {
    if (typeof wallet?.provider?.disconnect === "function") {
      await wallet.provider.disconnect();
    }
    if (profile?.walletAddress || profile?.walletVerified) {
      const response = await fetch("/api/wallet", { method: "DELETE" });
      let body = {};
      try {
        body = await response.json();
      } catch (_) {
        body = {};
      }
      if (!response.ok && response.status !== 404) throw new Error(body.error || "Wallet disconnect failed.");
      const updatedProfile = { ...profile };
      delete updatedProfile.walletAddress;
      delete updatedProfile.walletVerified;
      setStoredAirdropProfile(updatedProfile);
      renderWalletState(updatedProfile);
    }
    if (closeModal) removeWalletModal();
    if (notify) window.alert("Wallet disconnected.");
  } catch (error) {
    window.alert(error.message || "Wallet disconnect failed.");
  }
}

dom.disconnectWalletButton?.addEventListener("click", () => disconnectWalletConnection());

dom.demoWalletButton?.addEventListener("click", () => {
  window.alert("Demo wallets cannot be used for airdrop verification. Connect a real wallet and approve the signature request.");
});

dom.copyTokenAddressButton?.addEventListener("click", async () => {
  const tokenAddress = dom.tokenAddress?.textContent?.trim() || "";
  window.clearTimeout(dom.copyTokenAddressButton.dataset.resetTimer);
  const isCopied = dom.copyTokenAddressButton.textContent.trim() === "Copied";
  dom.copyTokenAddressButton.textContent = tokenAddress ? (isCopied ? "Copy" : "Copied") : "Copy failed";
  dom.tokenAddress?.classList.remove("token-address-copied");
  void dom.tokenAddress?.offsetWidth;
  dom.tokenAddress?.classList.add("token-address-copied");

  copyTextToClipboard(tokenAddress).catch(() => {});
});

dom.topCopyReferralButton?.addEventListener("click", async () => {
  try {
    const response = await fetch("/api/referral", { credentials: "same-origin" });
    const body = await response.json();
    const referralLink = body.referralLink || body.link;
    if (!response.ok || !referralLink) throw new Error(body.detail || "Referral link unavailable.");
    const copied = await copyTextToClipboard(referralLink);
    showCopyToast(copied ? "Copied link" : "Copy failed");
  } catch {
    showCopyToast("Sign in first");
  }
});

dom.qrForm?.addEventListener("submit", () => {
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

const qrImageInput = document.getElementById("qrImageInput");
qrImageInput?.addEventListener("change", () => {
  if (qrImageInput.files && qrImageInput.files.length > 0) {
    const form = qrImageInput.form;
    if (analysisLoadingState) {
      analysisLoadingState.textContent = "Preparing file scan...";
      analysisLoadingState.classList.remove("hidden");
    }
    if (form) {
      window.setTimeout(() => {
        form.requestSubmit ? form.requestSubmit() : form.submit();
      }, 80);
    }
  }
});

// Live camera scan. The scanner module (qr-camera.js) handles camera
// access, frame decoding, and cooldown; we just feed the decoded payload
// into the existing manual-URL form so the same /search_qr_api pipeline
// runs on the result.
const scanCameraButton = document.getElementById("scanCameraButton");
function openCameraScanner() {
  if (!window.SafeScanQrCamera || typeof window.SafeScanQrCamera.open !== "function") {
    window.alert("Camera scanner is still loading. Please try again in a moment.");
    return;
  }
  window.SafeScanQrCamera.open({
    onResult: (value) => {
      const urlInput = document.getElementById("urlInput");
      const form = document.getElementById("qrForm");
      if (urlInput) urlInput.value = value;
      if (analysisLoadingState) {
        analysisLoadingState.textContent = "QR detected - analysing...";
        analysisLoadingState.classList.remove("hidden");
      }
      if (form) {
        form.requestSubmit ? form.requestSubmit() : form.submit();
      }
    },
    onError: (message) => {
      if (message) window.alert(message);
    }
  });
}
scanCameraButton?.addEventListener("click", openCameraScanner);

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

renderAirdropProfile(getCurrentProfile());
syncWalletFromServer();
hydrateSplineShowcase();

if (new URLSearchParams(window.location.search).get("walletConnect") === "phantom") {
  window.setTimeout(() => {
    const currentUrl = new URL(window.location.href);
    currentUrl.searchParams.delete("walletConnect");
    window.history.replaceState({}, "", `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}`);
    if (getCurrentProfile()) {
      connectWallet();
    } else {
      showSignInWalletModal("You are in Phantom now. Sign in here, then tap Connect wallet to finish verification.");
    }
  }, 700);
}

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
      closeRiskModal();
    }
  });

  // Park the modal at the TOP of all scroll surfaces, and KEEP it there
  // for the first 500ms after open. Earlier attempts failed because:
  //   1. focus()ing blockReportButton (at bottom of card) scrolled the
  //      target into view. preventScroll is not honoured everywhere
  //      (older WebKit, in-app browsers). Reliable fix: focus a target
  //      that is already AT the top - the modal close button.
  //   2. The score-gauge animation triggers layout reflows for ~1s
  //      after open. Chrome scroll-restoration heuristics can latch on
  //      to the post-POST document scroll during that window. A single
  //      reset is not enough; we poll every 50ms for the first 500ms.
  const riskModalCard = riskModal.querySelector(".risk-modal-card");
  const resetScroll = () => {
    if (riskModalCard) riskModalCard.scrollTop = 0;
    riskModal.scrollTop = 0;
    if (document.scrollingElement) document.scrollingElement.scrollTop = 0;
    if (document.documentElement) document.documentElement.scrollTop = 0;
    if (document.body) document.body.scrollTop = 0;
    if (typeof window.scrollTo === "function") {
      try {
        window.scrollTo({ top: 0, left: 0, behavior: "instant" });
      } catch (_err) {
        window.scrollTo(0, 0);
      }
    }
  };
  resetScroll();
  window.requestAnimationFrame(() => {
    resetScroll();
    window.requestAnimationFrame(resetScroll);
  });

  let scrollGuardTicks = 0;
  const scrollGuard = window.setInterval(() => {
    resetScroll();
    scrollGuardTicks += 1;
    if (scrollGuardTicks >= 10) window.clearInterval(scrollGuard);
  }, 50);

  // Focus the close (X) button - it is sticky at top of the card so
  // browser focus-scroll behaviour is harmless. Falls back to focusing
  // the modal itself if the close button is not in the DOM yet.
  window.setTimeout(() => {
    const topFocusTarget = riskModalCloseButton || riskModal;
    if (topFocusTarget && typeof topFocusTarget.focus === "function") {
      try {
        topFocusTarget.focus({ preventScroll: true });
      } catch (_err) {
        topFocusTarget.focus();
      }
    }
    resetScroll();
  }, 0);
}

function closeRiskModal() {
  document.body.style.overflow = "";
  riskModal?.classList.add("hidden");
  document.getElementById("resultsSection")?.scrollIntoView({ behavior: "smooth", block: "start" });
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
  closeRiskModal();
});

riskModalCloseButton?.addEventListener("click", closeRiskModal);

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

const revealTargets = document.querySelectorAll(".reveal-on-scroll");
if (revealTargets.length) {
  revealTargets.forEach((target, index) => {
    target.style.setProperty("--reveal-delay", `${Math.min(index * 70, 280)}ms`);
  });

  if ("IntersectionObserver" in window) {
    const revealObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        revealObserver.unobserve(entry.target);
      });
    }, { threshold: 0.01, rootMargin: "0px 0px 32% 0px" });

    revealTargets.forEach((target) => revealObserver.observe(target));
  } else {
    revealTargets.forEach((target) => target.classList.add("is-visible"));
  }
}

document.querySelectorAll(".vt-panel").forEach((panel) => {
  const tabs = panel.querySelectorAll("[data-vt-tab]");
  const groups = panel.querySelectorAll("[data-vt-group]");
  const search = panel.querySelector(".vt-engine-search");
  const mobileToggle = panel.querySelector(".vt-mobile-toggle");

  const applyFilter = () => {
    const activeTab = panel.querySelector("[data-vt-tab].active")?.dataset.vtTab || "clean";
    const query = search?.value?.trim().toLowerCase() || "";
    groups.forEach((group) => {
      const isActive = group.dataset.vtGroup === activeTab;
      group.classList.toggle("hidden", !isActive);
      if (!isActive) return;
      group.querySelectorAll(".vt-engine-row").forEach((row) => {
        const name = row.dataset.engineName || "";
        row.classList.toggle("hidden", Boolean(query) && !name.includes(query));
      });
    });
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((item) => item.classList.remove("active"));
      tab.classList.add("active");
      applyFilter();
    });
  });
  search?.addEventListener("input", applyFilter);
  mobileToggle?.addEventListener("click", () => {
    const isOpen = panel.classList.toggle("vt-mobile-open");
    mobileToggle.textContent = isOpen ? "Hide engine details" : "Show engine details";
  });
  applyFilter();
});

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
    automationNote: "Assisted: search with your name and location, copy the matching listing details, then complete the suppression form.",
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
    automationNote: "Assisted: find the matching profile, copy its URL, paste it into Spokeo opt-out, then verify the email.",
    searchUrl: ({ name, location }) => `https://www.spokeo.com/${ghostPathSlug(name)}${location ? `/${ghostPathSlug(location)}` : ""}`
  },
  {
    id: "beenverified",
    name: "BeenVerified",
    priority: "High traffic",
    priorityDescription: "One of the most visible people-search sites, so it is a good place to remove first.",
    removalUrl: "https://www.beenverified.com/app/optout/search",
    prefillMap: { name: "fn", address: "address", location: "citystatezip", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Full name", "State/city", "Matching record", "Email confirmation"],
    automationNote: "Assisted: use the opt-out search, choose the matching record, and complete email verification.",
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
    automationNote: "Assisted: search, open the matching record, then use the removal flow and verify by email.",
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
    automationNote: "Assisted: copy the address/phone details, open opt-out, then submit only the fields Thatsthem requests.",
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
    automationNote: "Assisted: find the matching Nuwber profile, paste its URL into the removal form, then verify by email.",
    searchUrl: ({ name, location }) => `https://nuwber.com/search?name=${encodeURIComponent(name || "")}&location=${encodeURIComponent(location || "")}`
  },
  {
    id: "radaris",
    name: "Radaris",
    priority: "Duplicate check",
    priorityDescription: "This site can show multiple records for one person, so check for duplicates before marking it removed.",
    removalUrl: "https://radaris.com/page/how-to-remove",
    prefillMap: { name: "name", address: "address", location: "location", email: "email", phone: "phone", identifier: "phone" },
    requiredInfo: ["Profile URL", "Matching record", "Email confirmation"],
    automationNote: "Assisted: Radaris may show duplicate records, so confirm the exact profile before submitting removal.",
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

function updateGhostAutomationState(siteId, automation) {
  const progress = getGhostProgress();
  progress[siteId] = { ...(progress[siteId] || {}), automation, updatedAt: new Date().toISOString() };
  writeJsonStorage(GO_GHOST_PROGRESS_KEY, progress);
  renderGoGhostProgress();
}

function formatGhostAutomationStatus(status) {
  const labels = {
    captcha_required: "CAPTCHA checkpoint",
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

function startGhostAssistedQueue() {
  const profile = getGhostProfile();
  if (!hasGhostSearchProfile(profile)) {
    scrollToGhostProfile();
    showCopyToast("Add a name first");
    return;
  }
  const broker = nextPendingGhostBroker();
  if (!broker) {
    showCopyToast("All brokers tracked");
    return;
  }
  scrollToGhostBroker(broker);
  showCopyToast(`Next: ${broker.name}`);
}

async function openNextGhostBroker() {
  const profile = getGhostProfile();
  if (!hasGhostSearchProfile(profile)) {
    scrollToGhostProfile();
    showCopyToast("Add a name first");
    return;
  }
  const broker = nextPendingGhostBroker();
  if (!broker) {
    showCopyToast("All brokers tracked");
    return;
  }
  const searchUrl = goGhostBrokerSearchUrl(broker, profile);
  openGhostUrl(searchUrl);
  scrollToGhostBroker(broker);
  const copied = await copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
  showCopyToast(copied ? `${broker.name} packet copied` : `Opened ${broker.name}`);
}

async function runGhostBrokerAutomation(broker, triggerButton) {
  const activeController = goGhostAutomationControllers.get(broker.id);
  if (activeController) {
    activeController.abort();
    showCopyToast(`Cancelling ${broker.name}`);
    return;
  }

  const profile = getGhostProfile();
  if (!profile.name?.trim()) {
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

  const originalText = triggerButton?.textContent || "";
  const controller = new AbortController();
  goGhostAutomationControllers.set(broker.id, controller);
  if (triggerButton) {
    triggerButton.textContent = "Cancel run";
    triggerButton.setAttribute("aria-pressed", "true");
  }
  const searchUrl = goGhostBrokerSearchUrl(broker, profile);
  const optOutUrl = goGhostBrokerOptOutUrl(broker, profile);
  const opened = openGhostUrl(optOutUrl);
  const copied = await copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
  updateGhostAutomationState(broker.id, {
    status: "running",
    detail: opened
      ? `Opened ${broker.name} opt-out and ${copied ? "copied" : "prepared"} your details. Browser privacy blocks SafeScan from typing into the third-party tab directly.`
      : "Popup blocked. Copy the details and open the opt-out page manually.",
    targetUrl: optOutUrl,
    updatedAt: new Date().toISOString()
  });
  showCopyToast(opened ? `${broker.name} opt-out opened` : "Popup blocked");

  try {
    const response = await fetch(`/api/go-ghost/removals/${encodeURIComponent(broker.id)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        name: profile.name,
        address: profile.address,
        cityState: profile.location,
        phone: profile.phone,
        email: profile.email
      })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || "Automation failed");
    }
    const automation = {
      status: body.status || "failed",
      detail: body.detail || "",
      jobId: body.jobId || "",
      targetUrl: body.targetUrl || broker.removalUrl,
      updatedAt: new Date().toISOString()
    };
    if (opened && ["failed", "unavailable"].includes(automation.status)) {
      automation.status = "opened";
      automation.detail = `Browser-assisted opt-out opened. ${automation.detail || "Backend automation was not available."}`;
      automation.targetUrl = optOutUrl;
    }
    updateGhostAutomationState(broker.id, automation);
    if (automation.status === "submitted") setGhostProgress(broker.id, "submitted", true);
    showCopyToast(formatGhostAutomationStatus(automation.status));
  } catch (error) {
    if (error?.name === "AbortError") {
      updateGhostAutomationState(broker.id, {
        status: "cancelled",
        detail: "Backend automation was cancelled. Any opt-out tab that already opened stays open for manual review.",
        targetUrl: optOutUrl,
        updatedAt: new Date().toISOString()
      });
      showCopyToast(`${broker.name} run cancelled`);
      return;
    }
    if (opened) {
      updateGhostAutomationState(broker.id, {
        status: "opened",
        detail: `Browser-assisted opt-out opened. ${error.message || "Backend automation was not available."}`,
        targetUrl: optOutUrl,
        updatedAt: new Date().toISOString()
      });
      showCopyToast(copied ? "Details copied for the opt-out tab" : "Opt-out tab opened");
      return;
    }
    updateGhostAutomationState(broker.id, {
      status: "failed",
      detail: error.message || "Automation failed.",
      updatedAt: new Date().toISOString()
    });
    showCopyToast(error.message || "Automation failed");
  } finally {
    if (goGhostAutomationControllers.get(broker.id) === controller) {
      goGhostAutomationControllers.delete(broker.id);
    }
    if (triggerButton) {
      triggerButton.textContent = originalText;
      triggerButton.removeAttribute("aria-pressed");
    }
  }
}

function renderGoGhostProgress() {
  if (!ghostProgressCount) return;
  const progress = getGhostProgress();
  const removed = goGhostBrokers.filter((broker) => progress[broker.id]?.removed).length;
  ghostProgressCount.textContent = `${removed} / ${goGhostBrokers.length}`;
}

function renderGoGhostAutomationScope() {
  if (!goGhostAutomationRows) return;
  goGhostAutomationRows.innerHTML = goGhostBrokers.slice(0, 8).map((broker) => {
    const scope = goGhostAutomationScope(broker);
    return `
      <button class="ghost-automation-row ghost-automation-site-row" type="button" data-ghost-scope="${broker.id}" aria-label="Open ${escapeHtml(broker.name)} automation details">
        <span>${escapeHtml(broker.name)}</span>
        <span>${escapeHtml(scope.search)}</span>
        <span>${escapeHtml(scope.submit)}</span>
        <span>${escapeHtml(scope.manual)}</span>
      </button>
    `;
  }).join("");
}

function renderGoGhostBrokers() {
  if (!goGhostBrokerList) return;
  const profile = getGhostProfile();
  const progress = getGhostProgress();
  goGhostBrokerList.innerHTML = goGhostBrokers.map((broker) => {
    const state = progress[broker.id] || {};
    const searchUrl = goGhostBrokerSearchUrl(broker, profile);
    const optOutUrl = goGhostBrokerOptOutUrl(broker, profile);
    return `
      <article class="broker-card" data-ghost-broker="${broker.id}">
        <div>
          <span class="broker-priority" title="${escapeHtml(broker.priorityDescription || "")}">${escapeHtml(broker.priority)}</span>
          <h3>${escapeHtml(broker.name)}</h3>
        </div>
        <div class="broker-actions">
          <a class="secondary-button" href="${searchUrl}" target="_blank" rel="noopener noreferrer">Search</a>
          <a class="primary-button" href="${optOutUrl}" target="_blank" rel="noopener noreferrer" data-ghost-optout="${broker.id}">Opt out</a>
          ${broker.automationEnabled ? `<button class="primary-button" type="button" data-ghost-auto="${broker.id}">${goGhostAutomationControllers.has(broker.id) ? "Cancel run" : "Run auto fill"}</button>` : ""}
          <button class="secondary-button" type="button" data-ghost-copy="${broker.id}">Copy details</button>
        </div>
        <div class="broker-requirements">${(broker.requiredInfo || []).map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>
        ${state.automation ? `<div class="broker-automation-status"><strong>${escapeHtml(formatGhostAutomationStatus(state.automation.status))}</strong><span>${escapeHtml(state.automation.detail || "")}</span></div>` : ""}
        <div class="broker-checks">
          <label><input type="checkbox" data-ghost-site="${broker.id}" data-ghost-field="submitted" ${state.submitted ? "checked" : ""}> Submitted</label>
          <label><input type="checkbox" data-ghost-site="${broker.id}" data-ghost-field="removed" ${state.removed ? "checked" : ""}> Removed</label>
        </div>
      </article>
    `;
  }).join("");
  renderGoGhostProgress();
}

function closeGoGhostScopeModal() {
  activeGhostScopeBrokerId = "";
  goGhostScopeModal?.classList.add("hidden");
}

function renderGhostScopeKeywords(profile) {
  if (!goGhostScopeKeywords) return;
  const fields = [
    ["Full name", profile.name],
    ["City/state", profile.location],
    ["Street address", profile.address],
    ["Phone", profile.phone || profile.identifier],
    ["Email", profile.email]
  ];
  goGhostScopeKeywords.innerHTML = fields.map(([label, value]) => `
    <div class="ghost-scope-keyword">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value || "Not set")}</strong>
    </div>
  `).join("");
}

function openGoGhostScopeModal(siteId) {
  const broker = goGhostBrokers.find((item) => item.id === siteId);
  if (!broker || !goGhostScopeModal) return;
  const profile = getGhostProfile();
  const scope = goGhostAutomationScope(broker);
  activeGhostScopeBrokerId = broker.id;
  if (goGhostScopeTitle) goGhostScopeTitle.textContent = broker.name;
  if (goGhostScopePriority) goGhostScopePriority.textContent = broker.priority;
  if (goGhostScopeDescription) goGhostScopeDescription.textContent = broker.automationNote || broker.priorityDescription || "";
  renderGhostScopeKeywords(profile);
  if (goGhostScopeDetails) {
    goGhostScopeDetails.innerHTML = `
      <div class="ghost-scope-detail"><span>Search</span><strong>${escapeHtml(scope.search)}</strong></div>
      <div class="ghost-scope-detail"><span>Submit</span><strong>${escapeHtml(scope.submit)}</strong></div>
      <div class="ghost-scope-detail"><span>Manual checkpoint</span><strong>${escapeHtml(scope.manual)}</strong></div>
      <div class="ghost-scope-detail ghost-scope-detail-wide"><span>Needed</span><strong>${escapeHtml((broker.requiredInfo || []).join(", "))}</strong></div>
    `;
  }
  if (goGhostScopeAutoFillButton) {
    goGhostScopeAutoFillButton.hidden = !broker.automationEnabled;
    goGhostScopeAutoFillButton.textContent = goGhostAutomationControllers.has(broker.id) ? "Cancel run" : "Run auto fill";
    if (goGhostAutomationControllers.has(broker.id)) goGhostScopeAutoFillButton.setAttribute("aria-pressed", "true");
    else goGhostScopeAutoFillButton.removeAttribute("aria-pressed");
  }
  goGhostScopeModal.classList.remove("hidden");
  goGhostScopeModal.querySelector(".ghost-scope-close")?.focus();
}

async function runGhostScopeAction(action) {
  const broker = goGhostBrokers.find((item) => item.id === activeGhostScopeBrokerId);
  if (!broker) return;
  const profile = getGhostProfile();
  const searchUrl = goGhostBrokerSearchUrl(broker, profile);

  if (action === "search") {
    openGhostUrl(searchUrl);
    showCopyToast(`Opened ${broker.name} search`);
    return;
  }
  if (action === "optout") {
    openGhostUrl(goGhostBrokerOptOutUrl(broker, profile));
    showCopyToast(`Opened ${broker.name} opt-out`);
    return;
  }
  if (action === "copy") {
    const copied = await copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
    showCopyToast(copied ? `${broker.name} details copied` : "Copy failed");
    return;
  }
  if (action === "auto") {
    await runGhostBrokerAutomation(broker, goGhostScopeAutoFillButton);
    renderGhostScopeKeywords(getGhostProfile());
  }
}

function hydrateGoGhostProfile() {
  const profile = getGhostProfile();
  if (ghostNameInput) ghostNameInput.value = profile.name || "";
  if (ghostLocationInput) ghostLocationInput.value = profile.location || "";
  if (ghostAddressInput) ghostAddressInput.value = profile.address || "";
  if (ghostPhoneInput) ghostPhoneInput.value = profile.phone || profile.identifier || "";
  if (ghostEmailInput) ghostEmailInput.value = profile.email || "";
}

function startGoGhost() {
  writeJsonStorage(GO_GHOST_CONSENT_KEY, { acceptedAt: new Date().toISOString() });
  goGhostConsentModal?.classList.add("hidden");
  if (goGhostWorkspace) goGhostWorkspace.hidden = false;
  hydrateGoGhostProfile();
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
}

if (goGhostWorkspace) {
  applyGoGhostDeviceFormatting();
  window.addEventListener("resize", applyGoGhostDeviceFormatting);

  const hasConsent = Boolean(readJsonStorage(GO_GHOST_CONSENT_KEY, null));
  if (hasConsent) startGoGhost();
  else goGhostConsentModal?.classList.remove("hidden");

  startGoGhostButton?.addEventListener("click", startGoGhost);
  startGhostQueueButton?.addEventListener("click", startGhostAssistedQueue);
  openNextGhostBrokerButton?.addEventListener("click", openNextGhostBroker);

  goGhostProfileForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    writeJsonStorage(GO_GHOST_PROFILE_KEY, getGhostFormProfile());
    renderGoGhostAutomationScope();
    renderGoGhostProgress();
    showCopyToast("Automation scope updated");
  });

  [ghostNameInput, ghostLocationInput, ghostAddressInput, ghostPhoneInput, ghostEmailInput].forEach((input) => {
    input?.addEventListener("input", () => {
      writeJsonStorage(GO_GHOST_PROFILE_KEY, getGhostFormProfile());
      renderGoGhostAutomationScope();
      renderGoGhostProgress();
    });
  });

  clearGhostDataButton?.addEventListener("click", () => {
    window.localStorage.removeItem(GO_GHOST_PROFILE_KEY);
    window.localStorage.removeItem(GO_GHOST_PROGRESS_KEY);
    hydrateGoGhostProfile();
    renderGoGhostAutomationScope();
    renderGoGhostProgress();
    showCopyToast("Go Ghost data cleared");
  });

  goGhostAutomationRows?.addEventListener("click", (event) => {
    const row = event.target.closest("[data-ghost-scope]");
    if (!row) return;
    openGoGhostScopeModal(row.dataset.ghostScope);
  });

  goGhostScopeModal?.addEventListener("click", (event) => {
    if (event.target === goGhostScopeModal || event.target.closest(".ghost-scope-close")) closeGoGhostScopeModal();
  });

  goGhostScopeSearchButton?.addEventListener("click", () => runGhostScopeAction("search"));
  goGhostScopeOptOutButton?.addEventListener("click", () => runGhostScopeAction("optout"));
  goGhostScopeAutoFillButton?.addEventListener("click", () => runGhostScopeAction("auto"));
  goGhostScopeCopyButton?.addEventListener("click", () => runGhostScopeAction("copy"));

  goGhostBrokerList?.addEventListener("change", (event) => {
    const checkbox = event.target.closest("[data-ghost-site][data-ghost-field]");
    if (!checkbox) return;
    setGhostProgress(checkbox.dataset.ghostSite, checkbox.dataset.ghostField, checkbox.checked);
  });

  goGhostBrokerList?.addEventListener("click", async (event) => {
    const autoButton = event.target.closest("[data-ghost-auto]");
    if (autoButton) {
      const broker = goGhostBrokers.find((item) => item.id === autoButton.dataset.ghostAuto);
      if (broker) await runGhostBrokerAutomation(broker, autoButton);
      return;
    }

    const copyButton = event.target.closest("[data-ghost-copy]");
    if (!copyButton) return;
    const profile = getGhostProfile();
    const broker = goGhostBrokers.find((item) => item.id === copyButton.dataset.ghostCopy);
    if (!broker) return;
    const searchUrl = goGhostBrokerSearchUrl(broker, profile);
    const copied = await copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
    showCopyToast(copied ? `${broker.name} details copied` : "Copy failed");
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !goGhostScopeModal?.classList.contains("hidden")) closeGoGhostScopeModal();
  });
}


// Generate QR: takes whatever URL is currently typed into the paste-URL
// input and asks the backend to render a SafeScan-verified QR PNG for it.
// The backend runs the URL through the full risk pipeline and refuses to
// render anything flagged as suspicious or dangerous, so the button is a
// "publish a safe QR" tool, not a generic QR maker.
(() => {
  const generateBtn = document.getElementById("generateQrButton");
  const urlInputField = document.getElementById("generateQrUrlInput");
  const wrap = document.getElementById("generatedQrWrap");
  const img = document.getElementById("generatedQrImage");
  const dl = document.getElementById("generatedQrDownload");
  const errEl = document.getElementById("generateQrError");
  if (!generateBtn || !urlInputField || !wrap || !img || !errEl) return;

  const showError = (message) => {
    errEl.textContent = message;
    errEl.classList.remove("hidden");
    wrap.classList.add("hidden");
  };
  const clearError = () => {
    errEl.textContent = "";
    errEl.classList.add("hidden");
  };

  generateBtn.addEventListener("click", async () => {
    clearError();
    const raw = urlInputField.value.trim();
    if (!raw) {
      showError("Paste a URL above first.");
      return;
    }
    let normalized = raw;
    if (!/^https?:\/\//i.test(normalized)) normalized = `https://${normalized}`;
    try {
      new URL(normalized);
    } catch (_err) {
      showError("That does not look like a valid URL.");
      return;
    }

    generateBtn.disabled = true;
    generateBtn.textContent = "Generating...";
    try {
      const res = await fetch("/api/qr/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized })
      });
      if (!res.ok) {
        let detail = "Could not generate QR.";
        try {
          const body = await res.json();
          detail = body.detail || body.error || detail;
        } catch (_err) {
          /* non-JSON 4xx body */
        }
        showError(detail);
        return;
      }
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      img.src = objectUrl;
      dl.href = objectUrl;
      wrap.classList.remove("hidden");
    } catch (err) {
      showError("Network error while generating QR.");
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = "Generate QR";
    }
  });
})();
