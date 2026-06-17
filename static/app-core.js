// app-core.js — constants, scroll/toast/fingerprint helpers, wallet connect/verify, airdrop profile.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
// =============================================================================
// app.js — primary front-end controller for the SafeScan site.
//
// This is the largest client script and wires up most interactive behaviour:
//   • Google Sign-In and the auth/session UI.
//   • Submitting URLs / QR images to the scan API and rendering the risk modal.
//   • The token "airdrop" / rewards profile stored in localStorage.
//   • Wallet (Phantom) connection prompts and various page widgets.
//
// Loaded as an external script (the site CSP is script-src 'self', so no inline
// scripts run). Constants below are public client identifiers / deep-link bases.
// =============================================================================
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
let riskModalScrollGuard = 0;

function targetHasScrollableAncestor(target) {
  for (let el = target instanceof Element ? target : null; el && el !== document.body; el = el.parentElement) {
    const style = window.getComputedStyle(el);
    const canScrollY = /(auto|scroll)/.test(style.overflowY) && el.scrollHeight > el.clientHeight + 1;
    if (canScrollY) return true;
  }
  return false;
}

window.addEventListener("wheel", (event) => {
  if (document.body.classList.contains("sidenav-open")) return;
  if (riskModal && !riskModal.classList.contains("hidden")) return;
  if (targetHasScrollableAncestor(event.target)) return;
  const before = window.scrollY || document.documentElement.scrollTop || 0;
  window.scrollBy({ top: event.deltaY, left: 0, behavior: "auto" });
  const after = window.scrollY || document.documentElement.scrollTop || 0;
  if (after !== before) event.preventDefault();
}, { passive: false });

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

