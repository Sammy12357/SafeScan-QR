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
let scanSubmitting = false;
let scanProgressTimer = 0;
let scanDeadlineTimer = 0;
let scanPaintTimer = 0;
let scanSubmitter = null;
let scanSubmitterNodes = null;
let copyToastTimer = 0;
let riskModalScrollGuard = 0;

// A dialog must keep keyboard focus inside it and make the page behind it inert.
// Return the cleanup so callers can restore the exact previous inert state.
function trapModalFocus(modal, onEscape) {
  const outside = [];
  for (let branch = modal; branch.parentElement && branch !== document.body; branch = branch.parentElement) {
    for (const sibling of branch.parentElement.children) {
      if (sibling !== branch) {
        outside.push({ element: sibling, inert: sibling.inert });
        sibling.inert = true;
      }
    }
  }
  const onKeyDown = (event) => {
    if (!modal.isConnected || modal.classList.contains("hidden") || modal.closest("[inert]")) return;
    if (event.key === "Escape") {
      event.preventDefault();
      onEscape();
    } else if (event.key === "Tab") {
      const focusable = Array.from(modal.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'))
        .filter((element) => !element.hidden && element.getClientRects().length > 0);
      if (!focusable.length) { event.preventDefault(); return; }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !modal.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !modal.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    }
  };
  document.addEventListener("keydown", onKeyDown);
  return () => {
    document.removeEventListener("keydown", onKeyDown);
    outside.forEach(({ element, inert }) => { if (element.isConnected) element.inert = inert; });
  };
}

// Keep wheel and touch scrolling native. Intercepting wheel events here
// competes with smooth scrolling and nested modal/menu scroll containers.

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
}).catch(() => { deviceFingerprint = ""; });

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
  try {
    if (!profile) {
      window.localStorage.removeItem(AIRDROP_STORAGE_KEY);
      return true;
    }
    window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(profile));
    return true;
  } catch {
    // The server owns wallet verification; unavailable browser storage must
    // not stop the rest of the scanner or privacy controls from loading.
    return false;
  }
}

function getCurrentProfile() {
  const profileEmail = document.querySelector(".profile-email");
  const email = profileEmail?.dataset?.email || profileEmail?.textContent?.trim();
  if (!email) return null;
  const stored = getStoredAirdropProfile();
  const sameAccount = stored && typeof stored === "object" && !Array.isArray(stored) &&
    String(stored.email || "").toLowerCase() === email.toLowerCase();
  const profile = sameAccount ? { ...stored, email } : { email };
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
    let timeout = 0;
    try {
      await Promise.race([
        navigator.clipboard.writeText(value),
        new Promise((_, reject) => {
          timeout = window.setTimeout(() => reject(new Error("Clipboard copy timed out")), 15000);
        })
      ]);
      return true;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  const textarea = document.createElement("textarea");
  const previousFocus = document.activeElement;
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
    if (previousFocus?.isConnected && typeof previousFocus.focus === "function") {
      try { previousFocus.focus({ preventScroll: true }); } catch { previousFocus.focus(); }
    }
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
  const profile = getAuthoritativeWalletProfile();
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

const WALLET_API_TIMEOUT_MS = 12000;
const WALLET_PROVIDER_TIMEOUT_MS = 30000;
let activeWalletOperation = null;
let walletReturnFocus = null;
let walletModalFocusCleanup = null;
let walletMutationVersion = 0;
let confirmedWalletProfile = null;
let walletBusyButtons = [];

function getAuthoritativeWalletProfile() {
  const account = getCurrentProfile();
  if (!account) return null;
  if (confirmedWalletProfile?.email?.toLowerCase() === account.email.toLowerCase()) {
    return { ...confirmedWalletProfile };
  }
  return { email: account.email };
}

function walletFriendlyError(error, action) {
  if (navigator.onLine === false) return "You're offline. Reconnect and try again.";
  if (error?.status === 401) return "Your sign-in expired. Sign in again, then try the wallet action.";
  if (error?.code === 4001 || error?.code === "4001") return "The wallet request was not approved. Try again when you're ready.";
  if (error?.name === "AbortError" || /timed out/i.test(error?.message || "")) {
    return `The wallet ${action} took too long. Check your connection and try again.`;
  }
  return `The wallet ${action} could not finish. Check your wallet and try again.`;
}

function walletCancelledError() {
  const error = new Error("Wallet action cancelled.");
  error.code = "wallet_cancelled";
  return error;
}

function boundedWalletStep(task, timeoutMs, signal, timeoutMessage) {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    let settled = false;
    let timer = 0;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      signal?.removeEventListener("abort", onCancel);
      if (error) reject(error);
      else resolve(value);
    };
    const onCancel = () => {
      controller.abort();
      finish(walletCancelledError());
    };
    if (signal?.aborted) {
      onCancel();
      return;
    }
    signal?.addEventListener("abort", onCancel, { once: true });
    timer = window.setTimeout(() => {
      controller.abort();
      finish(new Error(timeoutMessage));
    }, timeoutMs);
    Promise.resolve().then(() => {
      if (!settled) return task(controller.signal);
      return undefined;
    }).then((value) => finish(null, value), (error) => finish(error));
  });
}

function walletJsonRequest(url, options = {}, operation = null, allowedStatuses = [], includeStatus = false) {
  return boundedWalletStep(async (signal) => {
    const response = await fetch(url, { ...options, signal, credentials: "same-origin" });
    let body = {};
    try { body = await response.json(); } catch (_) { /* The HTTP status still determines failure. */ }
    if (!body || typeof body !== "object") body = {};
    if (!response.ok && !allowedStatuses.includes(response.status)) {
      const error = new Error(typeof body.error === "string" ? body.error : "Wallet request failed. Try again.");
      error.status = response.status;
      throw error;
    }
    return includeStatus ? { body, status: response.status } : body;
  }, WALLET_API_TIMEOUT_MS, operation?.controller.signal, "Wallet request timed out. Check your connection and try again.");
}

function startWalletOperation() {
  if (activeWalletOperation) activeWalletOperation.controller.abort();
  walletMutationVersion += 1;
  const operation = { controller: new AbortController() };
  activeWalletOperation = operation;
  const focused = document.activeElement;
  if (focused && focused !== document.body) walletReturnFocus = focused;
  return operation;
}

function currentWalletOperation(operation) {
  return activeWalletOperation === operation && !operation.controller.signal.aborted;
}

function finishWalletOperation(operation) {
  if (!currentWalletOperation(operation)) return;
  activeWalletOperation = null;
  clearWalletBusy();
}

function removeWalletModal() {
  if (activeWalletOperation) {
    activeWalletOperation.controller.abort();
    activeWalletOperation = null;
    walletMutationVersion += 1;
    clearWalletBusy();
  }
  walletModalFocusCleanup?.();
  walletModalFocusCleanup = null;
  document.querySelector(".wallet-modal")?.remove();
  const target = walletReturnFocus?.isConnected && !walletReturnFocus.disabled
    ? walletReturnFocus
    : dom.disconnectWalletButton?.isConnected && !dom.disconnectWalletButton.classList.contains("hidden") && !dom.disconnectWalletButton.disabled
      ? dom.disconnectWalletButton
      : dom.walletStatus?.isConnected ? dom.walletStatus : document.querySelector("main h1, main h2");
  if (target) {
    if (target === dom.walletStatus || target.matches?.("main h1, main h2")) target.tabIndex = -1;
    try { target.focus({ preventScroll: true }); } catch (_) { target.focus(); }
  }
  walletReturnFocus = null;
}

function showWalletModal(content) {
  walletModalFocusCleanup?.();
  document.querySelector(".wallet-modal")?.remove();
  const modal = document.createElement("div");
  modal.className = "wallet-modal";
  modal.setAttribute("role", "dialog");
  modal.setAttribute("aria-modal", "true");
  modal.innerHTML = `<div class="wallet-modal-card"><button class="wallet-modal-close" type="button" aria-label="Close wallet dialog" style="position:absolute;top:12px;right:12px;display:grid;place-items:center;width:34px;height:34px;border:1px solid rgba(255,110,127,0.72);border-radius:8px;background:rgba(255,110,127,0.16);color:#ff6e7f;font-family:inherit;font-size:1rem;font-weight:900;line-height:1;cursor:pointer;z-index:3;">X</button>${content}</div>`;
  const heading = modal.querySelector("h3");
  if (heading) {
    heading.id = "walletModalTitle";
    modal.setAttribute("aria-labelledby", heading.id);
  }
  modal.addEventListener("click", (event) => {
    if (event.target === modal) removeWalletModal();
  });
  modal.querySelector(".wallet-modal-close")?.addEventListener("click", removeWalletModal);
  document.body.appendChild(modal);
  walletModalFocusCleanup = trapModalFocus(modal, removeWalletModal);
  const close = modal.querySelector(".wallet-modal-close");
  try { close?.focus({ preventScroll: true }); } catch (_) { close?.focus(); }
  return modal;
}

function showSignInWalletModal(message = "Sign in first to connect and verify a wallet.") {
  if (document.activeElement && document.activeElement !== document.body) walletReturnFocus = document.activeElement;
  const next = encodeURIComponent(`${window.location.pathname}${window.location.search}${window.location.hash}`);
  showWalletModal(`<h3>Sign in required</h3><p>${escapeHtml(message)}</p><div class="wallet-modal-actions"><a class="primary-button" href="/login?next=${next}">Sign in / Sign up</a></div>`);
}

function setWalletBusy(message) {
  if (dom.walletStatus) dom.walletStatus.textContent = message;
  const disconnecting = message.startsWith("Disconnecting");
  [dom.connectWalletButton, dom.topConnectWalletButton, dom.disconnectWalletButton].forEach((button) => {
    if (!button) return;
    if (!walletBusyButtons.some((entry) => entry.button === button)) {
      walletBusyButtons.push({ button, label: button.textContent, busy: button.getAttribute("aria-busy") });
    }
    button.textContent = disconnecting && button === dom.disconnectWalletButton ? "Disconnecting…" : "Connecting…";
    button.setAttribute("aria-busy", "true");
    button.disabled = true;
  });
}

function clearWalletBusy() {
  walletBusyButtons.forEach(({ button, label, busy }) => {
    button.textContent = label;
    if (busy === null) button.removeAttribute("aria-busy");
    else button.setAttribute("aria-busy", busy);
  });
  walletBusyButtons = [];
  renderWalletState(getAuthoritativeWalletProfile());
  if (dom.disconnectWalletButton) dom.disconnectWalletButton.disabled = false;
}

function renderWalletState(profile = getAuthoritativeWalletProfile()) {
  const walletAddr = profile?.walletAddress || "";
  const verified = Boolean(profile?.walletVerified);

  if (dom.hiddenWalletInput) dom.hiddenWalletInput.value = verified ? walletAddr : "";

  if (!profile) {
    if (dom.walletStatus) dom.walletStatus.textContent = "Sign in to unlock wallet connection.";
    dom.connectWalletButton?.classList.remove("hidden");
    if (dom.connectWalletButton) dom.connectWalletButton.disabled = false;
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
    if (dom.connectWalletButton) dom.connectWalletButton.disabled = false;
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
  if (dom.connectWalletButton) dom.connectWalletButton.disabled = true;
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
  const startedAtVersion = walletMutationVersion;
  try {
    const body = await walletJsonRequest("/api/wallet");
    if (startedAtVersion !== walletMutationVersion) return;
    if (typeof body.connected !== "boolean") throw new Error("Wallet status response was incomplete.");
    const updatedProfile = { ...profile };
    if (body.connected && body.walletAddress) {
      updatedProfile.walletAddress = body.walletAddress;
      updatedProfile.walletVerified = true;
    } else {
      delete updatedProfile.walletAddress;
      delete updatedProfile.walletVerified;
    }
    setStoredAirdropProfile(updatedProfile);
    confirmedWalletProfile = updatedProfile;
    renderWalletState(updatedProfile);
    document.getElementById("walletFeedback")?.remove();
  } catch {
    if (startedAtVersion !== walletMutationVersion) return;
    const unverifiedProfile = { email: profile.email };
    setStoredAirdropProfile(unverifiedProfile);
    confirmedWalletProfile = unverifiedProfile;
    renderWalletState(unverifiedProfile);
    showWalletFeedback("error", "Wallet status couldn't be checked. Check your connection and try again.", syncWalletFromServer, "Wallet status unavailable");
  }
}

async function verifySelectedWallet(wallet, operation) {
  if (!currentWalletOperation(operation)) return;
  const profile = getCurrentProfile();
  if (!profile) {
    showSignInWalletModal("Sign in in this browser first, then connect your wallet for airdrop verification.");
    return;
  }
  try {
    setWalletBusy("Requesting verification challenge...");
    showWalletModal("<h3>Connecting wallet</h3><p>Requesting verification challenge...</p><div class='wallet-spinner'></div>");
    const connectResponse = await boundedWalletStep(
      () => wallet.provider.connect(), WALLET_PROVIDER_TIMEOUT_MS, operation.controller.signal,
      "The wallet did not respond to the connection request. Try again."
    );
    const publicKey = connectResponse?.publicKey || wallet.provider.publicKey;
    const walletAddress = publicKey?.toString();
    if (!walletAddress) throw new Error("Wallet did not return a public key.");

    const nonceBody = await walletJsonRequest("/api/wallet/nonce", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ walletAddress })
    }, operation);
    if (!nonceBody.message) throw new Error("The wallet challenge was incomplete. Try again.");

    setWalletBusy("Check your wallet and approve the signature request.");
    showWalletModal("<h3>Approve signature</h3><p>Check your wallet. This is free and does not send a transaction.</p><div class='wallet-spinner'></div>");
    if (typeof wallet.provider.signMessage !== "function") {
      throw new Error("This wallet does not support message signing.");
    }
    const messageBytes = new TextEncoder().encode(nonceBody.message);
    const signed = await boundedWalletStep(
      () => wallet.provider.signMessage(messageBytes, "utf8"), WALLET_PROVIDER_TIMEOUT_MS,
      operation.controller.signal, "The wallet signature request timed out. Try again."
    );
    const signatureBytes = signed?.signature || signed;
    const signature = normalizeSignature(signatureBytes);

    setWalletBusy("Verifying signature...");
    showWalletModal("<h3>Verifying wallet</h3><p>SafeScan is checking the signature server-side...</p><div class='wallet-spinner'></div>");
    const verifyBody = await walletJsonRequest("/api/wallet/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ walletAddress, signature })
    }, operation);
    if (!verifyBody.walletAddress) throw new Error("Wallet verification was incomplete. Check the connection and try again.");

    walletMutationVersion += 1;
    const updatedProfile = { ...profile, walletAddress: verifyBody.walletAddress, walletVerified: true };
    setStoredAirdropProfile(updatedProfile);
    confirmedWalletProfile = updatedProfile;
    renderWalletState(updatedProfile);
    document.getElementById("walletFeedback")?.remove();
    showWalletModal(`<h3>Wallet connected</h3><div class="wallet-success-spacer" aria-hidden="true"></div><button class="primary-button wallet-close-button" type="button">Done</button>`);
    document.querySelector(".wallet-close-button")?.addEventListener("click", removeWalletModal);
    document.querySelector(".wallet-close-button")?.focus({ preventScroll: true });
  } catch (error) {
    if (!currentWalletOperation(operation)) return;
    renderWalletState(getAuthoritativeWalletProfile());
    const message = walletFriendlyError(error, "connection");
    showWalletFeedback("error", message, connectWallet, "Wallet connection failed");
    showWalletModal(`<h3>Wallet connection failed</h3><p class="wallet-error">${escapeHtml(message)}</p><button class="primary-button wallet-retry-button" type="button">Try again</button>`);
    document.querySelector(".wallet-retry-button")?.addEventListener("click", connectWallet);
    document.querySelector(".wallet-retry-button")?.focus({ preventScroll: true });
  } finally {
    finishWalletOperation(operation);
  }
}

async function connectWallet() {
  const profile = getCurrentProfile();
  if (!profile) {
    showSignInWalletModal("Sign in first. If you opened from iPhone Safari, open this page in Phantom and sign in there before connecting.");
    return;
  }
  const operation = startWalletOperation();
  setWalletBusy("Looking for a Solana wallet...");
  showWalletModal("<h3>Looking for wallet</h3><p>Checking for a Solana wallet provider...</p><div class='wallet-spinner'></div>");
  let wallets;
  try {
    wallets = await boundedWalletStep(
      () => waitForSolanaWallets(), 2500, operation.controller.signal,
      "Wallet detection timed out. Try again."
    );
  } catch (error) {
    if (!currentWalletOperation(operation)) return;
    const message = walletFriendlyError(error, "connection");
    showWalletFeedback("error", message, connectWallet, "Wallet unavailable");
    showWalletModal(`<h3>Wallet unavailable</h3><p class="wallet-error">${escapeHtml(message)}</p><button class="primary-button wallet-retry-button" type="button">Try again</button>`);
    document.querySelector(".wallet-retry-button")?.addEventListener("click", connectWallet);
    document.querySelector(".wallet-retry-button")?.focus({ preventScroll: true });
    finishWalletOperation(operation);
    return;
  }
  if (!currentWalletOperation(operation)) return;
  if (!wallets.length) {
    const mobileCopy = isMobileDevice()
      ? `<p>${mobileWalletHelpText()}</p>${!window.isSecureContext ? "<p class='wallet-hint'>Wallet browsers only inject providers on HTTPS, localhost, or 127.0.0.1.</p>" : ""}`
      : "<p>Install a Solana wallet extension, then refresh this page and connect again.</p>";
    showWalletModal(`<h3>No Solana wallet detected</h3>${mobileCopy}${walletInstallLinksHtml(isMobileDevice())}<button class="secondary-button wallet-retry-button" type="button">Check again</button>`);
    document.querySelector(".wallet-retry-button")?.addEventListener("click", connectWallet);
    document.querySelector(".wallet-retry-button")?.focus({ preventScroll: true });
    finishWalletOperation(operation);
    return;
  }
  const modal = showWalletModal(`<h3>Select wallet</h3><div class="wallet-choice-list">${wallets.map((wallet, index) => `<div class="wallet-choice-row"><button class="secondary-button wallet-choice-button" data-wallet-index="${index}" type="button">${escapeHtml(wallet.name)}</button>${walletDisconnectButtonHtml(wallet, index)}</div>`).join("")}</div>`);
  modal.querySelectorAll("[data-wallet-index]").forEach((button) => {
    button.addEventListener("click", () => verifySelectedWallet(wallets[Number(button.dataset.walletIndex)], operation));
  });
  modal.querySelectorAll("[data-wallet-disconnect-index]").forEach((button) => {
    button.addEventListener("click", () => disconnectWalletConnection(wallets[Number(button.dataset.walletDisconnectIndex)], { closeModal: true }));
  });
}

dom.connectWalletButton?.addEventListener("click", connectWallet);
dom.topConnectWalletButton?.addEventListener("click", connectWallet);

function showWalletFeedback(type, message, retry, title = "Wallet action failed") {
  const anchor = document.querySelector(".wallet-panel") || dom.connectWalletButton || dom.disconnectWalletButton || dom.topConnectWalletButton;
  if (!anchor || !window.UIStates) return;
  let host = document.getElementById("walletFeedback");
  if (!host) {
    host = document.createElement("div");
    host.id = "walletFeedback";
    anchor.insertAdjacentElement("afterend", host);
  }
  if (type === "error") {
    UIStates.error(host, {
      title,
      body: message,
      retry,
      compact: true,
      focus: !document.querySelector(".wallet-modal")
    });
  } else {
    UIStates.notice(host, { type, message });
  }
}

function showActionFeedback(anchor, id, message) {
  if (!anchor || !window.UIStates) return;
  let host = document.getElementById(id);
  if (!host) {
    host = document.createElement("div");
    host.id = id;
    host.className = "action-feedback";
    const panel = anchor.closest(".wallet-panel, .token-address-row") || anchor;
    panel.insertAdjacentElement("afterend", host);
  }
  UIStates.notice(host, { type: "danger", message });
}

async function disconnectWalletConnection(wallet = null, options = {}) {
  const { closeModal = false, notify = true } = options;
  const profile = getAuthoritativeWalletProfile();
  if (!profile) {
    showSignInWalletModal("Sign in again before disconnecting a wallet from SafeScan.");
    return;
  }
  const operation = startWalletOperation();
  setWalletBusy("Disconnecting wallet...");
  if (closeModal) showWalletModal("<h3>Disconnecting wallet</h3><p>Removing the SafeScan link...</p><div class='wallet-spinner'></div>");
  try {
    // Browser cache and wallet-provider state do not prove whether this account
    // is linked on the server. Always ask SafeScan to remove its link first.
    const deletion = await walletJsonRequest("/api/wallet", { method: "DELETE" }, operation, [404], true);
    if (!currentWalletOperation(operation)) return;
    if (deletion.status !== 404 && deletion.body.success !== true) {
      throw new Error("Wallet unlink was not confirmed.");
    }
    walletMutationVersion += 1;
    const updatedProfile = { email: profile.email };
    setStoredAirdropProfile(updatedProfile);
    confirmedWalletProfile = updatedProfile;

    let providerFailed = false;
    if (typeof wallet?.provider?.disconnect === "function") {
      if (closeModal) showWalletModal("<h3>SafeScan link removed</h3><p>Disconnecting this site in your wallet app...</p><div class='wallet-spinner'></div>");
      try {
        await boundedWalletStep(
          () => wallet.provider.disconnect(), WALLET_PROVIDER_TIMEOUT_MS, operation.controller.signal,
          "The wallet did not respond to the disconnect request."
        );
      } catch {
        providerFailed = true;
      }
    }
    if (!currentWalletOperation(operation)) return;
    finishWalletOperation(operation);
    if (providerFailed) {
      const warning = "The SafeScan wallet link was removed, but your wallet app may still list this site as connected. Disconnect it in the wallet app if needed.";
      if (closeModal) {
        showWalletModal(`<h3>SafeScan link removed</h3><p class="wallet-error">${escapeHtml(warning)}</p><button class="primary-button wallet-close-button" type="button">Done</button>`);
        document.querySelector(".wallet-close-button")?.addEventListener("click", removeWalletModal);
      }
      showWalletFeedback("warning", warning);
    } else {
      if (closeModal) removeWalletModal();
      if (notify) showWalletFeedback("success", "Wallet disconnected from SafeScan.");
    }
  } catch (error) {
    if (!currentWalletOperation(operation)) return;
    if (error?.status === 401) {
      const unverifiedProfile = { email: profile.email };
      setStoredAirdropProfile(unverifiedProfile);
      confirmedWalletProfile = unverifiedProfile;
    }
    const message = walletFriendlyError(error, "disconnect");
    showWalletFeedback("error", message, () => disconnectWalletConnection(wallet, options), "Wallet disconnect failed");
    if (closeModal) {
      showWalletModal(`<h3>Wallet disconnect failed</h3><p class="wallet-error">${escapeHtml(message)}</p><button class="primary-button wallet-retry-button" type="button">Try again</button>`);
      document.querySelector(".wallet-retry-button")?.addEventListener("click", () => disconnectWalletConnection(wallet, options));
      document.querySelector(".wallet-retry-button")?.focus({ preventScroll: true });
    }
  } finally {
    finishWalletOperation(operation);
  }
}

dom.disconnectWalletButton?.addEventListener("click", () => disconnectWalletConnection());

dom.demoWalletButton?.addEventListener("click", () => {
  showWalletFeedback("warning", "Demo wallets cannot verify airdrop eligibility. Connect a real wallet and approve the signature request.");
});

dom.copyTokenAddressButton?.addEventListener("click", async () => {
  if (dom.copyTokenAddressButton.disabled) return;
  const tokenAddress = dom.tokenAddress?.textContent?.trim() || "";
  window.clearTimeout(dom.copyTokenAddressButton.dataset.resetTimer);
  if (!tokenAddress) {
    showActionFeedback(dom.copyTokenAddressButton, "tokenCopyFeedback", "No token address is available to copy.");
    return;
  }
  const hadFocus = document.activeElement === dom.copyTokenAddressButton;
  dom.copyTokenAddressButton.disabled = true;
  dom.copyTokenAddressButton.setAttribute("aria-busy", "true");
  dom.copyTokenAddressButton.textContent = "Copying…";
  try {
    const copied = await copyTextToClipboard(tokenAddress);
    if (!copied) throw new Error("Clipboard did not confirm the copy");
    document.getElementById("tokenCopyFeedback")?.remove();
    dom.copyTokenAddressButton.textContent = "Copied";
    dom.tokenAddress?.classList.remove("token-address-copied");
    void dom.tokenAddress?.offsetWidth;
    dom.tokenAddress?.classList.add("token-address-copied");
    dom.copyTokenAddressButton.dataset.resetTimer = String(window.setTimeout(() => {
      dom.copyTokenAddressButton.textContent = "Copy";
    }, 1400));
  } catch {
    dom.copyTokenAddressButton.textContent = "Copy";
    showActionFeedback(dom.copyTokenAddressButton, "tokenCopyFeedback", "We couldn't copy the address. Check your browser's clipboard permission and try again.");
  } finally {
    dom.copyTokenAddressButton.disabled = false;
    dom.copyTokenAddressButton.removeAttribute("aria-busy");
    if (hadFocus && document.activeElement === document.body) dom.copyTokenAddressButton.focus();
  }
});

dom.topCopyReferralButton?.addEventListener("click", () => {
  if (dom.topCopyReferralButton.disabled) return;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 15000);
  UIStates.busy(dom.topCopyReferralButton, async () => {
    try {
      const body = await UIStates.fetchJson("/api/referral", { credentials: "same-origin", signal: controller.signal });
      const referralLink = body.referralLink || body.link;
      if (!referralLink) throw new Error("Referral link unavailable");
      let copied = false;
      try { copied = await copyTextToClipboard(referralLink); } catch { /* Show the same clipboard guidance below. */ }
      if (!copied) {
        const copyProblem = new Error("Clipboard did not confirm the copy");
        copyProblem.code = "clipboard_failed";
        throw copyProblem;
      }
      document.getElementById("referralCopyFeedback")?.remove();
      showCopyToast("Copied link");
    } catch (problem) {
      const message = problem?.status === 401
        ? "Sign in to copy your referral link."
        : controller.signal.aborted
          ? "The referral link took too long to load. Try again."
          : problem?.code === "offline"
            ? "You're offline. Reconnect and try again."
            : problem?.code === "clipboard_failed"
              ? "We couldn't copy the link. Check your browser's clipboard permission and try again."
              : "Your referral link isn't available right now. Try again later.";
      showActionFeedback(dom.topCopyReferralButton, "referralCopyFeedback", message);
    } finally {
      window.clearTimeout(timer);
    }
  }, { label: "Copying…" });
});

function showAnalysisProgress(label, form = null) {
  if (!analysisLoadingState) return;
  if (form && analysisLoadingState.parentElement !== form) form.appendChild(analysisLoadingState);
  analysisLoadingState.classList.add("scan-status");
  analysisLoadingState.classList.remove("scan-progress-host", "hidden");
  analysisLoadingState.setAttribute("role", "status");
  const intro = document.createElement("div");
  intro.className = "scan-progress-intro";
  const spinner = document.createElement("span");
  spinner.className = "state-spinner";
  spinner.setAttribute("aria-hidden", "true");
  const title = document.createElement("strong");
  title.textContent = label;
  intro.append(spinner, title);
  const list = document.createElement("ol");
  list.className = "scan-progress-steps";
  list.setAttribute("aria-hidden", "true");
  ["Submit payload", "Check for risk", "Review result"].forEach((step, index) => {
    const item = document.createElement("li");
    item.textContent = step;
    if (index === 0) item.className = "is-complete";
    if (index === 1) item.className = "is-current";
    list.appendChild(item);
  });
  const hint = document.createElement("p");
  hint.className = "scan-progress-hint";
  hint.textContent = "This usually takes a few seconds.";
  analysisLoadingState.replaceChildren(intro, list, hint);
  window.clearTimeout(scanProgressTimer);
  scanProgressTimer = window.setTimeout(() => {
    hint.textContent = "Still working. Keep this page open while we finish checking.";
  }, 10000);
}

function showCameraError(message) {
  if (!analysisLoadingState || !window.UIStates) return;
  analysisLoadingState.classList.remove("scan-status", "hidden");
  analysisLoadingState.classList.add("scan-progress-host");
  UIStates.error(analysisLoadingState, {
    title: "Camera scan stopped",
    body: message || "Try again or upload a QR photo instead.",
    retry: openCameraScanner,
    focus: true
  });
}

function resetScanSubmission() {
  window.clearTimeout(scanProgressTimer);
  window.clearTimeout(scanDeadlineTimer);
  window.clearTimeout(scanPaintTimer);
  scanSubmitting = false;
  if (scanCameraButton) scanCameraButton.disabled = false;
  if (scanSubmitter && scanSubmitterNodes) {
    scanSubmitter.replaceChildren(...scanSubmitterNodes);
    scanSubmitter.disabled = false;
    scanSubmitter.removeAttribute("aria-busy");
  }
  scanSubmitter = null;
  scanSubmitterNodes = null;
}

function showScanTimeout(form) {
  if (!scanSubmitting || !form.isConnected) return;
  window.stop();
  resetScanSubmission();
  if (!analysisLoadingState) return;
  analysisLoadingState.removeAttribute("role");
  analysisLoadingState.classList.remove("scan-status", "hidden");
  analysisLoadingState.classList.add("scan-progress-host");
  if (window.UIStates) {
    UIStates.error(analysisLoadingState, {
      title: "Scan response took too long",
      body: "Check your connection and try again. Your QR input is still here.",
      retry: () => { if (form.isConnected) form.requestSubmit(); },
      focus: true
    });
  } else {
    analysisLoadingState.textContent = "Scan response took too long. Check your connection and try again.";
  }
}

function startScanSubmission(event, label) {
  if (scanSubmitting) {
    event.preventDefault();
    return;
  }
  // Give the progress panel one paint before native form navigation begins.
  // These two scanner forms do not use submitter name/value fields.
  event.preventDefault();
  scanSubmitting = true;
  const form = event.currentTarget;
  showAnalysisProgress(label, form);
  if (scanCameraButton) scanCameraButton.disabled = true;
  if (event.submitter && event.submitter.tagName === "BUTTON") {
    scanSubmitter = event.submitter;
    scanSubmitterNodes = Array.from(scanSubmitter.childNodes);
    const spinner = document.createElement("span");
    spinner.className = "button-spinner";
    spinner.setAttribute("aria-hidden", "true");
    scanSubmitter.replaceChildren(spinner, document.createTextNode("Checking…"));
    scanSubmitter.disabled = true;
    scanSubmitter.setAttribute("aria-busy", "true");
  }
  scanDeadlineTimer = window.setTimeout(() => showScanTimeout(form), 15000);
  scanPaintTimer = window.setTimeout(() => {
    if (form.isConnected) HTMLFormElement.prototype.submit.call(form);
  }, 120);
}

dom.qrForm?.addEventListener("submit", (event) => startScanSubmission(event, "Checking this QR image"));
document.getElementById("urlForm")?.addEventListener("submit", (event) => startScanSubmission(event, "Checking this QR payload"));
window.addEventListener("pagehide", () => {
  window.clearTimeout(scanProgressTimer);
  window.clearTimeout(scanDeadlineTimer);
  window.clearTimeout(scanPaintTimer);
});
window.addEventListener("pageshow", (event) => {
  if (!event.persisted) return;
  resetScanSubmission();
  analysisLoadingState?.classList.add("hidden");
});

const qrImageInput = document.getElementById("qrImageInput");
qrImageInput?.addEventListener("change", () => {
  if (qrImageInput.files && qrImageInput.files.length > 0) {
    const form = qrImageInput.form;
    showAnalysisProgress("Preparing your QR image", form);
    if (form) {
      window.setTimeout(() => {
        form.requestSubmit ? form.requestSubmit() : form.submit();
      }, 80);
    }
  }
});

// Live camera scan. The scanner module (qr-camera.js) handles camera
// access, local burst decoding, guidance, and optional server retry. We feed a decoded payload
// into the manual payload form so the same /search_qr_api pipeline
// runs on the result.
const scanCameraButton = document.getElementById("scanCameraButton");
function openCameraScanner() {
  if (!window.SafeScanQrCamera || typeof window.SafeScanQrCamera.open !== "function") {
    showCameraError("The camera is still getting ready. Wait a moment, then try again.");
    return;
  }
  window.SafeScanQrCamera.open({
    onResult: (value) => {
      const urlInput = document.getElementById("urlInput");
      const form = document.getElementById("urlForm");
      if (urlInput) urlInput.value = value;
      showAnalysisProgress("Checking this QR payload", form);
      if (form) {
        form.requestSubmit ? form.requestSubmit() : form.submit();
      }
    },
    onServerFallback: (blob) => {
      const input = document.getElementById("qrImageInput");
      const form = document.getElementById("qrForm");
      const source = document.getElementById("cameraCaptureSource");
      if (!blob || !input || !form || !source || typeof DataTransfer !== "function" || typeof File !== "function") return false;
      const transfer = new DataTransfer();
      transfer.items.add(new File([blob], "safescan-camera-frame.jpg", { type: "image/jpeg" }));
      input.files = transfer.files;
      source.value = "camera_frame";
      showAnalysisProgress("Checking this QR photo", form);
      form.requestSubmit ? form.requestSubmit() : form.submit();
      return true;
    }
  });
}
scanCameraButton?.addEventListener("click", openCameraScanner);

