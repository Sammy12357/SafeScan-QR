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

function detectedSolanaWallets() {
  const wallets = [];
  const seen = new Set();
  const add = (name, provider, url) => {
    if (!provider || seen.has(provider)) return;
    seen.add(provider);
    wallets.push({ name, provider, url });
  };
  add("Phantom", window.phantom?.solana || (window.solana?.isPhantom ? window.solana : null), "https://phantom.app/");
  add("Solflare", window.solflare || (window.solana?.isSolflare ? window.solana : null), "https://solflare.com/");
  add("Backpack", window.backpack?.solana, "https://backpack.app/");
  add("Solana Wallet", window.solana, "https://phantom.app/");
  return wallets;
}

function removeWalletModal() {
  document.querySelector(".wallet-modal")?.remove();
}

function showWalletModal(content) {
  removeWalletModal();
  const modal = document.createElement("div");
  modal.className = "wallet-modal";
  modal.innerHTML = `<div class="wallet-modal-card">${content}</div>`;
  modal.addEventListener("click", (event) => {
    if (event.target === modal) removeWalletModal();
  });
  document.body.appendChild(modal);
  return modal;
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
    if (dom.walletStatus) dom.walletStatus.textContent = "Sign in to unlock verified wallet connection.";
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
    dom.walletStatus.innerHTML = `Verified: <a href="https://solscan.io/account/${walletAddr}" target="_blank" rel="noopener">${truncateAddress(walletAddr)}</a>`;
  }
  dom.connectWalletButton?.classList.add("hidden");
  dom.disconnectWalletButton?.classList.remove("hidden");

  if (dom.topConnectWalletButton) {
    dom.topConnectWalletButton.textContent = "Wallet verified";
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
  if (!profile) { window.alert("Sign in with Google first."); return; }
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
    const signature = base58Encode(signatureBytes);

    setWalletBusy("Verifying signature...");
    showWalletModal("<h3>Verifying wallet</h3><p>SafeScan is checking the signature server-side...</p><div class='wallet-spinner'></div>");
    const verifyResponse = await fetch("/api/wallet/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ walletAddress, signature })
    });
    const verifyBody = await verifyResponse.json();
    if (!verifyResponse.ok) throw new Error(verifyBody.error || "Wallet verification failed.");

    const updatedProfile = { ...profile, walletAddress: verifyBody.walletAddress, walletVerified: true };
    setStoredAirdropProfile(updatedProfile);
    renderWalletState(updatedProfile);
    showWalletModal(`<h3>Wallet verified</h3><p class="wallet-success">Connected ${truncateAddress(verifyBody.walletAddress)}</p><a href="https://solscan.io/account/${verifyBody.walletAddress}" target="_blank" rel="noopener">View on Solscan</a><button class="primary-button wallet-close-button" type="button">Done</button>`);
    document.querySelector(".wallet-close-button")?.addEventListener("click", removeWalletModal);
  } catch (error) {
    renderWalletState(getCurrentProfile());
    showWalletModal(`<h3>Wallet verification failed</h3><p class="wallet-error">${escapeHtml(error.message || "Signature rejected. Try again.")}</p><button class="primary-button wallet-retry-button" type="button">Try Again</button>`);
    document.querySelector(".wallet-retry-button")?.addEventListener("click", connectWallet);
  } finally {
    clearWalletBusy();
  }
}

async function connectWallet() {
  const profile = getCurrentProfile();
  if (!profile) { window.alert("Sign in with Google first."); return; }
  const wallets = detectedSolanaWallets();
  if (!wallets.length) {
    showWalletModal("<h3>No Solana wallet detected</h3><p>Install Phantom or Solflare to continue.</p><div class='wallet-install-links'><a href='https://phantom.app/' target='_blank' rel='noopener'>Install Phantom</a><a href='https://solflare.com/' target='_blank' rel='noopener'>Install Solflare</a></div>");
    return;
  }
  const modal = showWalletModal(`<h3>Select wallet</h3><div class="wallet-choice-list">${wallets.map((wallet, index) => `<button class="secondary-button wallet-choice-button" data-wallet-index="${index}" type="button">${wallet.name}</button>`).join("")}</div>`);
  modal.querySelectorAll("[data-wallet-index]").forEach((button) => {
    button.addEventListener("click", () => verifySelectedWallet(wallets[Number(button.dataset.walletIndex)]));
  });
}

dom.connectWalletButton?.addEventListener("click", connectWallet);
dom.topConnectWalletButton?.addEventListener("click", connectWallet);

dom.disconnectWalletButton?.addEventListener("click", async () => {
  const profile = getCurrentProfile();
  if (!profile) return;
  try {
    const response = await fetch("/api/wallet", { method: "DELETE" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "Wallet disconnect failed.");
    const updatedProfile = { ...profile };
    delete updatedProfile.walletAddress;
    delete updatedProfile.walletVerified;
    setStoredAirdropProfile(updatedProfile);
    renderWalletState(updatedProfile);
    window.alert("Wallet disconnected.");
  } catch (error) {
    window.alert(error.message || "Wallet disconnect failed.");
  }
});

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
    if (form) form.requestSubmit ? form.requestSubmit() : form.submit();
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

renderAirdropProfile(getCurrentProfile());
syncWalletFromServer();
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
