const GOOGLE_CLIENT_ID = "230684501873-4aauu1triudaaopdcus2k7achvesr3el.apps.googleusercontent.com";
const AIRDROP_STORAGE_KEY = "phishproofAirdropProfile";
const SCAN_COUNT_STORAGE_KEY = "phishproofScanCount";
const sampleUrls = {
  safe: "https://www.apple.com/iphone",
  shortener: "https://bit.ly/3secure-deal",
  lookalike: "https://paypaI-verification-login.com/secure",
  malware: "http://download-secure-update.top/update-app/installer.apk?payload=1",
  wifi: "WIFI:T:WPA;S:Airport_Free_WiFi;P:guest1234;H:false;;",
  crypto: "solana:Bpdt7Hey78HeEEr9Q6x19gYAns5n6w44LdjJhxN3pump?amount=2.5&label=SafeScan%20Claim"
};

const dom = {
  hiddenWalletInput: document.getElementById("hiddenWalletInput"),
  qrForm: document.getElementById("qrForm"),
  urlInput: document.getElementById("urlInput"),
  qrImageInput: document.getElementById("qrImageInput"),
  uploadPreview: document.getElementById("uploadPreview"),
  previewImage: document.getElementById("previewImage"),
  scanStatus: document.getElementById("scanStatus"),
  qrFrame: document.querySelector(".qr-frame"),
  sampleButtons: Array.from(document.querySelectorAll(".sample-button[data-sample]")),
  simulateScanButton: document.getElementById("simulateScanButton"),
  walletStatus: document.getElementById("walletStatus"),
  connectWalletButton: document.getElementById("connectWalletButton"),
  disconnectWalletButton: document.getElementById("disconnectWalletButton"),
  topConnectWalletButton: document.getElementById("topConnectWalletButton"),
  topCopyReferralButton: document.getElementById("topCopyReferralButton"),
  airdropProfile: document.getElementById("airdropProfile"),
  airdropStatus: document.getElementById("airdropStatus"),
  googleSignInButton: document.getElementById("googleSignInButton"),
  demoWalletButton: document.getElementById("demoWalletButton"),
  copyTokenAddressButton: document.getElementById("copyTokenAddressButton"),
  tokenAddress: document.getElementById("tokenAddress"),
  scanProgressValue: document.getElementById("scanProgressValue")
};

function bootstrapServerProfile() {
  const bootstrap = window.SAFESCAN_BOOTSTRAP || {};
  if (bootstrap.scanCount !== undefined) {
    window.localStorage.setItem(SCAN_COUNT_STORAGE_KEY, String(bootstrap.scanCount || 0));
  }

  if (!bootstrap.loggedIn) return;

  const existing = getStoredAirdropProfile();
  const profile = {
    ...(existing || {}),
    email: bootstrap.email || existing?.email || "guest@demo.com",
    name: existing?.name || "Safe scanner",
    googleSubject: existing?.googleSubject || "server-session",
    registeredAt: existing?.registeredAt || new Date().toISOString()
  };
  window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(profile));
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
  const profile = getStoredAirdropProfile() || {
    email: window.SAFESCAN_BOOTSTRAP?.email || "guest@demo.com",
    name: "Safe scanner",
    googleSubject: "demo-wallet-user",
    registeredAt: new Date().toISOString()
  };
  const updatedProfile = { ...profile, walletAddress: "DemoSQRWallet111111111111111111111" };
  window.localStorage.setItem(AIRDROP_STORAGE_KEY, JSON.stringify(updatedProfile));
  renderWalletState(updatedProfile);
});

dom.qrForm?.addEventListener("submit", (e) => {
  if (!dom.hiddenWalletInput.value) {
    e.preventDefault();
    window.alert("Connect a wallet or use the demo wallet first so scan rewards can be tracked.");
  }
});

dom.sampleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    if (!dom.urlInput) return;
    dom.urlInput.value = sampleUrls[button.dataset.sample] || "";
    if (dom.scanStatus) dom.scanStatus.textContent = "Sample payload loaded. Submit it to run the SafeScan backend analysis.";
  });
});

dom.simulateScanButton?.addEventListener("click", () => {
  if (!dom.urlInput) return;
  dom.urlInput.value = sampleUrls.safe;
  dom.qrFrame?.classList.add("scanning");
  if (dom.scanStatus) dom.scanStatus.textContent = "Mobile scan simulated. Submit to analyze the decoded payload.";
  window.setTimeout(() => dom.qrFrame?.classList.remove("scanning"), 1400);
});

dom.qrImageInput?.addEventListener("change", (event) => {
  const [file] = event.target.files || [];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    if (dom.previewImage) dom.previewImage.src = reader.result;
    dom.uploadPreview?.classList.remove("hidden");
    if (dom.scanStatus) dom.scanStatus.textContent = "QR image ready. Submit it to decode with the Render backend.";
  };
  reader.readAsDataURL(file);
});

dom.copyTokenAddressButton?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(dom.tokenAddress?.textContent || "");
    dom.copyTokenAddressButton.textContent = "Copied";
    setTimeout(() => { dom.copyTokenAddressButton.textContent = "Copy"; }, 1200);
  } catch {
    window.prompt("Copy token address:", dom.tokenAddress?.textContent || "");
  }
});

dom.topCopyReferralButton?.addEventListener("click", async () => {
  const profile = getStoredAirdropProfile();
  if (!profile) {
    window.alert("Sign in first to generate a referral link.");
    return;
  }
  const referral = new URL("https://safescan-qr.onrender.com/auth/google");
  referral.searchParams.set("ref", `SAFE-${Math.abs(profile.email.split("").reduce((hash, char) => ((hash << 5) - hash + char.charCodeAt(0)) | 0, 0)).toString(36).toUpperCase()}`);
  try {
    await navigator.clipboard.writeText(referral.toString());
    dom.topCopyReferralButton.textContent = "Copied link";
    setTimeout(() => { dom.topCopyReferralButton.textContent = "Referral link"; }, 1200);
  } catch {
    window.prompt("Copy referral link:", referral.toString());
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

bootstrapServerProfile();
renderAirdropProfile(getStoredAirdropProfile());
