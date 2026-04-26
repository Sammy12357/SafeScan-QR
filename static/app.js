const GOOGLE_CLIENT_ID = "230684501873-4aauu1triudaaopdcus2k7achvesr3el.apps.googleusercontent.com";
const AIRDROP_STORAGE_KEY = "phishproofAirdropProfile";

const dom = {
  hiddenWalletInput: document.getElementById("hiddenWalletInput"),
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