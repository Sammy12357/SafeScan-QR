(() => {
  const button = document.getElementById("disconnectExistingWallet");
  const status = document.getElementById("walletDisconnectStatus");
  if (!button || !status) return;

  async function refresh() {
    try {
      const response = await fetch("/api/wallet", { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error("Wallet status unavailable");
      const data = await response.json();
      button.classList.toggle("hidden", !data.connected);
      status.textContent = data.connected ? "An existing wallet is connected to this account." : "No wallet is connected.";
    } catch {
      status.textContent = "Wallet status could not be checked. Try again later or request account help.";
    }
  }

  button.addEventListener("click", async () => {
    button.disabled = true;
    status.textContent = "Disconnecting wallet…";
    try {
      const response = await fetch("/api/wallet", { method: "DELETE", credentials: "same-origin" });
      if (!response.ok) throw new Error("Wallet disconnect failed");
      button.classList.add("hidden");
      status.textContent = "Wallet disconnected from your SafeScan account.";
    } catch {
      status.textContent = "Wallet disconnect did not complete. Try again or request account help.";
      button.disabled = false;
    }
  });
  void refresh();
})();
