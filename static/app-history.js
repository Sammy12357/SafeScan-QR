document.querySelectorAll(".history-copy-button").forEach((button) => {
  button.addEventListener("click", async () => {
    if (button.disabled) return;
    const card = button.closest(".history-card");
    const url = card?.querySelector(".history-url")?.textContent?.trim();
    const feedback = card?.querySelector(".history-copy-feedback");
    if (!url || !feedback) return;

    button.disabled = true;
    feedback.textContent = "Copying…";
    try {
      if (!await copyTextToClipboard(url)) throw new Error("Clipboard did not confirm the copy");
      feedback.textContent = "Copied. Paste it into the scanner for a fresh check.";
    } catch {
      feedback.textContent = "Could not copy. Select the URL above and paste it into the scanner.";
    } finally {
      button.disabled = false;
    }
  });
});
