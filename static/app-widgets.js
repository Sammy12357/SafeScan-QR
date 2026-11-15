// app-widgets.js — airdrop profile render, camera scan, risk modal, consent banner, page widgets.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
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

const initialAirdropProfile = getCurrentProfile();
renderAirdropProfile(initialAirdropProfile ? { email: initialAirdropProfile.email } : null);
if (initialAirdropProfile && dom.walletStatus) dom.walletStatus.textContent = "Checking wallet status…";
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
      closeRiskModal();
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
  };
  resetScroll();
  window.requestAnimationFrame(() => {
    resetScroll();
    window.requestAnimationFrame(resetScroll);
  });

  let scrollGuardTicks = 0;
  riskModalScrollGuard = window.setInterval(() => {
    resetScroll();
    scrollGuardTicks += 1;
    if (scrollGuardTicks >= 10) window.clearInterval(riskModalScrollGuard);
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
  if (riskModalScrollGuard) window.clearInterval(riskModalScrollGuard);
  riskModal?.classList.add("hidden");
  riskModal?.setAttribute("aria-hidden", "true");
  riskModal?.remove();
  document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

blockReportButton?.addEventListener("click", () => {
  if (blockReportButton.disabled) return;
  const payload = blockReportButton.dataset.reportUrl?.trim() || "";
  let parsed;
  try {
    parsed = new URL(payload);
  } catch (_err) {
    parsed = null;
  }
  if (!parsed || !["http:", "https:"].includes(parsed.protocol)) {
    if (reportStatus) {
      reportStatus.setAttribute("role", "alert");
      reportStatus.textContent = "Only web URLs can be reported here. This payload was not submitted.";
    }
    return;
  }

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15000);
  if (reportStatus) {
    reportStatus.removeAttribute("role");
    reportStatus.textContent = "Submitting report…";
  }
  UIStates.busy(blockReportButton, async () => {
    try {
      const response = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({ url: payload, reason: "other" })
      });
      if (!response.ok) throw new Error(`Report request failed: ${response.status}`);
      const result = await response.json();
      if (!result.id || result.status !== "pending") throw new Error("Report was not confirmed");
      if (reportStatus) reportStatus.textContent = "Report submitted for review. This does not block the link on your device.";
    } catch (error) {
      if (reportStatus) {
        reportStatus.setAttribute("role", "alert");
        reportStatus.textContent = error?.name === "AbortError"
          ? "We couldn't confirm the report after 15 seconds. Check whether it was received before submitting again."
          : navigator.onLine === false
            ? "You're offline. Reconnect and submit the report again."
            : "We couldn't confirm this report was received. Check your connection and try again.";
      }
    } finally {
      window.clearTimeout(timeout);
    }
  }, { label: "Submitting…" });
});

const cautionOpenConsent = document.getElementById("cautionOpenConsent");
if (continueSafelyButton && cautionOpenConsent) {
  const destination = continueSafelyButton.dataset.destination || "";
  let webDestination = "";
  try {
    const parsed = new URL(destination);
    if (["http:", "https:"].includes(parsed.protocol)) webDestination = parsed.href;
  } catch (_err) {
    // Keep the action disabled if the decoded destination is malformed.
  }
  const syncCautionOpen = () => {
    const enabled = Boolean(webDestination && cautionOpenConsent.checked);
    if (enabled) continueSafelyButton.href = webDestination;
    else continueSafelyButton.removeAttribute("href");
    continueSafelyButton.classList.toggle("caution-open-disabled", !enabled);
    continueSafelyButton.setAttribute("aria-disabled", String(!enabled));
    continueSafelyButton.tabIndex = enabled ? 0 : -1;
  };
  cautionOpenConsent.addEventListener("change", syncCautionOpen);
  continueSafelyButton.addEventListener("click", (event) => {
    if (!cautionOpenConsent.checked || !webDestination) {
      event.preventDefault();
      cautionOpenConsent.focus();
    }
  });
  syncCautionOpen();
}

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

function showConsentCacheWarning() {
  const title = cookieConsentBanner?.querySelector(".consent-title");
  const copy = cookieConsentBanner?.querySelector(".consent-copy");
  const actions = cookieConsentBanner?.querySelector(".consent-actions");
  if (title) title.textContent = "Privacy choice recorded";
  if (copy) {
    copy.textContent = "SafeScan recorded your choice, but this browser couldn't remember it. You may be asked again on another visit.";
    copy.setAttribute("role", "status");
  }
  if (actions) {
    const close = document.createElement("button");
    close.type = "button";
    close.className = "secondary-button";
    close.textContent = "Close";
    close.addEventListener("click", () => cookieConsentBanner.classList.add("hidden"));
    actions.replaceChildren(close);
    close.focus();
  }
}

let consentSaving = false;
cookieConsentBanner?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-consent-choice]");
  if (!button || button.disabled || consentSaving) return;
  consentSaving = true;
  const otherButtons = Array.from(cookieConsentBanner.querySelectorAll("[data-consent-choice]"))
    .filter((choice) => choice !== button).map((choice) => [choice, choice.disabled]);
  otherButtons.forEach(([choice]) => { choice.disabled = true; });
  const consentType = button.dataset.consentChoice;
  const bannerVersion = cookieConsentBanner.dataset.version || "consent-v1";
  const record = { consentType, bannerVersion, timestamp: new Date().toISOString() };
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15000);
  UIStates.busy(button, async () => {
    try {
      const response = await fetch("/api/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consentType, bannerVersion }),
        signal: controller.signal
      });
      if (!response.ok) throw new Error("Consent save failed");
      const parsedBody = await response.json().catch(() => ({}));
      const body = parsedBody && typeof parsedBody === "object" ? parsedBody : {};
      let cached = true;
      try {
        window.localStorage.setItem("safeScanConsent", JSON.stringify(record));
        if (body.id) window.localStorage.setItem("safeScanConsentId", body.id);
      } catch {
        cached = false;
      }
      document.getElementById("consentSaveFeedback")?.remove();
      if (cached) cookieConsentBanner.classList.add("hidden");
      else showConsentCacheWarning();
    } catch {
      let feedback = document.getElementById("consentSaveFeedback");
      if (!feedback) {
        feedback = document.createElement("div");
        feedback.id = "consentSaveFeedback";
        cookieConsentBanner.firstElementChild?.appendChild(feedback);
      }
      UIStates.notice(feedback, {
        type: "danger",
        message: controller.signal.aborted
          ? "Saving your privacy choice took too long. Check your connection and try again."
          : navigator.onLine === false
            ? "You're offline. Reconnect and save your privacy choice again."
            : "We couldn't confirm your privacy choice was recorded. Check your connection and try again."
      });
    } finally {
      window.clearTimeout(timeout);
      otherButtons.forEach(([choice, wasDisabled]) => { choice.disabled = wasDisabled; });
      consentSaving = false;
    }
  }, { label: "Saving…" });
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
