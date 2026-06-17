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

