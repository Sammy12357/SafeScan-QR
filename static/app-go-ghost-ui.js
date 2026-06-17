// app-go-ghost-ui.js — Go Ghost run/queue automation, rendering, scope modal, event wiring.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
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

async function finishGhostBrokerAndOpenNext(broker) {
  if (!broker) return;
  finishGhostBroker(broker.id, "No matching profile found in search results.");
  closeGoGhostScopeModal();
  renderGoGhostAutomationScope();
  showCopyToast(`${broker.name} marked finished`);
  await openNextGhostBroker();
}

async function runGhostBrokerAutomation(broker, triggerButton) {
  const activeController = goGhostAutomationControllers.get(broker.id);
  if (activeController) {
    activeController.abort();
    showCopyToast(`Cancelling ${broker.name}`);
    return null;
  }

  const profile = getGhostProfile();
  if (!profile.name?.trim()) {
    scrollToGhostProfile();
    showCopyToast("Add a name first");
    return null;
  }
  if (!profile.email?.trim()) {
    scrollToGhostProfile();
    ghostEmailInput?.focus({ preventScroll: true });
    showCopyToast("Add an email first");
    return null;
  }

  const originalText = triggerButton?.textContent || "";
  const controller = new AbortController();
  goGhostAutomationControllers.set(broker.id, controller);
  if (triggerButton) {
    triggerButton.textContent = "Cancel run";
    triggerButton.setAttribute("aria-pressed", "true");
  }
  const optOutUrl = goGhostBrokerOptOutUrl(broker, profile);
  updateGhostAutomationState(broker.id, {
    status: "running",
    detail: `Running backend Playwright autofill for ${broker.name}. This fills a server-side browser session, not the visible tab.`,
    targetUrl: optOutUrl,
    updatedAt: new Date().toISOString()
  });
  showCopyToast(`Running ${broker.name} backend autofill`);

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
    updateGhostAutomationState(broker.id, automation);
    // "submitted" is fully done; "email_required" means the request was sent
    // and only an email-link click remains, so it also counts as submitted.
    if (automation.status === "submitted" || automation.status === "email_required") {
      setGhostProgress(broker.id, "submitted", true);
    }
    showCopyToast(automation.detail || formatGhostAutomationStatus(automation.status));
    return automation;
  } catch (error) {
    if (error?.name === "AbortError") {
      const cancelled = {
        status: "cancelled",
        detail: "Backend automation was cancelled before completion.",
        targetUrl: optOutUrl,
        updatedAt: new Date().toISOString()
      };
      updateGhostAutomationState(broker.id, cancelled);
      showCopyToast(`${broker.name} run cancelled`);
      return cancelled;
    }
    const failed = {
      status: "failed",
      detail: error.message || "Automation failed.",
      updatedAt: new Date().toISOString()
    };
    updateGhostAutomationState(broker.id, failed);
    showCopyToast(error.message || "Automation failed");
    return failed;
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
  const progress = getGhostProgress();
  goGhostAutomationRows.innerHTML = goGhostBrokers.slice(0, 8).map((broker) => {
    const lane = ghostEffortLane(broker);
    const automation = progress[broker.id]?.automation;
    const statusLabel = automation ? formatGhostAutomationStatus(automation.status) : "Not run";
    return `
      <button class="ghost-automation-row ghost-automation-site-row" type="button" data-ghost-scope="${broker.id}" aria-label="Open ${escapeHtml(broker.name)} automation details">
        <span>${escapeHtml(broker.name)}</span>
        <span><span class="ghost-effort ghost-effort-${lane.lane}">${escapeHtml(lane.label)}</span></span>
        <span>${escapeHtml(lane.you)}</span>
        <span>${escapeHtml(statusLabel)}</span>
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
  const state = getGhostProgress()[broker.id] || {};
  const automation = state.automation;
  activeGhostScopeBrokerId = broker.id;
  if (goGhostScopeTitle) goGhostScopeTitle.textContent = broker.name;
  if (goGhostScopePriority) goGhostScopePriority.textContent = broker.priority;
  if (goGhostScopeDescription) goGhostScopeDescription.textContent = broker.automationNote || broker.priorityDescription || "";
  renderGhostScopeKeywords(profile);
  const lane = ghostEffortLane(broker);
  const guidance = automation ? ghostStatusGuidance(automation.status) : null;
  if (goGhostScopeDetails) {
    goGhostScopeDetails.innerHTML = `
      <div class="ghost-scope-detail"><span>Backend does</span><strong>Fills the whole form</strong></div>
      <div class="ghost-scope-detail"><span>You do</span><strong>${escapeHtml(lane.label === "Auto" ? "Just check email" : lane.label)}</strong></div>
      <div class="ghost-scope-detail ghost-scope-detail-wide"><span>Needed</span><strong>${escapeHtml((broker.requiredInfo || []).join(", "))}</strong></div>
      ${guidance && guidance.text ? `<div class="ghost-scope-detail ghost-scope-detail-wide ghost-scope-guidance ghost-scope-guidance-${guidance.tone}"><span>Next step</span><strong>${escapeHtml(guidance.text)}</strong></div>` : ""}
      ${state.finishReason ? `<div class="ghost-scope-detail ghost-scope-detail-wide"><span>Finished as</span><strong>${escapeHtml(state.finishReason)}</strong></div>` : ""}
      ${automation ? `<div class="ghost-scope-detail ghost-scope-detail-wide"><span>Automation status</span><strong>${escapeHtml(formatGhostAutomationStatus(automation.status))}</strong></div>` : ""}
    `;
  }
  if (goGhostScopeAutoFillButton) {
    goGhostScopeAutoFillButton.hidden = !broker.automationEnabled;
    goGhostScopeAutoFillButton.textContent = goGhostAutomationControllers.has(broker.id) ? "Cancel run" : "Run auto fill";
    if (goGhostAutomationControllers.has(broker.id)) goGhostScopeAutoFillButton.setAttribute("aria-pressed", "true");
    else goGhostScopeAutoFillButton.removeAttribute("aria-pressed");
  }
  // The "Finish in browser" one-click handoff only appears once a run has left
  // a human checkpoint (CAPTCHA / pick-listing / filled-but-not-submitted).
  if (goGhostScopeFinishButton) {
    goGhostScopeFinishButton.hidden = !(guidance && guidance.action);
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
    showCopyToast(await openGhostOptOutWithPacket(broker, profile, searchUrl));
    return;
  }
  if (action === "finish") {
    // One-click handoff after a CAPTCHA/listing checkpoint: open the opt-out
    // page and copy the details packet. Most broker pages ignore query-string
    // prefill values, so clipboard fallback is the reliable part.
    showCopyToast(await openGhostOptOutWithPacket(broker, profile, searchUrl));
    return;
  }
  if (action === "copy") {
    const copied = await copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
    showCopyToast(copied ? `${broker.name} details copied` : "Copy failed");
    return;
  }
  if (action === "nomatch") {
    await finishGhostBrokerAndOpenNext(broker);
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
  goGhostScopeFinishButton?.addEventListener("click", () => runGhostScopeAction("finish"));
  goGhostScopeAutoFillButton?.addEventListener("click", () => runGhostScopeAction("auto"));
  goGhostScopeNoMatchButton?.addEventListener("click", () => runGhostScopeAction("nomatch"));
  goGhostScopeCopyButton?.addEventListener("click", () => runGhostScopeAction("copy"));

  goGhostBrokerList?.addEventListener("change", (event) => {
    const checkbox = event.target.closest("[data-ghost-site][data-ghost-field]");
    if (!checkbox) return;
    setGhostProgress(checkbox.dataset.ghostSite, checkbox.dataset.ghostField, checkbox.checked);
  });

  goGhostBrokerList?.addEventListener("click", async (event) => {
    const optOutLink = event.target.closest("[data-ghost-optout]");
    if (optOutLink) {
      event.preventDefault();
      const profile = getGhostProfile();
      const broker = goGhostBrokers.find((item) => item.id === optOutLink.dataset.ghostOptout);
      if (!broker) return;
      const searchUrl = goGhostBrokerSearchUrl(broker, profile);
      showCopyToast(await openGhostOptOutWithPacket(broker, profile, searchUrl));
      return;
    }

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


