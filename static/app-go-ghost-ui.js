// app-go-ghost-ui.js — Go Ghost run/queue automation, rendering, scope modal, event wiring.
// Split from app.js; the app-*.js files share one global scope and MUST
// load in this order: app-core.js -> app-widgets.js -> app-go-ghost.js -> app-go-ghost-ui.js -> app-generate-qr.js.
const ghostCaliforniaDropCard = document.getElementById("ghostCaliforniaDropCard");
const ghostDropFamilyNote = document.getElementById("ghostDropFamilyNote");
const goGhostAccountCheckStatus = document.getElementById("goGhostAccountCheckStatus");
const goGhostSessionActions = document.getElementById("goGhostSessionActions");
const goGhostSessionRetryButton = document.getElementById("goGhostSessionRetryButton");
const GHOST_PROFILE_VALIDATION_MESSAGE =
  "Enter a valid first name, last name, city, region, email, and optional birth year.";

function renderGhostCaliforniaDropCard() {
  if (!ghostCaliforniaDropCard) return;
  if (goGhostStoreLocked) {
    ghostCaliforniaDropCard.hidden = true;
    if (ghostDropFamilyNote) ghostDropFamilyNote.hidden = true;
    return;
  }
  ghostCaliforniaDropCard.hidden = ghostStateInput?.value !== "CA";
  if (ghostDropFamilyNote) ghostDropFamilyNote.hidden = ghostCurrentSubject().kind !== "family";
}

function ghostRequiresSubjectOwnAction(broker) {
  return broker?.group === "peopleconnect";
}

function ghostCanAct(broker = null) {
  if (goGhostStoreLocked) return false;
  const subject = ghostCurrentSubject();
  if (!subject.consentAcceptedAt) {
    ghostShowIssue("Confirm this person's Go Ghost setup first.", ghostVisibleIssueHost());
    return false;
  }
  if (subject.kind === "family" && !goGhostFamilyAttestedThisVisit.has(subject.id)) {
    if (goGhostScopeModal && !goGhostScopeModal.classList.contains("hidden")) closeGoGhostScopeModal();
    ghostFamilyAttestationInput?.setAttribute?.("aria-invalid", "true");
    ghostFamilyAttestationInput?.setAttribute?.("aria-describedby", "goGhostActionError");
    ghostShowIssue("Confirm your authority to help this family member before opening broker links.",
      goGhostActionError, ghostFamilyAttestationInput);
    return false;
  }
  if (subject.kind === "family" && ghostRequiresSubjectOwnAction(broker)) {
    ghostShowIssue("This broker requires the person to use its suppression tool themselves.", ghostVisibleIssueHost());
    return false;
  }
  if (!ghostProfileIsReviewed()) {
    if (goGhostScopeModal && !goGhostScopeModal.classList.contains("hidden")) closeGoGhostScopeModal();
    scrollToGhostProfile();
    ghostShowIssue("Complete and save the reviewed name, city, region, and email before opening broker links.",
      ghostProfileError, ghostFirstNameInput);
    return false;
  }
  ghostClearIssue(goGhostActionError);
  return true;
}

async function openNextGhostBroker() {
  if (!ghostCanAct()) return;
  const profile = getGhostProfile();
  if (!hasGhostSearchProfile(profile)) {
    scrollToGhostProfile();
    ghostShowIssue("Add and save a name before opening a broker search.", ghostProfileError, ghostFirstNameInput);
    return;
  }
  const family = ghostCurrentSubject().kind === "family";
  const broker = nextPendingGhostBroker((item) => !family || !ghostRequiresSubjectOwnAction(item));
  if (!broker) {
    showCopyToast(family ? "Remaining brokers may require the person to complete them directly" : "All brokers tracked");
    return;
  }
  const searchUrl = goGhostBrokerSearchUrl(broker, profile);
  const opened = openGhostUrl(searchUrl);
  const copied = await copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
  if (!opened) {
    ghostShowIssue(copied
      ? "Your browser blocked the broker page. The details were copied; open the broker row and try Search again."
      : "Your browser blocked the broker page and the details could not be copied. Allow pop-ups and clipboard access, then try again.",
    goGhostActionError);
    return;
  }
  scrollToGhostBroker(broker);
  if (!copied) {
    ghostShowIssue("The broker page opened, but the details could not be copied. Try Copy details from the broker row.",
      goGhostActionError);
    return;
  }
  ghostClearIssue(goGhostActionError);
  showCopyToast(`${broker.name} packet copied`);
}

async function finishGhostBrokerAndOpenNext(broker) {
  if (!broker) return;
  if (!finishGhostBroker(broker.id)) return;
  closeGoGhostScopeModal();
  showCopyToast(`${broker.name}: no matching profile recorded`);
  await openNextGhostBroker();
}

async function runGhostBrokerAutomation(broker, triggerButton) {
  if (!GO_GHOST_BROWSER_AUTOMATION_AVAILABLE) return null;
  if (ghostCurrentSubject().kind === "family") {
    ghostShowIssue("Assisted submissions are unavailable for family requests. Use the broker's opt-out page directly.",
      ghostVisibleIssueHost());
    return null;
  }
  if (!ghostCanAct(broker)) return null;
  const activeController = goGhostAutomationControllers.get(broker.id);
  if (activeController) {
    activeController.abort();
    showCopyToast(`Cancelling ${broker.name}`);
    return null;
  }

  const profile = getGhostProfile();
  if (!profile.name?.trim()) {
    scrollToGhostProfile();
    ghostShowIssue("Add and save a name before running broker automation.", ghostProfileError, ghostFirstNameInput);
    return null;
  }
  if (!profile.email?.trim()) {
    scrollToGhostProfile();
    ghostShowIssue("Add and save an email before running broker automation.", ghostProfileError, ghostEmailInput);
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
    if (goGhostStoreLocked) return null;
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
      ghostApplyManualEvent(broker.id, "mark_submitted");
    }
    if (automation.status === "failed" || automation.status === "unavailable") {
      ghostShowIssue("The broker automation could not finish. Open the broker's opt-out page to continue manually.",
        ghostVisibleIssueHost());
    } else {
      showCopyToast(automation.detail || formatGhostAutomationStatus(automation.status));
    }
    return automation;
  } catch (error) {
    if (goGhostStoreLocked) return null;
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
    ghostShowIssue("The broker automation could not finish. Open the broker's opt-out page to continue manually.",
      ghostVisibleIssueHost());
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
  const counts = GoGhostState.summarize(progress, goGhostBrokerIds);
  const submitted = goGhostBrokerIds.filter((id) =>
    GoGhostState.sanitizedEntry(progress[id]).state === "submitted").length;
  ghostProgressCount.textContent = `${counts.client_recheck_absent} / ${counts.total}`;
  if (ghostProgressBreakdown) ghostProgressBreakdown.textContent =
    `${submitted} submitted · ${counts.user_reported_removed} reported gone · ${counts.not_found} not found · ${counts.in_progress - submitted} other active`;
}

function ghostManualStatusLabel(state) {
  const entry = GoGhostState.sanitizedEntry(state);
  if (entry.state === "client_recheck_absent") return entry.source === "extension"
    ? "Extension rechecked absent" : "You rechecked absent";
  return ({
    not_started: "Pending", scanning: "Searching", not_found: "Not found",
    needs_review: "Review listing", found: "Listing found", submitting: "Submitting",
    needs_human: "Needs you", submitted: "Submitted", awaiting_email: "Check email",
    confirmed: "Email confirmed", verifying: "Rechecking",
    user_reported_removed: "You reported gone",
    still_listed: "Still listed", failed: "Needs retry", skipped: "Skipped"
  })[entry.state] || "Pending";
}

function renderGoGhostAutomationScope() {
  if (!goGhostAutomationRows) return;
  const progress = getGhostProgress();
  const groups = new Map();
  for (const broker of goGhostBrokers) {
    if (!groups.has(broker.group)) groups.set(broker.group, []);
    groups.get(broker.group).push(broker);
  }
  const noBrokerState = document.getElementById("goGhostNoBrokerState");
  if (goGhostAutomationRows.parentElement) goGhostAutomationRows.parentElement.hidden = groups.size === 0;
  if (noBrokerState) noBrokerState.hidden = groups.size !== 0;
  goGhostAutomationRows.innerHTML = [...groups.values()].map((group) => {
    const broker = group[0];
    const lane = ghostEffortLane(broker);
    const state = progress[broker.id];
    const automation = GO_GHOST_BROWSER_AUTOMATION_AVAILABLE ? state?.automation : null;
    const statusLabel = group.length > 1
      ? `${group.filter((item) => GoGhostState.sanitizedEntry(progress[item.id]).state !== "not_started").length}/${group.length} tracked`
      : GO_GHOST_BROWSER_AUTOMATION_AVAILABLE
      ? (automation ? formatGhostAutomationStatus(automation.status) : ghostManualStatusLabel(state))
      : ghostManualStatusLabel(state);
    const name = group.length > 1 ? "PeopleConnect" : broker.name;
    const brandSummary = group.length > 1 ? group.map((item) =>
      `${item.name}: ${ghostManualStatusLabel(progress[item.id])}`).join(" · ") : "";
    const brandStatuses = brandSummary ? `<small class="ghost-group-brand-status">${escapeHtml(brandSummary)}</small>` : "";
    return `
      <button class="ghost-automation-row ghost-automation-site-row${group.length > 1 ? " ghost-group-row" : ""}" type="button" data-ghost-scope="${broker.id}" aria-label="Open ${escapeHtml(name)} opt-out details${brandSummary ? `; ${escapeHtml(brandSummary)}` : ""}">
        <span>${escapeHtml(name)}${group.length > 1 ? ` (${group.length} sites)` : ""}${brandStatuses}</span>
        <span><span class="ghost-effort ghost-effort-${lane.lane}">${escapeHtml(lane.label)}</span></span>
        <span>${escapeHtml(lane.you)}</span>
        <span>${escapeHtml(statusLabel)}</span>
      </button>
    `;
  }).join("");
}

function closeGoGhostScopeModal() {
  activeGhostScopeBrokerId = "";
  goGhostScopeModal?.classList.add("hidden");
  ghostClearIssue(goGhostScopeError);
}

function renderGhostScopeKeywords(profile) {
  if (!goGhostScopeKeywords) return;
  const fields = [
    ["Full name", profile.name],
    ["City/state", profile.location],
    ["Email", profile.email]
  ];
  goGhostScopeKeywords.innerHTML = fields.map(([label, value]) => `
    <div class="ghost-scope-keyword">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value || "Not set")}</strong>
    </div>
  `).join("");
}

function openGoGhostScopeModal(siteId, focusClose = true) {
  const broker = goGhostBrokers.find((item) => item.id === siteId);
  if (!broker || !goGhostScopeModal) return;
  const group = goGhostBrokers.filter((item) => item.group === broker.group);
  const profile = getGhostProfile();
  const state = GoGhostState.sanitizedEntry(getGhostProgress()[broker.id]);
  const automation = GO_GHOST_BROWSER_AUTOMATION_AVAILABLE ? getGhostProgress()[broker.id]?.automation : null;
  const subjectOnly = ghostCurrentSubject().kind === "family" && ghostRequiresSubjectOwnAction(broker);
  activeGhostScopeBrokerId = broker.id;
  ghostClearIssue(goGhostScopeError);
  if (goGhostScopeTitle) goGhostScopeTitle.textContent = group.length > 1 ? "PeopleConnect" : broker.name;
  if (goGhostScopePriority) goGhostScopePriority.textContent = broker.priority;
  if (goGhostScopeBrandPicker) goGhostScopeBrandPicker.hidden = group.length === 1;
  if (goGhostScopeBrandSelect && group.length > 1) {
    goGhostScopeBrandSelect.innerHTML = group.map((item) =>
      `<option value="${item.id}">${escapeHtml(item.name)} — ${escapeHtml(ghostManualStatusLabel(getGhostProgress()[item.id]))}</option>`
    ).join("");
    goGhostScopeBrandSelect.value = broker.id;
  }
  if (goGhostScopeDescription) goGhostScopeDescription.textContent = subjectOnly
    ? "PeopleConnect limits this suppression tool to the person's own use. Ask the family member to complete it directly."
    : profile.state === "OUTSIDE_US"
      ? "This directory targets U.S. records. Search opens this broker's manual instructions without adding your name or location to a link."
    : GO_GHOST_BROWSER_AUTOMATION_AVAILABLE
      ? (broker.automationNote || broker.priorityDescription || "")
      : "Find your matching listing, then open the broker opt-out page and submit the request in your browser.";
  if (goGhostScopeSearchButton) goGhostScopeSearchButton.textContent =
    profile.state === "OUTSIDE_US" ? "Broker instructions" : "Search";
  if (goGhostScopeOptOutButton) goGhostScopeOptOutButton.textContent =
    group.length > 1 ? "Open shared suppression center" : "Opt out";
  for (const button of [goGhostScopeSearchButton, goGhostScopeOptOutButton, goGhostScopeCopyButton, goGhostScopeFinishButton, goGhostScopeAutoFillButton]) {
    if (button) button.disabled = subjectOnly;
  }
  renderGhostScopeKeywords(profile);
  const lane = ghostEffortLane(broker);
  const guidance = automation ? ghostStatusGuidance(automation.status) : null;
  if (goGhostScopeDetails) {
    goGhostScopeDetails.innerHTML = `
      ${GO_GHOST_BROWSER_AUTOMATION_AVAILABLE ? `<div class="ghost-scope-detail"><span>Backend does</span><strong>Fills the whole form</strong></div>` : `<div class="ghost-scope-detail"><span>Search</span><strong>Find your matching listing</strong></div>`}
      <div class="ghost-scope-detail"><span>You do</span><strong>${escapeHtml(GO_GHOST_BROWSER_AUTOMATION_AVAILABLE && lane.label === "Auto" ? "Just check email" : "Submit the request")}</strong></div>
      <div class="ghost-scope-detail ghost-scope-detail-wide"><span>Needed</span><strong>${escapeHtml((broker.requiredInfo || []).join(", "))}</strong></div>
      <div class="ghost-scope-detail ghost-scope-detail-wide"><span>${group.length > 1 ? "Selected site" : "Status"}</span><strong>${escapeHtml(group.length > 1 ? `${broker.name}: ${ghostManualStatusLabel(state)}` : ghostManualStatusLabel(state))}</strong></div>
      ${guidance && guidance.text ? `<div class="ghost-scope-detail ghost-scope-detail-wide ghost-scope-guidance ghost-scope-guidance-${guidance.tone}"><span>Next step</span><strong>${escapeHtml(guidance.text)}</strong></div>` : ""}
      ${state.recheck ? `<div class="ghost-scope-detail ghost-scope-detail-wide"><span>Last recheck</span><strong>${escapeHtml(state.recheck.checkedAt.slice(0, 10))} · ${state.recheck.method === "user_recheck" ? "Manual" : "Extension"}</strong></div>` : ""}
      ${automation ? `<div class="ghost-scope-detail ghost-scope-detail-wide"><span>Automation status</span><strong>${escapeHtml(formatGhostAutomationStatus(automation.status))}</strong></div>` : ""}
    `;
  }
  if (goGhostScopeAutoFillButton) {
    goGhostScopeAutoFillButton.hidden = !GO_GHOST_BROWSER_AUTOMATION_AVAILABLE || !broker.automationEnabled;
    goGhostScopeAutoFillButton.textContent = goGhostAutomationControllers.has(broker.id) ? "Cancel run" : "Run auto fill";
    if (goGhostAutomationControllers.has(broker.id)) goGhostScopeAutoFillButton.setAttribute("aria-pressed", "true");
    else goGhostScopeAutoFillButton.removeAttribute("aria-pressed");
  }
  // The "Finish in browser" one-click handoff only appears once a run has left
  // a human checkpoint (CAPTCHA / pick-listing / filled-but-not-submitted).
  if (goGhostScopeFinishButton) {
    goGhostScopeFinishButton.hidden = !(guidance && guidance.action);
  }
  const can = (event) => GoGhostState.TRANSITIONS[event].from.includes(state.state);
  if (goGhostScopeNoMatchButton) {
    goGhostScopeNoMatchButton.hidden = !can("mark_not_found");
    goGhostScopeNoMatchButton.disabled = subjectOnly;
  }
  if (goGhostScopeSubmittedButton) {
    goGhostScopeSubmittedButton.hidden = !can("mark_submitted");
    goGhostScopeSubmittedButton.disabled = subjectOnly;
  }
  if (goGhostScopeRemovedButton) {
    goGhostScopeRemovedButton.hidden = !can("report_removed");
    goGhostScopeRemovedButton.disabled = subjectOnly;
  }
  if (goGhostScopeRecheckButton) {
    goGhostScopeRecheckButton.hidden = !can("begin_recheck");
    goGhostScopeRecheckButton.disabled = subjectOnly;
  }
  if (goGhostScopeAbsentButton) {
    goGhostScopeAbsentButton.hidden = !can("recheck_absent");
    goGhostScopeAbsentButton.disabled = subjectOnly;
  }
  if (goGhostScopePresentButton) {
    goGhostScopePresentButton.hidden = !can("recheck_present");
    goGhostScopePresentButton.disabled = subjectOnly;
  }
  goGhostScopeModal.classList.remove("hidden");
  if (focusClose) goGhostScopeModal.querySelector(".ghost-scope-close")?.focus();
}

async function runGhostScopeAction(action) {
  const broker = goGhostBrokers.find((item) => item.id === activeGhostScopeBrokerId);
  if (!broker) return;
  if (action !== "reset" && !ghostCanAct(broker)) return;
  const profile = getGhostProfile();
  const searchUrl = goGhostBrokerSearchUrl(broker, profile);

  if (action === "search") {
    if (!openGhostUrl(searchUrl)) {
      ghostShowIssue("Your browser blocked the broker page. Allow pop-ups for SafeScan, then try Search again.",
        goGhostScopeError);
      return;
    }
    ghostClearIssue(goGhostScopeError);
    showCopyToast(`Opened ${broker.name} search`);
    return;
  }
  if (action === "optout" || action === "finish") {
    // One-click handoff after a CAPTCHA/listing checkpoint: open the opt-out
    // page and copy the details packet without putting them in the URL.
    const result = await openGhostOptOutWithPacket(broker, profile, searchUrl);
    if (!result.opened) {
      ghostShowIssue(result.copied
        ? "Your browser blocked the broker page. Details were copied; allow pop-ups and try again."
        : "Your browser blocked the broker page and the details could not be copied. Allow pop-ups and clipboard access, then try again.",
      goGhostScopeError);
    } else if (!result.copied) {
      ghostShowIssue("The broker page opened, but the details could not be copied. Try Copy details again or enter them yourself.",
        goGhostScopeError);
    } else {
      ghostClearIssue(goGhostScopeError);
      showCopyToast(`${broker.name}: opened and details copied`);
    }
    return;
  }
  if (action === "copy") {
    const copied = await copyTextToClipboard(goGhostCopyPacket(broker, profile, searchUrl)).catch(() => false);
    if (!copied) {
      ghostShowIssue("The details could not be copied. Check clipboard permission, then try Copy details again.",
        goGhostScopeError);
      return;
    }
    ghostClearIssue(goGhostScopeError);
    showCopyToast(`${broker.name} details copied`);
    return;
  }
  if (action === "submitted" || action === "removed" || action === "reset") {
    if (!setGhostManualStatus(broker.id, action === "reset" ? "pending" : action)) return;
    openGoGhostScopeModal(broker.id, false);
    showCopyToast(action === "submitted" ? `${broker.name}: request submitted` :
      action === "removed" ? `${broker.name}: reported gone; recheck to record whether it is absent` : `${broker.name}: status reset`);
    return;
  }
  if (action === "nomatch") {
    await finishGhostBrokerAndOpenNext(broker);
    return;
  }
  if (action === "recheck") {
    if (!openGhostUrl(searchUrl)) {
      ghostShowIssue("Open the broker search in a new tab before recording a recheck. Allow pop-ups, then try again.",
        goGhostScopeError);
      return;
    }
    ghostClearIssue(goGhostScopeError);
    if (!ghostApplyManualEvent(broker.id, "begin_recheck")) return;
    openGoGhostScopeModal(broker.id, false);
    showCopyToast(`Check ${broker.name}'s listing, then record whether it is absent or still listed`);
    return;
  }
  if (action === "absent" || action === "present") {
    const event = action === "absent" ? "recheck_absent" : "recheck_present";
    if (!ghostApplyManualEvent(broker.id, event, { method: "user_recheck" })) return;
    openGoGhostScopeModal(broker.id, false);
    showCopyToast(`${broker.name}: ${action === "absent" ? "manually rechecked absent" : "still listed"}`);
    return;
  }
  if (action === "auto") {
    await runGhostBrokerAutomation(broker, goGhostScopeAutoFillButton);
    renderGhostScopeKeywords(getGhostProfile());
  }
}

function renderGhostSubjects() {
  if (!ghostSubjectSelect || goGhostStoreLocked) return;
  const state = ghostCurrentState();
  ghostSubjectSelect.innerHTML = Object.values(state.subjects).map((subject, index) => {
    const label = subject.kind === "self" ? "My information" : `Family member ${index + 1}`;
    const name = subject.profile.name ? ` — ${subject.profile.name}` : "";
    return `<option value="${subject.id}">${escapeHtml(label + name)}</option>`;
  }).join("");
  ghostSubjectSelect.value = state.activeSubjectId;
  const subject = ghostCurrentSubject();
  if (removeGhostSubjectButton) removeGhostSubjectButton.disabled = subject.kind !== "family";
  if (ghostFamilyAttestationLabel) ghostFamilyAttestationLabel.hidden = subject.kind !== "family";
  if (ghostFamilyAttestationInput) ghostFamilyAttestationInput.checked = goGhostFamilyAttestedThisVisit.has(subject.id);
}

function ghostSimpleAccountName(value) {
  const parts = cleanGhostText(value).split(" ");
  const namePart = /^[\p{L}\p{M}][\p{L}\p{M}'-]*$/u;
  return parts.length === 2 && parts.every((part) => namePart.test(part)) ? parts : null;
}

function ghostRefreshReviewNotice() {
  if (!ghostProfileReviewNotice) return;
  const reviewed = ghostProfileIsReviewed();
  const firstUseState = document.getElementById("ghostFirstUseState");
  if (firstUseState) firstUseState.hidden = reviewed;
  ghostProfileReviewNotice.textContent = reviewed
    ? "Details reviewed. You can open broker links for this person."
    : "Enter the required details, review them, then save before opening broker links.";
}

function hydrateGoGhostProfile() {
  const profile = goGhostStoreLocked ? ghostEmptyProfile() : ghostCurrentSubject().profile;
  const subject = goGhostStoreLocked ? null : ghostCurrentSubject();
  const self = subject?.kind === "self";
  const hasOlderScopedName = Boolean(profile.name || profile.location)
    && !profile.firstName && !profile.lastName && !profile.city && !profile.state;
  const allowAccountPrefill = self && !hasOlderScopedName && !profile.firstName && !profile.lastName;
  const accountParts = allowAccountPrefill ? ghostSimpleAccountName(goGhostAccountName) : null;
  if (ghostFirstNameInput) ghostFirstNameInput.value = profile.firstName || (accountParts ? accountParts[0] : "");
  if (ghostMiddleNameInput) ghostMiddleNameInput.value = profile.middleName || "";
  if (ghostLastNameInput) ghostLastNameInput.value = profile.lastName || (accountParts ? accountParts[1] : "");
  if (ghostCityInput) ghostCityInput.value = profile.city || "";
  if (ghostStateInput) ghostStateInput.value = profile.state || "";
  if (ghostBirthYearInput) ghostBirthYearInput.value = profile.birthYear || "";
  if (ghostAddressInput) ghostAddressInput.value = profile.address || "";
  if (ghostPhoneInput) ghostPhoneInput.value = profile.phone || profile.identifier || "";
  if (ghostEmailInput) ghostEmailInput.value = profile.email || (self ? goGhostAccountEmail : "");
  if (ghostPreviousCitiesInput) ghostPreviousCitiesInput.value = profile.previousCities || "";
  if (ghostOtherNamesInput) ghostOtherNamesInput.value = profile.otherNames || "";
  if (ghostSavedProfileHint) {
    ghostSavedProfileHint.hidden = !hasOlderScopedName || Boolean(profile.reviewedAt);
    ghostSavedProfileHint.textContent = ghostSavedProfileHint.hidden ? "" :
      "Previously saved on this account: " + [profile.name, profile.location].filter(Boolean).join(" · ")
      + ". Split and review these details before opening broker links.";
  }
  if (ghostAccountNameHint) {
    const showNameHint = allowAccountPrefill
      && Boolean(goGhostAccountName) && !accountParts;
    ghostAccountNameHint.hidden = !showNameHint;
    ghostAccountNameHint.textContent = showNameHint
      ? "Your account name is “" + goGhostAccountName
        + ".” Enter the correct first and last name for the broker search." : "";
  }
  renderGhostSubjects();
  ghostRefreshReviewNotice();
  renderGhostCaliforniaDropCard();
}

function saveGhostFormProfile(review = false) {
  if (goGhostStoreLocked) return false;
  const subject = ghostCurrentSubject();
  const next = getGhostFormProfile();
  if (review && !ghostValidProfileFields(next)) {
    goGhostProfileForm?.reportValidity?.();
    scrollToGhostProfile();
    const invalid = goGhostProfileForm?.querySelector?.(":invalid") || ghostFirstNameInput;
    invalid?.setAttribute?.("aria-invalid", "true");
    invalid?.setAttribute?.("aria-describedby", "ghostProfileError");
    ghostShowIssue(GHOST_PROFILE_VALIDATION_MESSAGE, ghostProfileError, invalid);
    return false;
  }
  const changed = GHOST_PROFILE_FORM_FIELDS.some((field) => next[field] !== (subject.profile[field] || ""));
  if (subject.kind === "family" && changed) {
    goGhostFamilyAttestedThisVisit.delete(subject.id);
    subject.familyAttestedAt = "";
    if (ghostFamilyAttestationInput) ghostFamilyAttestationInput.checked = false;
  }
  if (review) {
    next.name = `${next.firstName} ${next.lastName}`;
    next.location = next.state === "OUTSIDE_US" ? "" : next.city + ", " + next.state;
    next.reviewedAt = new Date().toISOString();
  } else if (changed) {
    next.reviewedAt = "";
  }
  if (!ghostSaveProfile(next)) return false;
  renderGhostSubjects();
  ghostRefreshReviewNotice();
  renderGhostCaliforniaDropCard();
  if (ghostSavedProfileHint && review) ghostSavedProfileHint.hidden = true;
  return true;
}

function showGoGhostWorkspace() {
  ghostClearIssue(goGhostConsentError);
  goGhostConsentModal?.classList.add("hidden");
  if (goGhostWorkspace) goGhostWorkspace.hidden = false;
  hydrateGoGhostProfile();
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
}

function startGoGhost() {
  if (goGhostStoreLocked) return;
  const subject = ghostCurrentSubject();
  const previous = subject.consentAcceptedAt;
  subject.consentAcceptedAt = new Date().toISOString();
  if (!ghostSaveState(goGhostConsentError)) {
    subject.consentAcceptedAt = previous;
    return;
  }
  showGoGhostWorkspace();
}

function selectGhostSubject(id, save = true) {
  const state = ghostCurrentState();
  if (!Object.hasOwn(state.subjects, id) || goGhostStoreLocked) return;
  const previous = state.activeSubjectId;
  state.activeSubjectId = id;
  if (save && !ghostSaveState(goGhostActionError)) {
    state.activeSubjectId = previous;
    if (ghostSubjectSelect) ghostSubjectSelect.value = previous;
    return;
  }
  ghostClearIssue(goGhostActionError);
  ghostClearIssue(ghostProfileError);
  hydrateGoGhostProfile();
  renderGoGhostAutomationScope();
  renderGoGhostProgress();
  goGhostScopeModal?.classList.add("hidden");
  if (ghostCurrentSubject().consentAcceptedAt) showGoGhostWorkspace();
  else {
    if (goGhostWorkspace) goGhostWorkspace.hidden = true;
    goGhostConsentModal?.classList.remove("hidden");
  }
}

function addGhostFamilySubject() {
  if (goGhostStoreLocked) return;
  const state = ghostCurrentState();
  if (Object.keys(state.subjects).length >= 20) {
    ghostShowIssue("Go Ghost supports up to 20 people on this device. Remove a family member before adding another.",
      goGhostActionError);
    return;
  }
  let subject;
  try { subject = ghostNewSubject("family"); }
  catch {
    ghostShowIssue("A secure browser is required to add a family member. Try an updated browser.", goGhostActionError);
    return;
  }
  const previous = state.activeSubjectId;
  state.subjects[subject.id] = subject;
  state.activeSubjectId = subject.id;
  if (!ghostSaveState(goGhostActionError)) {
    delete state.subjects[subject.id];
    state.activeSubjectId = previous;
    return;
  }
  selectGhostSubject(subject.id, false);
  startGoGhostButton?.focus();
}

function removeGhostSubject() {
  const state = ghostCurrentState();
  if (goGhostStoreLocked || ghostCurrentSubject().kind !== "family") return;
  if (!window.confirm("Remove this person's Go Ghost details and progress from this browser?")) return;
  const removedId = state.activeSubjectId;
  const removed = state.subjects[removedId];
  const hadAttestation = goGhostFamilyAttestedThisVisit.has(removedId);
  goGhostFamilyAttestedThisVisit.delete(removedId);
  delete state.subjects[removedId];
  state.activeSubjectId = Object.keys(state.subjects)[0];
  if (!ghostSaveState(goGhostActionError)) {
    state.subjects[removedId] = removed;
    state.activeSubjectId = removedId;
    if (hadAttestation) goGhostFamilyAttestedThisVisit.add(removedId);
    return;
  }
  selectGhostSubject(state.activeSubjectId, false);
}

function lockGhostWorkspace() {
  if (ghostCaliforniaDropCard) ghostCaliforniaDropCard.hidden = true;
  if (goGhostStoreLocked) return;
  goGhostStoreLocked = true;
  ghostQueueStopRequested = true;
  for (const controller of goGhostAutomationControllers.values()) controller.abort();
  goGhostAutomationControllers.clear();
  goGhostFamilyAttestedThisVisit.clear();
  goGhostState = null;
  for (const input of [ghostFirstNameInput, ghostMiddleNameInput, ghostLastNameInput, ghostCityInput,
    ghostStateInput, ghostBirthYearInput, ghostAddressInput, ghostPhoneInput, ghostEmailInput,
    ghostPreviousCitiesInput, ghostOtherNamesInput]) {
    if (input) input.value = "";
  }
  if (ghostProfileReviewNotice) ghostProfileReviewNotice.textContent = "";
  if (ghostSavedProfileHint) ghostSavedProfileHint.textContent = "";
  if (ghostAccountNameHint) ghostAccountNameHint.textContent = "";
  if (ghostFamilyAttestationInput) ghostFamilyAttestationInput.checked = false;
  if (goGhostAutomationRows) goGhostAutomationRows.innerHTML = "";
  if (ghostSubjectSelect) ghostSubjectSelect.innerHTML = "";
  if (goGhostScopeKeywords) goGhostScopeKeywords.innerHTML = "";
  if (goGhostScopeDetails) goGhostScopeDetails.innerHTML = "";
  if (ghostProgressCount) ghostProgressCount.textContent = "—";
  if (ghostProgressBreakdown) ghostProgressBreakdown.textContent = "";
  if (goGhostWorkspace) goGhostWorkspace.hidden = true;
  goGhostScopeModal?.classList.add("hidden");
  goGhostConsentModal?.classList.add("hidden");
  if (goGhostSessionNotice) goGhostSessionNotice.hidden = false;
  if (goGhostSessionActions) goGhostSessionActions.hidden = true;
}

let goGhostCheckSerial = 0;
let goGhostVisibleBeforeCheck = false;
let goGhostCheckController = null;
function showGhostAccountCheckFailure() {
  lockGhostWorkspace();
  if (goGhostSessionNotice) {
    goGhostSessionNotice.textContent = "We couldn't confirm your sign-in. Your Go Ghost details are hidden. Check your connection, then reload to try again.";
    goGhostSessionNotice.hidden = false;
  }
  if (goGhostSessionActions) goGhostSessionActions.hidden = false;
}

async function checkGhostAccount() {
  if (goGhostStoreLocked) return;
  const serial = ++goGhostCheckSerial;
  goGhostCheckController?.abort();
  const controller = new AbortController();
  goGhostCheckController = controller;
  const timeout = window.setTimeout(() => controller.abort(), 15000);
  const showChecking = window.setTimeout(() => {
    if (serial === goGhostCheckSerial && !goGhostStoreLocked && goGhostAccountCheckStatus) {
      goGhostAccountCheckStatus.hidden = false;
    }
  }, 300);
  // Hide personal details before waiting for the server to confirm this tab's owner.
  if (goGhostWorkspace && !goGhostWorkspace.hidden) goGhostVisibleBeforeCheck = true;
  if (goGhostWorkspace) goGhostWorkspace.hidden = true;
  goGhostScopeModal?.classList.add("hidden");
  try {
    const response = await fetch("/api/me", {
      credentials: "same-origin", cache: "no-store", signal: controller.signal
    });
    if (goGhostStoreLocked || serial !== goGhostCheckSerial) return;
    if (controller.signal.aborted) return showGhostAccountCheckFailure();
    if (!goGhostAccountId && response.status === 401) {
      if (goGhostVisibleBeforeCheck && goGhostWorkspace) goGhostWorkspace.hidden = false;
      goGhostVisibleBeforeCheck = false;
      return;
    }
    if (response.status === 401 || response.status === 403) return lockGhostWorkspace();
    if (!response.ok) return showGhostAccountCheckFailure();
    const body = await response.json();
    if (goGhostStoreLocked || serial !== goGhostCheckSerial) return;
    if (controller.signal.aborted) return showGhostAccountCheckFailure();
    if (body?.user?.id !== goGhostAccountId) return lockGhostWorkspace();
    if (goGhostVisibleBeforeCheck && goGhostWorkspace) goGhostWorkspace.hidden = false;
    goGhostVisibleBeforeCheck = false;
  } catch {
    if (serial === goGhostCheckSerial && !goGhostStoreLocked) showGhostAccountCheckFailure();
  } finally {
    window.clearTimeout(timeout);
    window.clearTimeout(showChecking);
    if (goGhostCheckController === controller) goGhostCheckController = null;
    if (serial === goGhostCheckSerial && goGhostAccountCheckStatus) goGhostAccountCheckStatus.hidden = true;
  }
}

if (goGhostWorkspace) {
  applyGoGhostDeviceFormatting();
  window.addEventListener("resize", applyGoGhostDeviceFormatting);
  // Guest details must not reappear after a sign-in on this tab.
  if (goGhostAccountId) {
    try { window.sessionStorage.removeItem("safeScanGoGhostV2:guest"); } catch { /* Storage unavailable. */ }
  }

  let hasConsent = false;
  try {
    hasConsent = Boolean(ghostCurrentSubject().consentAcceptedAt);
  } catch {
    if (startGoGhostButton) startGoGhostButton.disabled = true;
    ghostShowIssue("A secure browser is required to use Go Ghost. Try an updated browser.", goGhostConsentError);
  }
  if (hasConsent) showGoGhostWorkspace();
  else goGhostConsentModal?.classList.remove("hidden");

  startGoGhostButton?.addEventListener("click", startGoGhost);
  ghostSubjectSelect?.addEventListener("change", () => selectGhostSubject(ghostSubjectSelect.value));
  addGhostFamilyButton?.addEventListener("click", addGhostFamilySubject);
  removeGhostSubjectButton?.addEventListener("click", removeGhostSubject);
  ghostFamilyAttestationInput?.addEventListener("change", () => {
    ghostFamilyAttestationInput.removeAttribute?.("aria-invalid");
    ghostFamilyAttestationInput.removeAttribute?.("aria-describedby");
    const subject = ghostCurrentSubject();
    if (subject.kind !== "family") return;
    const previous = subject.familyAttestedAt;
    const hadAttestation = goGhostFamilyAttestedThisVisit.has(subject.id);
    if (ghostFamilyAttestationInput.checked) {
      goGhostFamilyAttestedThisVisit.add(subject.id);
      subject.familyAttestedAt = new Date().toISOString();
    } else {
      goGhostFamilyAttestedThisVisit.delete(subject.id);
      subject.familyAttestedAt = "";
    }
    if (!ghostSaveState(goGhostActionError)) {
      subject.familyAttestedAt = previous;
      if (hadAttestation) goGhostFamilyAttestedThisVisit.add(subject.id);
      else goGhostFamilyAttestedThisVisit.delete(subject.id);
      ghostFamilyAttestationInput.checked = hadAttestation;
      return;
    }
    ghostClearIssue(goGhostActionError);
  });
  startGhostQueueButton?.addEventListener("click", startGhostAssistedQueue);
  openNextGhostBrokerButton?.addEventListener("click", openNextGhostBroker);

  goGhostProfileForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!saveGhostFormProfile(true)) return;
    renderGoGhostAutomationScope();
    renderGoGhostProgress();
    showCopyToast("Reviewed details saved");
  });

  goGhostProfileForm?.addEventListener("invalid", (event) => {
    event.target?.setAttribute?.("aria-invalid", "true");
    event.target?.setAttribute?.("aria-describedby", "ghostProfileError");
    ghostShowIssue(GHOST_PROFILE_VALIDATION_MESSAGE, ghostProfileError);
  }, true);

  [ghostFirstNameInput, ghostMiddleNameInput, ghostLastNameInput, ghostCityInput, ghostStateInput,
    ghostBirthYearInput, ghostAddressInput, ghostPhoneInput, ghostEmailInput,
    ghostPreviousCitiesInput, ghostOtherNamesInput].forEach((input) => {
    const changed = () => {
      input?.removeAttribute?.("aria-invalid");
      input?.removeAttribute?.("aria-describedby");
      saveGhostFormProfile();
      renderGoGhostAutomationScope();
      renderGoGhostProgress();
    };
    input?.addEventListener(input === ghostStateInput ? "change" : "input", changed);
  });

  clearGhostDataButton?.addEventListener("click", () => {
    if (goGhostStoreLocked) return;
    const scope = goGhostAccountId ? "this account" : "this guest tab";
    if (!window.confirm(`Clear Go Ghost details and progress for all people in ${scope} from this browser? This cannot be undone.`)) return;
    try {
      if (!goGhostStorageArea) throw new Error("Storage unavailable");
      goGhostStorageArea.removeItem(GO_GHOST_STORE_KEY);
    } catch {
      ghostShowIssue("Go Ghost details could not be cleared from this browser. Check storage settings and try again.",
        goGhostActionError);
      return;
    }
    goGhostState = null;
    goGhostFamilyAttestedThisVisit.clear();
    hydrateGoGhostProfile();
    renderGoGhostAutomationScope();
    renderGoGhostProgress();
    if (goGhostWorkspace) goGhostWorkspace.hidden = true;
    goGhostScopeModal?.classList.add("hidden");
    goGhostConsentModal?.classList.remove("hidden");
    startGoGhostButton?.focus();
    showCopyToast("Go Ghost data cleared");
  });

  eraseGhostLegacyButton?.addEventListener("click", () => {
    const erased = ghostEraseLegacyData();
    if (erased) showCopyToast("Older browser details erased");
  });

  window.addEventListener("focus", checkGhostAccount);
  goGhostSessionRetryButton?.addEventListener("click", () => window.location.reload());
  window.addEventListener("pageshow", checkGhostAccount);
  window.addEventListener("pagehide", lockGhostWorkspace);
  window.addEventListener("storage", (event) => {
    if (event.key === GO_GHOST_STORE_KEY) lockGhostWorkspace();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") checkGhostAccount();
  });
  document.querySelectorAll(".sign-out-form").forEach((form) => {
    form.addEventListener("submit", lockGhostWorkspace);
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
  goGhostScopeSubmittedButton?.addEventListener("click", () => runGhostScopeAction("submitted"));
  goGhostScopeRemovedButton?.addEventListener("click", () => runGhostScopeAction("removed"));
  goGhostScopeRecheckButton?.addEventListener("click", () => runGhostScopeAction("recheck"));
  goGhostScopeAbsentButton?.addEventListener("click", () => runGhostScopeAction("absent"));
  goGhostScopePresentButton?.addEventListener("click", () => runGhostScopeAction("present"));
  goGhostScopeResetButton?.addEventListener("click", () => runGhostScopeAction("reset"));
  goGhostScopeCopyButton?.addEventListener("click", () => runGhostScopeAction("copy"));
  goGhostScopeBrandSelect?.addEventListener("change", () =>
    openGoGhostScopeModal(goGhostScopeBrandSelect.value, false));

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !goGhostScopeModal?.classList.contains("hidden")) closeGoGhostScopeModal();
  });
}


