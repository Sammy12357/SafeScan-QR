// Pure Go Ghost progress state logic. This file has no browser or storage APIs;
// a future page/extension integration may load it as a plain script.
const GoGhostState = (() => {
  "use strict";

  const VERSION = 2;
  const STATES = Object.freeze([
    "not_started", "scanning", "not_found", "needs_review", "found",
    "submitting", "needs_human", "submitted", "awaiting_email",
    "confirmed", "verifying", "user_reported_removed", "client_recheck_absent",
    "still_listed", "failed", "skipped"
  ]);
  const STATE_SET = new Set(STATES);
  const FAILURE_CODES = new Set([
    "network", "layout_changed", "permission_denied", "broker_unavailable", "unknown"
  ]);
  const HUMAN_REASONS = new Set(["captcha", "identity", "record_selection"]);
  const RECHECK_METHODS = new Set(["user_recheck", "extension_recheck"]);

  // Manual actions can record work done outside SafeScan. Only recheck_absent
  // can produce client_recheck_absent, and only after begin_recheck.
  const TRANSITIONS = Object.freeze({
    start_scan: { from: ["not_started", "not_found", "failed", "skipped", "still_listed"], to: "scanning" },
    scan_not_found: { from: ["scanning"], to: "not_found" },
    scan_found: { from: ["scanning"], to: "found" },
    scan_ambiguous: { from: ["scanning"], to: "needs_review" },
    start_submit: { from: ["found", "needs_review"], to: "submitting" },
    needs_human: { from: ["submitting"], to: "needs_human" },
    resume_submit: { from: ["needs_human"], to: "submitting" },
    submit_recorded: { from: ["submitting", "needs_human"], to: "submitted" },
    mark_not_found: { from: ["not_started", "scanning", "found", "needs_review", "failed", "skipped"], to: "not_found" },
    mark_submitted: { from: ["not_started", "scanning", "found", "needs_review", "submitting", "needs_human", "failed", "skipped", "still_listed"], to: "submitted" },
    report_removed: { from: ["not_started", "submitted", "awaiting_email", "confirmed", "verifying", "still_listed", "failed", "skipped"], to: "user_reported_removed" },
    await_email: { from: ["submitted"], to: "awaiting_email" },
    confirm_email: { from: ["awaiting_email"], to: "confirmed" },
    begin_recheck: { from: ["submitted", "awaiting_email", "confirmed", "user_reported_removed", "client_recheck_absent", "still_listed"], to: "verifying" },
    recheck_absent: { from: ["verifying"], to: "client_recheck_absent" },
    recheck_present: { from: ["verifying"], to: "still_listed" },
    mark_failed: { from: ["scanning", "needs_review", "found", "submitting", "needs_human", "submitted", "awaiting_email", "confirmed", "verifying", "still_listed"], to: "failed" },
    mark_skipped: { from: ["not_started", "not_found", "needs_review", "failed"], to: "skipped" }
  });
  const EVENTS = Object.freeze([...Object.keys(TRANSITIONS), "reset"]);

  function isIsoTime(value) {
    return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
      && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
  }

  function brokerIdsFrom(value) {
    if (!Array.isArray(value) || !value.length) throw new TypeError("A nonempty broker ID list is required");
    const ids = new Set();
    for (const id of value) {
      if (typeof id !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(id) || ids.has(id)) {
        throw new TypeError("Broker IDs must be unique, bounded identifiers");
      }
      ids.add(id);
    }
    return ids;
  }

  function emptyEntry() {
    return { state: "not_started", source: "system", updatedAt: null };
  }

  function migrateLegacyEntry(legacy) {
    if (!legacy || typeof legacy !== "object" || Array.isArray(legacy)) return emptyEntry();
    // Old clients saved no-match as removed:true with a finish reason. It must
    // win over removed:true so a no-match is never counted as a removal.
    const hasFinishReason = typeof legacy.finishReason === "string" && legacy.finishReason.trim().length > 0;
    let state = "not_started";
    if (legacy.noMatch === true || hasFinishReason) state = "not_found";
    else if (legacy.removed === true) state = "user_reported_removed";
    else if (legacy.submitted === true) state = "submitted";
    return {
      state,
      source: "legacy_manual",
      updatedAt: isIsoTime(legacy.updatedAt) ? legacy.updatedAt : null
    };
  }

  // The caller must decide whether unowned legacy browser data may be read at
  // all. This helper never reads localStorage and never auto-imports anything.
  function migrateLegacyProgress(raw, brokerIds) {
    const validIds = brokerIdsFrom(brokerIds);
    const output = Object.create(null);
    for (const id of validIds) {
      if (raw && typeof raw === "object" && Object.prototype.hasOwnProperty.call(raw, id)) {
        output[id] = migrateLegacyEntry(raw[id]);
      }
    }
    return output;
  }

  function transition(entry, event) {
    const before = entry || emptyEntry();
    if (!before || !STATE_SET.has(before.state)) throw new TypeError("Invalid current Go Ghost state");
    if (!event || typeof event !== "object" || !isIsoTime(event.at)) {
      throw new TypeError("A transition requires an ISO timestamp");
    }
    if (!EVENTS.includes(event.type)) throw new TypeError("Unknown Go Ghost event");
    if (event.source !== "manual" && event.source !== "extension") {
      throw new TypeError("Event source must be manual or extension");
    }
    if (event.type === "reset") return { state: "not_started", source: event.source, updatedAt: event.at };
    const rule = TRANSITIONS[event.type];
    if (!rule.from.includes(before.state)) {
      throw new Error(`Cannot ${event.type} from ${before.state}`);
    }
    if (event.type === "needs_human" && !HUMAN_REASONS.has(event.reason)) {
      throw new TypeError("A recognized human checkpoint is required");
    }
    if (event.type === "mark_failed" && !FAILURE_CODES.has(event.code)) {
      throw new TypeError("A recognized failure code is required");
    }
    if ((event.type === "recheck_absent" || event.type === "recheck_present")
        && !RECHECK_METHODS.has(event.method)) {
      throw new TypeError("A documented recheck method is required");
    }
    if ((event.type === "recheck_absent" || event.type === "recheck_present")
        && ((event.source === "manual" && event.method !== "user_recheck")
          || (event.source === "extension" && event.method !== "extension_recheck"))) {
      throw new TypeError("Recheck method must match the event source");
    }
    const next = { state: rule.to, source: event.source, updatedAt: event.at };
    if (event.type === "needs_human") next.humanReason = event.reason;
    if (event.type === "mark_failed") next.failureCode = event.code;
    if (event.type === "recheck_absent" || event.type === "recheck_present") {
      next.recheck = { method: event.method, checkedAt: event.at };
    }
    return next;
  }

  function sanitizedEntry(entry) {
    if (!entry || !STATE_SET.has(entry.state)) return emptyEntry();
    if (entry.state === "client_recheck_absent" || entry.state === "still_listed") {
      const method = entry.recheck?.method;
      const validSource = (entry.source === "manual" && method === "user_recheck")
        || (entry.source === "extension" && method === "extension_recheck");
      if (!validSource || !isIsoTime(entry.recheck?.checkedAt)) return emptyEntry();
    }
    const clean = {
      state: entry.state,
      source: ["manual", "extension", "legacy_manual", "system"].includes(entry.source) ? entry.source : "system",
      updatedAt: isIsoTime(entry.updatedAt) ? entry.updatedAt : null
    };
    if (entry.state === "needs_human" && HUMAN_REASONS.has(entry.humanReason)) {
      clean.humanReason = entry.humanReason;
    }
    if (entry.state === "failed" && FAILURE_CODES.has(entry.failureCode)) {
      clean.failureCode = entry.failureCode;
    }
    if (entry.state === "client_recheck_absent" || entry.state === "still_listed") {
      clean.recheck = { method: entry.recheck.method, checkedAt: entry.recheck.checkedAt };
    }
    return clean;
  }

  // A group name is deliberately not accepted here. One PeopleConnect action
  // cannot mark Intelius, US Search, TruthFinder and Instant Checkmate absent.
  function applyBrokerEvent(progress, brokerId, event, brokerIds) {
    const validIds = brokerIdsFrom(brokerIds);
    if (!validIds.has(brokerId)) throw new TypeError("Unknown broker ID");
    const before = progress && typeof progress === "object" ? progress : {};
    const output = Object.create(null);
    for (const id of validIds) {
      if (Object.prototype.hasOwnProperty.call(before, id)) output[id] = sanitizedEntry(before[id]);
    }
    output[brokerId] = transition(output[brokerId], event);
    return output;
  }

  function summarize(progress, brokerIds) {
    const validIds = brokerIdsFrom(brokerIds);
    const counts = {
      total: validIds.size, not_started: 0, not_found: 0,
      user_reported_removed: 0, client_recheck_absent: 0,
      in_progress: 0, failed: 0, skipped: 0
    };
    for (const id of validIds) {
      const entry = progress && Object.prototype.hasOwnProperty.call(progress, id) ? progress[id] : null;
      const state = sanitizedEntry(entry).state;
      if (Object.prototype.hasOwnProperty.call(counts, state)) counts[state] += 1;
      else counts.in_progress += 1;
    }
    return counts;
  }

  return Object.freeze({ VERSION, STATES, EVENTS, TRANSITIONS, emptyEntry,
    migrateLegacyEntry, migrateLegacyProgress, sanitizedEntry, transition, applyBrokerEvent, summarize });
})();

if (typeof module !== "undefined" && module.exports) module.exports = GoGhostState;
