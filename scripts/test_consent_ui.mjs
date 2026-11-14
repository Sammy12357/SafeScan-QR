#!/usr/bin/env node
// Exercise the consent widget with browser-shaped fakes, without a live server.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = fs.readFileSync(path.join(root, "static/app-widgets.js"), "utf8");
const start = source.indexOf("function storedConsentIsFresh(");
const end = source.indexOf("const revealTargets", start);
assert(start >= 0 && end > start, "consent widget section exists");
const consentCode = source.slice(start, end);

class Element {
  constructor() {
    this.classes = new Set(["hidden"]);
    this.classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      contains: (name) => this.classes.has(name),
    };
    this.listeners = new Map();
    this.dataset = {};
    this.disabled = false;
    this.textContent = "";
  }
  addEventListener(name, handler) { this.listeners.set(name, handler); }
  setAttribute() {}
  focus() {}
}

function loadWidget({ revoked = false, response = { ok: true, id: "consent_1" }, initialChoice } = {}) {
  const storage = new Map();
  if (initialChoice) storage.set("safeScanConsent", JSON.stringify({
    consentType: initialChoice, bannerVersion: "consent-v1", timestamp: new Date().toISOString(),
  }));
  const banner = new Element();
  banner.dataset.version = "consent-v1";
  const buttons = [new Element(), new Element(), new Element()];
  banner.querySelectorAll = () => buttons;
  const elements = Object.fromEntries([
    "cookieConsentPreferences", "manageConsentPreferences", "consentAnalytics",
    "consentSaveStatus", "cancelConsentPreferences", "saveConsentPreferences",
  ].map((id) => [id, new Element()]));
  elements.consentAnalytics.checked = false;
  const requests = [];
  const context = {
    cookieConsentBanner: banner,
    document: {
      getElementById: (id) => id === "consentRevocationApplied" ? (revoked ? new Element() : null) : elements[id],
      querySelector: (selector) => selector === 'meta[name="csrf-token"]' ? { content: "csrf-test" } : null,
    },
    window: { localStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    } },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { ok: response.ok, status: response.ok ? 200 : 400, json: async () => response };
    },
  };
  vm.runInNewContext(consentCode, context);
  return { context, banner, buttons, elements, requests, storage };
}

const failed = loadWidget({ response: { ok: false } });
await failed.context.saveConsentChoice("all");
assert.equal(failed.banner.classList.contains("hidden"), false);
assert.equal(failed.storage.has("safeScanConsent"), false);
assert.match(failed.elements.consentSaveStatus.textContent, /Could not save/);
assert(failed.buttons.every((button) => !button.disabled));

const legacyCustom = loadWidget({ initialChoice: "custom" });
assert.equal(legacyCustom.banner.classList.contains("hidden"), false);

const managed = loadWidget();
managed.elements.manageConsentPreferences.listeners.get("click")();
assert.equal(managed.elements.cookieConsentPreferences.classList.contains("hidden"), false);
await managed.context.saveConsentChoice(managed.elements.consentAnalytics.checked ? "all" : "essential_only");
assert.equal(managed.requests[0].url, "/api/consent");
assert.equal(managed.requests[0].options.headers["X-CSRF-Token"], "csrf-test");
assert.equal(JSON.parse(managed.requests[0].options.body).consentType, "essential_only");
assert.equal(JSON.parse(managed.storage.get("safeScanConsent")).consentType, "essential_only");
assert.equal(managed.banner.classList.contains("hidden"), true);

const revoked = loadWidget({ revoked: true, initialChoice: "all" });
assert.equal(JSON.parse(revoked.storage.get("safeScanConsent")).consentType, "essential_only");
assert.equal(revoked.storage.has("safeScanConsentId"), false);

console.log("Consent widget checks passed");
