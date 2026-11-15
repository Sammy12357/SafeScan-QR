const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("static/app-core.js", "utf8");

function walletPage({ email, cached = null, storageDenied = false, status = 503, statusBody = null, fetchResponse = null }) {
  const writes = [];
  const feedback = [];
  const body = {};
  const classList = () => {
    const classes = new Set();
    return {
      add(value) { classes.add(value); },
      remove(value) { classes.delete(value); },
      contains(value) { return classes.has(value); }
    };
  };
  const node = () => {
    let value = "";
    const attributes = new Map();
    return {
      classList: classList(), disabled: false, isConnected: true,
      get textContent() { return value; },
      set textContent(next) { value = next; writes.push(String(next)); },
      get innerHTML() { return value; },
      set innerHTML(next) { value = next; writes.push(String(next)); },
      getAttribute(name) { return attributes.has(name) ? attributes.get(name) : null; },
      setAttribute(name, next) { attributes.set(name, String(next)); },
      removeAttribute(name) { attributes.delete(name); },
      focus() {}, insertAdjacentElement() {}, addEventListener() {}
    };
  };
  const nodes = {
    hiddenWalletInput: node(), walletStatus: node(), connectWalletButton: node(),
    disconnectWalletButton: node(), topConnectWalletButton: node()
  };
  const profile = { dataset: { email }, textContent: email };
  const document = {
    body, activeElement: body,
    getElementById(id) { return nodes[id] || null; },
    querySelector(selector) { return selector === ".profile-email" ? profile : null; },
    createElement() { throw new Error("canvas unavailable"); }
  };
  let stored = cached === null ? null : JSON.stringify(cached);
  const localStorage = {
    getItem() { if (storageDenied) throw new Error("denied"); return stored; },
    setItem(_key, value) { if (storageDenied) throw new Error("denied"); stored = value; },
    removeItem() { if (storageDenied) throw new Error("denied"); stored = null; }
  };
  const window = {
    history: { scrollRestoration: "auto" }, localStorage,
    location: { href: "https://example.test/token", origin: "https://example.test" },
    fetch: fetchResponse || (async () => ({
      ok: status === 200, status,
      json: async () => statusBody || (status === 200 ? { connected: false } : { error: "unavailable" })
    })),
    setTimeout, clearTimeout, addEventListener() {}
  };
  const context = vm.createContext({
    window, document, navigator: { userAgent: "", language: "en", platform: "test" },
    screen: { width: 375, height: 800, colorDepth: 24 }, crypto: { subtle: null },
    Headers, AbortController, TextEncoder, URL, Intl, performance, console,
    walletFeedbackEvents: feedback,
    fetch: (...args) => window.fetch(...args)
  });
  vm.runInContext(source + "\nshowWalletFeedback = (type, message, retry, title) => walletFeedbackEvents.push({ type, message, retry, title }); this.walletTest = { getCurrentProfile, getAuthoritativeWalletProfile, renderWalletState, syncWalletFromServer, disconnectWalletConnection, boundedWalletStep, startWalletOperation, finishWalletOperation, setWalletBusy };", context);
  return { api: context.walletTest, nodes, writes, feedback, getStored: () => stored };
}

(async () => {
  const anotherAccount = walletPage({
    email: "current@example.test",
    cached: { email: "other@example.test", walletAddress: "other-wallet", walletVerified: true },
    status: 503
  });
  assert.equal(anotherAccount.api.getCurrentProfile().walletVerified, undefined);
  anotherAccount.api.renderWalletState({ email: "current@example.test" });
  await anotherAccount.api.syncWalletFromServer();
  assert.equal(anotherAccount.writes.some((text) => text.includes("Connected:")), false);
  assert.equal(anotherAccount.nodes.connectWalletButton.disabled, false);

  const sameAccount = walletPage({
    email: "current@example.test",
    cached: { email: "current@example.test", walletAddress: "cached-wallet", walletVerified: true },
    status: 503
  });
  // Startup deliberately renders only the account identity until the server responds.
  sameAccount.api.renderWalletState({ email: "current@example.test" });
  await sameAccount.api.syncWalletFromServer();
  assert.equal(sameAccount.writes.some((text) => text.includes("Connected:")), false);
  assert.equal(JSON.parse(sameAccount.getStored()).walletVerified, undefined);

  const denied = walletPage({ email: "current@example.test", storageDenied: true, status: 503 });
  denied.api.renderWalletState({ email: "current@example.test" });
  await denied.api.syncWalletFromServer();
  assert.equal(denied.writes.some((text) => text.includes("Connected:")), false);
  assert.equal(denied.nodes.connectWalletButton.disabled, false);

  const deniedButVerified = walletPage({
    email: "current@example.test", storageDenied: true, status: 200,
    statusBody: { connected: true, walletAddress: "server-wallet" }
  });
  deniedButVerified.api.renderWalletState({ email: "current@example.test" });
  await deniedButVerified.api.syncWalletFromServer();
  const operation = deniedButVerified.api.startWalletOperation();
  deniedButVerified.api.setWalletBusy("Verifying wallet...");
  assert.equal(deniedButVerified.nodes.topConnectWalletButton.textContent, "Connecting…");
  assert.equal(deniedButVerified.nodes.topConnectWalletButton.getAttribute("aria-busy"), "true");
  deniedButVerified.api.finishWalletOperation(operation);
  assert.equal(deniedButVerified.nodes.walletStatus.textContent.includes("Connected:"), true);
  assert.equal(deniedButVerified.nodes.connectWalletButton.disabled, true);
  assert.equal(deniedButVerified.nodes.topConnectWalletButton.disabled, true);
  assert.equal(deniedButVerified.nodes.topConnectWalletButton.getAttribute("aria-busy"), null);

  let releaseStatus;
  const heldStatus = new Promise((resolve) => { releaseStatus = resolve; });
  const invalidated = walletPage({
    email: "current@example.test",
    cached: { email: "current@example.test", walletAddress: "cached-wallet", walletVerified: true },
    fetchResponse: () => heldStatus
  });
  invalidated.api.renderWalletState({ email: "current@example.test" });
  const pendingStatus = invalidated.api.syncWalletFromServer();
  const pendingOperation = invalidated.api.startWalletOperation();
  invalidated.api.finishWalletOperation(pendingOperation);
  assert.equal(invalidated.writes.some((text) => text.includes("Connected:")), false);
  releaseStatus({ ok: true, status: 200, json: async () => ({ connected: true, walletAddress: "server-wallet" }) });
  await pendingStatus;
  assert.equal(invalidated.writes.some((text) => text.includes("Connected:")), false);

  await assert.rejects(
    denied.api.boundedWalletStep(() => new Promise(() => {}), 20, null, "Timed out"),
    /Timed out/
  );

  // A failed wallet-status lookup leaves the browser unable to infer whether
  // this account is linked. The server DELETE must still be attempted.
  const unknownCalls = [];
  const unknown = walletPage({
    email: "current@example.test",
    fetchResponse: async (_url, options = {}) => {
      unknownCalls.push(options.method || "GET");
      if (options.method === "DELETE") return { ok: true, status: 200, json: async () => ({ success: true }) };
      return { ok: false, status: 503, json: async () => ({ error: "Unavailable" }) };
    }
  });
  await unknown.api.syncWalletFromServer();
  let providerDisconnects = 0;
  await unknown.api.disconnectWalletConnection({ provider: { disconnect: async () => { providerDisconnects += 1; } } });
  assert.deepEqual(unknownCalls, ["GET", "DELETE"]);
  assert.equal(providerDisconnects, 1);
  assert.equal(unknown.feedback.at(-1).type, "success");

  const failedCalls = [];
  const failed = walletPage({
    email: "current@example.test",
    fetchResponse: async (_url, options = {}) => {
      failedCalls.push(options.method || "GET");
      if (options.method === "DELETE") return { ok: false, status: 503, json: async () => ({ error: "Unavailable" }) };
      return { ok: true, status: 200, json: async () => ({ connected: true, walletAddress: "server-wallet" }) };
    }
  });
  await failed.api.syncWalletFromServer();
  let failedProviderCalls = 0;
  await failed.api.disconnectWalletConnection({ provider: { disconnect: async () => { failedProviderCalls += 1; } } });
  assert.deepEqual(failedCalls, ["GET", "DELETE"]);
  assert.equal(failedProviderCalls, 0, "provider disconnect waits for server unlink");
  assert.equal(failed.feedback.at(-1).type, "error");
  assert.equal(typeof failed.feedback.at(-1).retry, "function");
  assert.equal(failed.api.getAuthoritativeWalletProfile().walletVerified, true);

  const alreadyUnlinked = walletPage({
    email: "current@example.test",
    fetchResponse: async () => ({ ok: false, status: 404, json: async () => ({ code: "wallet_not_found" }) })
  });
  await alreadyUnlinked.api.disconnectWalletConnection();
  assert.equal(alreadyUnlinked.feedback.at(-1).type, "success", "404 means the server link is already absent");

  const unconfirmed = walletPage({
    email: "current@example.test",
    fetchResponse: async () => ({ ok: true, status: 200, json: async () => ({ success: false }) })
  });
  await unconfirmed.api.disconnectWalletConnection();
  assert.equal(unconfirmed.feedback.at(-1).type, "error", "an unconfirmed 2xx body must not claim unlink");

  const providerFailure = walletPage({
    email: "current@example.test",
    fetchResponse: async () => ({ ok: true, status: 200, json: async () => ({ success: true }) })
  });
  await providerFailure.api.disconnectWalletConnection({ provider: { disconnect: async () => { throw new Error("Wallet app unavailable"); } } });
  assert.equal(providerFailure.feedback.at(-1).type, "warning");
  assert.match(providerFailure.feedback.at(-1).message, /SafeScan wallet link was removed/);
  assert.equal(providerFailure.api.getAuthoritativeWalletProfile().walletVerified, undefined);

  const expired = walletPage({
    email: "current@example.test",
    fetchResponse: async (_url, options = {}) => options.method === "DELETE"
      ? { ok: false, status: 401, json: async () => ({ error: "Sign in to continue" }) }
      : { ok: true, status: 200, json: async () => ({ connected: true, walletAddress: "server-wallet" }) }
  });
  await expired.api.syncWalletFromServer();
  await expired.api.disconnectWalletConnection();
  assert.equal(expired.feedback.at(-1).type, "error");
  assert.match(expired.feedback.at(-1).message, /sign-in expired/i);
  assert.equal(expired.api.getAuthoritativeWalletProfile().walletVerified, undefined,
    "expired auth must not keep a verified wallet claim on a stale page");
  console.log("Wallet cache isolation, authoritative state, denied storage, and deadline: pass");
})().catch((error) => { console.error(error); process.exitCode = 1; });
