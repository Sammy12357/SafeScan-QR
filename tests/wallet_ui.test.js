const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("static/app-core.js", "utf8");

function walletPage({ email, cached = null, storageDenied = false, status = 503, statusBody = null, fetchResponse = null }) {
  const writes = [];
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
    fetch: (...args) => window.fetch(...args)
  });
  vm.runInContext(source + "\nthis.walletTest = { getCurrentProfile, renderWalletState, syncWalletFromServer, boundedWalletStep, startWalletOperation, finishWalletOperation, setWalletBusy };", context);
  return { api: context.walletTest, nodes, writes, getStored: () => stored };
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
  console.log("Wallet cache isolation, authoritative state, denied storage, and deadline: pass");
})().catch((error) => { console.error(error); process.exitCode = 1; });
