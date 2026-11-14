const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function makeElement() {
  const classes = new Set();
  return {
    dataset: {}, hidden: false, value: '', innerHTML: '', textContent: '',
    handlers: {},
    classList: {
      add: name => classes.add(name),
      remove: name => classes.delete(name),
      contains: name => classes.has(name),
      toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name)
    },
    addEventListener(name, callback) { this.handlers[name] = callback; },
    querySelector() { return {focus() {}, scrollIntoView() {}}; },
    setAttribute() {}, removeAttribute() {}, focus() {}, scrollIntoView() {}
  };
}

const ids = [
  'goGhostWorkspace', 'goGhostConsentModal', 'startGoGhostButton',
  'goGhostProfileForm', 'clearGhostDataButton', 'goGhostAutomationRows',
  'goGhostScopeModal', 'goGhostScopeTitle', 'goGhostScopePriority',
  'goGhostScopeDescription', 'goGhostScopeKeywords', 'goGhostScopeDetails',
  'goGhostScopeSearchButton', 'goGhostScopeOptOutButton',
  'goGhostScopeFinishButton', 'goGhostScopeNoMatchButton',
  'goGhostScopeCopyButton', 'openNextGhostBrokerButton',
  'ghostProgressCount', 'ghostNameInput', 'ghostLocationInput',
  'ghostAddressInput', 'ghostPhoneInput', 'ghostEmailInput',
  'goGhostDeviceNotice'
];
const elements = Object.fromEntries(ids.map(id => [id, makeElement()]));
elements.goGhostWorkspace.hidden = true;
elements.goGhostWorkspace.dataset.browserAutomationAvailable = 'false';
elements.goGhostScopeModal.classList.add('hidden');
const saved = new Map();
const opened = [];
const copied = [];
const window = {
  localStorage: {
    getItem: key => saved.get(key) ?? null,
    setItem: (key, value) => saved.set(key, value),
    removeItem: key => saved.delete(key)
  },
  matchMedia: () => ({matches: false}),
  addEventListener() {},
  open: url => { opened.push(url); return {opener: null}; }
};
const document = {
  getElementById: id => elements[id] || null,
  body: {classList: makeElement().classList},
  addEventListener() {}
};
const context = vm.createContext({
  document, window, URL, AbortController,
  isMobileDevice: () => false,
  showCopyToast: () => {},
  copyTextToClipboard: async value => { copied.push(value); return true; },
  escapeHtml: value => String(value ?? '').replace(/[&<>\"]/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'
  })[char])
});
vm.runInContext(fs.readFileSync('static/app-go-ghost.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('static/app-go-ghost-ui.js', 'utf8'), context);

async function main() {
  assert.equal(vm.runInContext('GO_GHOST_BROWSER_AUTOMATION_AVAILABLE', context), false);
  assert.equal(elements.goGhostWorkspace.hidden, true, 'consent should gate the workspace');
  assert.equal(elements.goGhostAutomationRows.innerHTML, '', 'rows should wait for consent');

  elements.startGoGhostButton.handlers.click();
  assert.equal(elements.goGhostWorkspace.hidden, false);
  assert.equal(elements.goGhostConsentModal.classList.contains('hidden'), true);
  assert.equal(elements.ghostProgressCount.textContent, '0 / 18');
  const rows = elements.goGhostAutomationRows.innerHTML;
  const brokerIds = [...rows.matchAll(/data-ghost-scope="([^"]+)"/g)].map(match => match[1]);
  assert.equal(brokerIds.length, 18, 'all tracked brokers must have a visible row');
  assert.equal(new Set(brokerIds).size, 18);
  assert.equal(brokerIds.at(-1), 'cyberbackgroundchecks');
  assert.equal(rows.includes('Manual'), true);
  assert.equal(rows.includes('Run auto fill'), false);

  elements.ghostNameInput.value = 'Example Person';
  elements.ghostEmailInput.value = 'person@example.com';
  elements.ghostNameInput.handlers.input();
  elements.ghostEmailInput.handlers.input();
  const lastId = brokerIds.at(-1);
  elements.goGhostAutomationRows.handlers.click({
    target: {closest: selector => selector === '[data-ghost-scope]'
      ? {dataset: {ghostScope: lastId}} : null}
  });
  assert.equal(elements.goGhostScopeModal.classList.contains('hidden'), false);
  assert.equal(elements.goGhostScopeTitle.textContent, 'CyberBackgroundChecks');
  assert.match(elements.goGhostScopeKeywords.innerHTML, /Example Person/);
  assert.match(elements.goGhostScopeDetails.innerHTML, /Find your matching listing/);
  assert.doesNotMatch(elements.goGhostScopeDetails.innerHTML, /Backend does/);

  await elements.goGhostScopeSearchButton.handlers.click();
  assert.match(opened.at(-1), /^https:\/\/www\.google\.com\/search\?/);
  await elements.goGhostScopeOptOutButton.handlers.click();
  assert.equal(opened.at(-1), 'https://www.cyberbackgroundchecks.com/removal');
  assert.doesNotMatch(opened.at(-1), /Example|person%40|person@/i);
  assert.match(copied.at(-1), /CyberBackgroundChecks opt-out packet/);
  const copiesBeforeClick = copied.length;
  await elements.goGhostScopeCopyButton.handlers.click();
  assert.equal(copied.length, copiesBeforeClick + 1);
  assert.match(copied.at(-1), /Name: Example Person/);

  await elements.goGhostScopeNoMatchButton.handlers.click();
  assert.equal(elements.ghostProgressCount.textContent, '1 / 18');
  const finalRow = elements.goGhostAutomationRows.innerHTML.match(
    /<button[^>]+data-ghost-scope="cyberbackgroundchecks"[\s\S]*?<\/button>/
  );
  assert.ok(finalRow, 'last broker should remain visible after progress changes');
  assert.match(finalRow[0], /Removed/);
  assert.equal(opened.some(url => url.includes('safescan_prefill')), false);
}

main().catch(error => { console.error(error); process.exitCode = 1; });
