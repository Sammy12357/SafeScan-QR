const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function makeElement() {
  const classes = new Set();
  return {
    dataset: {}, hidden: false, value: '', checked: false, disabled: false, innerHTML: '', textContent: '',
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
  'goGhostScopeSubmittedButton', 'goGhostScopeRemovedButton',
  'goGhostScopeResetButton', 'goGhostScopeCopyButton',
  'openNextGhostBrokerButton',
  'ghostProgressCount', 'ghostFirstNameInput', 'ghostMiddleNameInput', 'ghostLastNameInput',
  'ghostCityInput', 'ghostStateInput', 'ghostBirthYearInput', 'ghostAddressInput',
  'ghostPhoneInput', 'ghostEmailInput', 'ghostPreviousCitiesInput', 'ghostOtherNamesInput',
  'ghostProfileReviewNotice', 'ghostSavedProfileHint', 'ghostAccountNameHint',
  'goGhostDeviceNotice', 'goGhostLegacyNotice', 'goGhostLegacyActions', 'eraseGhostLegacyButton', 'goGhostSessionNotice',
  'ghostSubjectSelect', 'addGhostFamilyButton', 'removeGhostSubjectButton',
  'ghostFamilyAttestationLabel', 'ghostFamilyAttestationInput'
];
const elements = Object.fromEntries(ids.map(id => [id, makeElement()]));
elements.goGhostBrokerRegistry = makeElement();
elements.goGhostBrokerRegistry.textContent = fs.readFileSync('data/go_ghost/brokers.json', 'utf8');
elements.goGhostWorkspace.hidden = true;
elements.goGhostWorkspace.dataset.browserAutomationAvailable = 'false';
elements.goGhostWorkspace.dataset.accountId = '';
elements.goGhostScopeModal.classList.add('hidden');
let closeFocusCount = 0;
elements.goGhostScopeModal.querySelector = selector => selector === '.ghost-scope-close'
  ? {focus() { closeFocusCount += 1; }} : null;
const saved = new Map();
const sessionSaved = new Map();
const opened = [];
const copied = [];
let nextUuid = 1;
const storage = map => ({
  get length() { return map.size; },
  key: index => [...map.keys()][index] ?? null,
  getItem: key => map.get(key) ?? null,
  setItem: (key, value) => map.set(key, value),
  removeItem: key => map.delete(key)
});
const window = {
  localStorage: storage(saved),
  sessionStorage: storage(sessionSaved),
  crypto: {randomUUID: () => `00000000-0000-4000-8000-${String(nextUuid++).padStart(12, '0')}`},
  confirm: () => true,
  matchMedia: () => ({matches: false}),
  addEventListener() {},
  open: url => { opened.push(url); return {opener: null}; }
};
const document = {
  getElementById: id => elements[id] || null,
  body: {classList: makeElement().classList},
  addEventListener() {},
  querySelectorAll: () => []
};
const context = vm.createContext({
  document, window, URL, AbortController,
  fetch: async () => ({status: 401, ok: false}),
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

  elements.ghostFirstNameInput.value = 'Example';
  elements.ghostLastNameInput.value = 'Person';
  elements.ghostCityInput.value = 'Tampa';
  elements.ghostStateInput.value = 'FL';
  elements.ghostAddressInput.value = '123 Private Street';
  elements.ghostPhoneInput.value = '8135550100';
  elements.ghostEmailInput.value = 'person@example.com';
  elements.ghostFirstNameInput.handlers.input();
  elements.ghostLastNameInput.handlers.input();
  elements.ghostCityInput.handlers.input();
  elements.ghostStateInput.handlers.change();
  elements.ghostAddressInput.handlers.input();
  elements.ghostPhoneInput.handlers.input();
  elements.ghostEmailInput.handlers.input();
  elements.goGhostProfileForm.handlers.submit({preventDefault() {}});
  const brokerUrls = vm.runInContext('goGhostBrokers.map(broker => [broker.id, goGhostBrokerOptOutUrl(broker)])', context);
  const brokerUrlById = Object.fromEntries(brokerUrls);
  for (const id of ['intelius', 'ussearch', 'instantcheckmate', 'truthfinder']) {
    assert.equal(brokerUrlById[id], 'https://suppression.peopleconnect.us/');
  }
  assert.equal(brokerUrlById.beenverified, 'https://www.beenverified.com/svc/optout/search/optouts');
  assert.equal(brokerUrlById.peoplelooker, 'https://www.peoplelooker.com/svc/optout/search/optouts');
  assert.equal(brokerUrlById.neighborwho, 'https://www.neighborwho.com/svc/optout/search/optouts');
  assert.equal(brokerUrls.some(([, url]) => /Private|8135550100|person%40example|person@example/i.test(url)), false);
  const searchFor = id => vm.runInContext(`goGhostBrokerSearchUrl(goGhostBrokers.find(b => b.id === '${id}'),
    {name: 'Example Person', location: 'Tampa, FL'})`, context);
  assert.equal(searchFor('fastpeoplesearch'), 'https://www.fastpeoplesearch.com/');
  assert.equal(searchFor('whitepages'), 'https://www.whitepages.com/');
  assert.equal(searchFor('truepeoplesearch'), 'https://www.truepeoplesearch.com/');
  assert.equal(searchFor('beenverified'), brokerUrlById.beenverified);
  const familyPacket = vm.runInContext(`goGhostCopyPacket(goGhostBrokers[0],
    {name: 'Family Member', address: '', location: '', email: ''}, 'https://example.test/search')`, context);
  assert.doesNotMatch(familyPacket, /I am the subject|Requester type:/i);
  const allSearchUrls = vm.runInContext(`goGhostBrokers.map(broker => goGhostBrokerSearchUrl(broker,
    {name: 'Example Person', location: 'Tampa, FL', address: '123 Private Street', phone: '8135550100', email: 'person@example.com'}))`, context);
  assert.equal(allSearchUrls.length, 18);
  for (const url of allSearchUrls) {
    assert.equal(new URL(url).search, '', 'broker starting links must have no query');
    assert.doesNotMatch(url, /Example|Tampa|Private|8135550100|person(?:%40|@)/i);
  }
  const lastId = brokerIds.at(-1);
  elements.goGhostAutomationRows.handlers.click({
    target: {closest: selector => selector === '[data-ghost-scope]'
      ? {dataset: {ghostScope: lastId}} : null}
  });
  assert.equal(elements.goGhostScopeModal.classList.contains('hidden'), false);
  assert.equal(closeFocusCount, 1, 'opening a broker should focus the close button');
  assert.equal(elements.goGhostScopeTitle.textContent, 'CyberBackgroundChecks');
  assert.match(elements.goGhostScopeKeywords.innerHTML, /Example Person/);
  assert.match(elements.goGhostScopeDetails.innerHTML, /Find your matching listing/);
  assert.doesNotMatch(elements.goGhostScopeDetails.innerHTML, /Backend does/);

  await elements.goGhostScopeSearchButton.handlers.click();
  assert.equal(opened.at(-1), 'https://www.cyberbackgroundchecks.com/');
  await elements.goGhostScopeOptOutButton.handlers.click();
  assert.equal(opened.at(-1), 'https://www.cyberbackgroundchecks.com/removal');
  assert.doesNotMatch(opened.at(-1), /Example|person%40|person@/i);
  assert.match(copied.at(-1), /CyberBackgroundChecks opt-out packet/);
  const copiesBeforeClick = copied.length;
  await elements.goGhostScopeCopyButton.handlers.click();
  assert.equal(copied.length, copiesBeforeClick + 1);
  assert.match(copied.at(-1), /Name: Example Person/);

  vm.runInContext(`updateGhostAutomationState('${lastId}', {status: 'failed'})`, context);
  await elements.goGhostScopeSubmittedButton.handlers.click();
  assert.equal(closeFocusCount, 1, 'updating status should not move keyboard focus');
  assert.equal(vm.runInContext(`getGhostProgress()['${lastId}'].automation`, context), null);
  assert.equal(elements.ghostProgressCount.textContent, '0 / 18');
  const finalRow = elements.goGhostAutomationRows.innerHTML.match(
    /<button[^>]+data-ghost-scope="cyberbackgroundchecks"[\s\S]*?<\/button>/
  );
  assert.ok(finalRow, 'last broker should remain visible after progress changes');
  assert.match(finalRow[0], /Submitted/);

  await elements.goGhostScopeRemovedButton.handlers.click();
  assert.equal(elements.ghostProgressCount.textContent, '1 / 18');
  assert.match(elements.goGhostAutomationRows.innerHTML, /data-ghost-scope="cyberbackgroundchecks"[\s\S]*?Removed/);
  await elements.goGhostScopeResetButton.handlers.click();
  assert.equal(elements.ghostProgressCount.textContent, '0 / 18');
  assert.match(elements.goGhostAutomationRows.innerHTML, /data-ghost-scope="cyberbackgroundchecks"[\s\S]*?Pending/);

  await elements.goGhostScopeNoMatchButton.handlers.click();
  assert.equal(elements.ghostProgressCount.textContent, '0 / 18', 'no match is not a removal');
  assert.match(elements.goGhostAutomationRows.innerHTML, /data-ghost-scope="cyberbackgroundchecks"[\s\S]*?No match/);
  assert.equal(vm.runInContext("nextPendingGhostBroker().id", context), 'fastpeoplesearch');

  vm.runInContext(`ghostSaveProgress({
    '${lastId}': {submitted: true, removed: true, finishReason: 'No matching profile found.'}
  }); renderGoGhostAutomationScope(); renderGoGhostProgress();`, context);
  assert.equal(elements.ghostProgressCount.textContent, '0 / 18', 'legacy no-match is not a removal');
  assert.match(elements.goGhostAutomationRows.innerHTML, /data-ghost-scope="cyberbackgroundchecks"[\s\S]*?No match/);
  assert.equal(opened.some(url => url.includes('safescan_prefill')), false);

  assert.equal(sessionSaved.has('safeScanGoGhostV2:guest'), true);
  saved.set('safeScanGoGhostProfile', JSON.stringify({name: 'Legacy Person'}));
  elements.clearGhostDataButton.handlers.click();
  assert.equal(saved.has('safeScanGoGhostProfile'), true, 'account clear must not erase unowned legacy data');
  assert.equal(sessionSaved.has('safeScanGoGhostV2:guest'), false);
  elements.eraseGhostLegacyButton.handlers.click();
  assert.equal(saved.has('safeScanGoGhostProfile'), false);
  assert.equal(elements.goGhostWorkspace.hidden, true);
  assert.equal(elements.goGhostConsentModal.classList.contains('hidden'), false);
  assert.equal(elements.ghostFirstNameInput.value, '');
  assert.equal(elements.ghostProgressCount.textContent, '0 / 18');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
