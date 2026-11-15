const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('static/app-go-ghost.js', 'utf8');
const uiSource = fs.readFileSync('static/app-go-ghost-ui.js', 'utf8');
let uuid = 1;

function element() {
  const classes = new Set();
  return {
    dataset: {}, value: '', checked: false, disabled: false, hidden: false,
    innerHTML: '', textContent: '', events: {},
    classList: {
      add: name => classes.add(name), remove: name => classes.delete(name),
      contains: name => classes.has(name), toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name)
    },
    addEventListener(name, callback) { this.events[name] = callback; },
    querySelector() { return {focus() {}, scrollIntoView() {}}; },
    setAttribute() {}, removeAttribute() {}, focus() {}, scrollIntoView() {}
  };
}

function storage(map, blockedDeletes = new Set()) {
  return {
    get length() { return map.size; },
    key: index => [...map.keys()][index] ?? null,
    getItem: key => {
      if (['safeScanGoGhostProfile', 'safeScanGoGhostProgress', 'safeScanGoGhostConsent'].includes(key)) {
        throw new Error('Legacy values must never be read');
      }
      return map.get(key) ?? null;
    },
    setItem: (key, value) => map.set(key, value),
    removeItem: key => {
      if (blockedDeletes.has(key)) throw new Error('Browser storage removal failed');
      map.delete(key);
    }
  };
}

function page(accountId, local, session, {automation = false, legacyEraseBlocked = false} = {}) {
  const ids = [
    'goGhostWorkspace', 'goGhostConsentModal', 'goGhostSessionNotice', 'goGhostLegacyNotice',
    'goGhostLegacyActions', 'eraseGhostLegacyButton',
    'startGoGhostButton', 'goGhostProfileForm', 'clearGhostDataButton', 'goGhostAutomationRows',
    'goGhostBrokerList', 'goGhostScopeModal', 'goGhostScopeTitle', 'goGhostScopePriority',
    'goGhostScopeDescription', 'goGhostScopeKeywords', 'goGhostScopeDetails',
    'goGhostScopeSearchButton', 'goGhostScopeOptOutButton', 'goGhostScopeCopyButton',
    'goGhostScopeNoMatchButton', 'goGhostScopeSubmittedButton', 'goGhostScopeRemovedButton',
    'goGhostScopeResetButton', 'goGhostScopeFinishButton', 'openNextGhostBrokerButton',
    'ghostProgressCount', 'ghostNameInput', 'ghostLocationInput', 'ghostAddressInput',
    'ghostPhoneInput', 'ghostEmailInput', 'goGhostDeviceNotice', 'ghostSubjectSelect',
    'addGhostFamilyButton', 'removeGhostSubjectButton', 'ghostFamilyAttestationLabel',
    'ghostFamilyAttestationInput'
  ];
  const elements = Object.fromEntries(ids.map(id => [id, element()]));
  elements.goGhostBrokerRegistry = element();
  elements.goGhostBrokerRegistry.textContent = fs.readFileSync('data/go_ghost/brokers.json', 'utf8');
  elements.goGhostWorkspace.hidden = true;
  elements.goGhostWorkspace.dataset.accountId = accountId;
  elements.goGhostWorkspace.dataset.browserAutomationAvailable = String(automation);
  elements.goGhostScopeModal.classList.add('hidden');
  const windowEvents = {};
  const opened = [];
  const messages = [];
  const removalRequests = [];
  const confirmQuestions = [];
  let confirmResult = true;
  let signedInAs = accountId;
  const blockedDeletes = new Set(legacyEraseBlocked ? ['safeScanGoGhostProfile'] : []);
  const window = {
    localStorage: storage(local, blockedDeletes), sessionStorage: storage(session),
    crypto: {randomUUID: () => `00000000-0000-4000-8000-${String(uuid++).padStart(12, '0')}`},
    matchMedia: () => ({matches: false}),
    confirm: question => { confirmQuestions.push(question); return confirmResult; },
    addEventListener(name, callback) { windowEvents[name] = callback; },
    open(url) { opened.push(url); return {opener: null}; }
  };
  const document = {
    getElementById: id => elements[id] || null,
    body: {classList: element().classList},
    querySelectorAll: () => [],
    addEventListener() {}
  };
  const context = vm.createContext({
    window, document, URL, AbortController,
    fetch: async url => {
      if (url.startsWith('/api/go-ghost/removals/')) {
        removalRequests.push(url);
        return {status: 503, ok: false, json: async () => ({error: 'Unavailable'})};
      }
      return signedInAs
        ? {status: 200, ok: true, json: async () => ({user: {id: signedInAs}})}
        : {status: 401, ok: false};
    },
    isMobileDevice: () => false,
    showCopyToast: message => messages.push(message),
    copyTextToClipboard: async () => true,
    escapeHtml: value => String(value ?? '').replace(/[&<>"]/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'
    })[char])
  });
  vm.runInContext(source, context);
  vm.runInContext(uiSource, context);
  return {elements, windowEvents, opened, messages, removalRequests, confirmQuestions, context,
    setSession: id => { signedInAs = id; }, setConfirmResult: result => { confirmResult = result; },
    allowLegacyErase: () => blockedDeletes.clear()};
}

async function main() {
  const local = new Map([['safeScanGoGhostProfile', JSON.stringify({name: 'Legacy Secret'})]]);
  const a = page('account-A', local, new Map());
  assert.equal(a.elements.goGhostLegacyNotice.hidden, true);
  assert.equal(a.elements.goGhostLegacyActions.hidden, true);
  assert.equal(a.elements.ghostNameInput.value, '', 'legacy profile must not be shown or imported');
  assert.equal(local.has('safeScanGoGhostProfile'), false, 'unowned legacy data is erased on page load');
  a.elements.startGoGhostButton.events.click();
  a.elements.ghostNameInput.value = 'Alice Person';
  a.elements.ghostNameInput.events.input();
  vm.runInContext("setGhostManualStatus('fastpeoplesearch', 'removed')", a.context);
  assert.equal(a.elements.ghostProgressCount.textContent, '1 / 18');
  const aKey = 'safeScanGoGhostV2:account:account-A';
  assert.ok(local.has(aKey));

  const b = page('account-B', local, new Map());
  b.elements.startGoGhostButton.events.click();
  assert.equal(b.elements.ghostNameInput.value, '', 'B must not see A’s profile');
  assert.equal(b.elements.ghostProgressCount.textContent, '0 / 18', 'B must not see A’s progress');
  b.elements.ghostNameInput.value = 'Bob Person';
  b.elements.ghostNameInput.events.input();
  assert.ok(local.has('safeScanGoGhostV2:account:account-B'));
  assert.equal(JSON.parse(local.get(aKey)).subjects[JSON.parse(local.get(aKey)).activeSubjectId].profile.name, 'Alice Person');

  a.setSession('account-B');
  const accountCheck = a.windowEvents.focus();
  assert.equal(a.elements.goGhostWorkspace.hidden, true, 'focus must hide A details before the server responds');
  await accountCheck;
  assert.equal(a.elements.goGhostWorkspace.hidden, true, 'stale A tab must lock after account switch');
  assert.equal(a.elements.ghostNameInput.value, '');
  assert.equal(a.elements.goGhostSessionNotice.hidden, false);
  assert.equal(vm.runInContext('goGhostState', a.context), null, 'old subject state must leave page memory');
  assert.equal(a.elements.ghostSubjectSelect.innerHTML, '', 'old subject names must leave the DOM');
  assert.equal(a.elements.goGhostScopeKeywords.innerHTML, '', 'old profile values must leave hidden modal markup');
  assert.equal(vm.runInContext('getGhostProfile().name', a.context), '');
  const beforeStaleWrite = local.get(aKey);
  vm.runInContext("setGhostManualStatus('whitepages', 'submitted')", a.context);
  assert.equal(local.get(aKey), beforeStaleWrite, 'locked tab cannot write an old account’s progress');

  const guestSession = new Map();
  const guest = page('', local, guestSession);
  guest.elements.startGoGhostButton.events.click();
  guest.elements.ghostNameInput.value = 'Guest Person';
  guest.elements.ghostNameInput.events.input();
  assert.ok(guestSession.has('safeScanGoGhostV2:guest'));
  assert.equal(local.has('safeScanGoGhostV2:guest'), false, 'guest data must be tab-only');
  page('account-A', local, guestSession);
  assert.equal(guestSession.has('safeScanGoGhostV2:guest'), false, 'sign-in must not merge guest data');

  const family = page('account-C', local, new Map());
  family.elements.startGoGhostButton.events.click();
  family.elements.ghostNameInput.value = 'Self Person';
  family.elements.ghostNameInput.events.input();
  family.elements.addGhostFamilyButton.events.click();
  assert.equal(family.elements.goGhostWorkspace.hidden, true, 'new subject needs its own consent');
  family.elements.startGoGhostButton.events.click();
  assert.equal(family.elements.ghostFamilyAttestationLabel.hidden, false);
  family.elements.ghostNameInput.value = 'Family Person';
  family.elements.ghostNameInput.events.input();
  vm.runInContext("openGoGhostScopeModal('fastpeoplesearch')", family.context);
  await family.elements.goGhostScopeSearchButton.events.click();
  assert.equal(family.opened.length, 0, 'family search requires attestation');
  family.elements.ghostFamilyAttestationInput.checked = true;
  family.elements.ghostFamilyAttestationInput.events.change();
  await family.elements.goGhostScopeSearchButton.events.click();
  assert.equal(family.opened.length, 1);
  family.elements.ghostNameInput.value = 'Different Family Person';
  family.elements.ghostNameInput.events.input();
  await family.elements.goGhostScopeSearchButton.events.click();
  assert.equal(family.opened.length, 1, 'changing family identity revokes the current attestation');
  family.elements.ghostFamilyAttestationInput.checked = true;
  family.elements.ghostFamilyAttestationInput.events.change();
  assert.equal(vm.runInContext("ghostCanAct({id: 'new-peopleconnect-brand', group: 'peopleconnect'})", family.context), false,
    'a future PeopleConnect brand must inherit the self-use restriction from registry metadata');
  vm.runInContext("openGoGhostScopeModal('intelius')", family.context);
  await family.elements.goGhostScopeOptOutButton.events.click();
  assert.equal(family.opened.length, 1, 'self-only broker must not open for family request');
  assert.match(family.messages.at(-1), /requires the person/);
  vm.runInContext("setGhostManualStatus('fastpeoplesearch', 'submitted')", family.context);
  const familyState = JSON.parse(local.get('safeScanGoGhostV2:account:account-C'));
  assert.equal(Object.keys(familyState.subjects).length, 2);
  const selfId = Object.values(familyState.subjects).find(subject => subject.kind === 'self').id;
  family.elements.ghostSubjectSelect.value = selfId;
  family.elements.ghostSubjectSelect.events.change();
  assert.equal(family.elements.ghostNameInput.value, 'Self Person');
  assert.equal(family.elements.ghostProgressCount.textContent, '0 / 18', 'family progress must not count for self');

  const beforeAccountClear = local.get('safeScanGoGhostV2:account:account-C');
  family.setConfirmResult(false);
  family.elements.clearGhostDataButton.events.click();
  assert.equal(local.get('safeScanGoGhostV2:account:account-C'), beforeAccountClear,
    'cancelling all-people account clear must preserve data');
  assert.match(family.confirmQuestions.at(-1), /all people in this account/);
  family.setConfirmResult(true);
  family.elements.clearGhostDataButton.events.click();
  assert.equal(local.has('safeScanGoGhostV2:account:account-C'), false);
  assert.equal(local.has('safeScanGoGhostProfile'), false, 'old unowned details remain erased');

  const oldLocal = new Map([['safeScanGoGhostProfile', JSON.stringify({name: 'Do not import'})]]);
  page('account-D', oldLocal, new Map());
  assert.equal(oldLocal.has('safeScanGoGhostProfile'), false, 'old data is erased without importing it');

  const blockedLocal = new Map([['safeScanGoGhostProfile', 'unowned details']]);
  const blocked = page('account-F', blockedLocal, new Map(), {legacyEraseBlocked: true});
  assert.equal(blockedLocal.has('safeScanGoGhostProfile'), true);
  assert.equal(blocked.elements.goGhostLegacyNotice.hidden, false, 'failure must be visible');
  assert.equal(blocked.elements.goGhostLegacyActions.hidden, false, 'failure offers retry');
  blocked.allowLegacyErase();
  blocked.elements.eraseGhostLegacyButton.events.click();
  assert.equal(blockedLocal.has('safeScanGoGhostProfile'), false);
  assert.equal(blocked.elements.goGhostLegacyNotice.hidden, true);

  const automation = page('account-E', local, new Map(), {automation: true});
  automation.elements.startGoGhostButton.events.click();
  automation.elements.addGhostFamilyButton.events.click();
  automation.elements.startGoGhostButton.events.click();
  automation.elements.ghostFamilyAttestationInput.checked = true;
  automation.elements.ghostFamilyAttestationInput.events.change();
  await vm.runInContext('startGhostAssistedQueue()', automation.context);
  assert.equal(automation.removalRequests.length, 0, 'family queue must not send profile to server');
  assert.match(automation.messages.at(-1), /unavailable for family/);
  const stopped = vm.runInContext(`(() => {
    const controller = new AbortController();
    goGhostAutomationControllers.set('fastpeoplesearch', controller);
    lockGhostWorkspace();
    return {aborted: controller.signal.aborted, stopped: ghostQueueStopRequested};
  })()`, automation.context);
  assert.equal(stopped.aborted, true, 'account lock must cancel in-flight broker work');
  assert.equal(stopped.stopped, true);
}

main().catch(error => { console.error(error); process.exitCode = 1; });
