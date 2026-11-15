const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('static/app-go-ghost.js', 'utf8');
const uiSource = fs.readFileSync('static/app-go-ghost-ui.js', 'utf8');
const stateSource = fs.readFileSync('static/go-ghost-state.js', 'utf8');
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

function page(accountId, local, session, {
  automation = false, accountName = '', accountEmail = '', legacyEraseBlocked = false
} = {}) {
  const ids = [
    'goGhostWorkspace', 'goGhostConsentModal', 'goGhostSessionNotice', 'goGhostLegacyNotice',
    'goGhostLegacyActions', 'eraseGhostLegacyButton',
    'startGoGhostButton', 'goGhostProfileForm', 'clearGhostDataButton', 'goGhostAutomationRows',
    'goGhostBrokerList', 'goGhostScopeModal', 'goGhostScopeTitle', 'goGhostScopePriority',
    'goGhostScopeDescription', 'goGhostScopeKeywords', 'goGhostScopeDetails',
    'goGhostScopeSearchButton', 'goGhostScopeOptOutButton', 'goGhostScopeCopyButton',
    'goGhostScopeNoMatchButton', 'goGhostScopeSubmittedButton', 'goGhostScopeRemovedButton',
    'goGhostScopeResetButton', 'goGhostScopeRecheckButton', 'goGhostScopeAbsentButton',
    'goGhostScopePresentButton', 'goGhostScopeBrandSelect', 'goGhostScopeBrandPicker',
    'goGhostScopeFinishButton', 'openNextGhostBrokerButton',
    'ghostProgressCount', 'ghostProgressBreakdown', 'ghostFirstNameInput', 'ghostMiddleNameInput', 'ghostLastNameInput',
    'ghostCityInput', 'ghostStateInput', 'ghostBirthYearInput', 'ghostAddressInput',
    'ghostPhoneInput', 'ghostEmailInput', 'ghostPreviousCitiesInput', 'ghostOtherNamesInput',
    'ghostProfileReviewNotice', 'ghostSavedProfileHint', 'ghostAccountNameHint',
    'goGhostDeviceNotice', 'ghostSubjectSelect',
    'addGhostFamilyButton', 'removeGhostSubjectButton', 'ghostFamilyAttestationLabel',
    'ghostFamilyAttestationInput'
  ];
  const elements = Object.fromEntries(ids.map(id => [id, element()]));
  elements.goGhostBrokerRegistry = element();
  elements.goGhostBrokerRegistry.textContent = fs.readFileSync('data/go_ghost/brokers.json', 'utf8');
  elements.goGhostWorkspace.hidden = true;
  elements.goGhostWorkspace.dataset.accountId = accountId;
  elements.goGhostWorkspace.dataset.accountName = accountName;
  elements.goGhostWorkspace.dataset.accountEmail = accountEmail;
  elements.goGhostWorkspace.dataset.browserAutomationAvailable = String(automation);
  elements.goGhostScopeModal.classList.add('hidden');
  const windowEvents = {};
  const opened = [];
  const copied = [];
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
    copyTextToClipboard: async value => { copied.push(value); return true; },
    escapeHtml: value => String(value ?? '').replace(/[&<>"]/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'
    })[char])
  });
  vm.runInContext(stateSource, context);
  vm.runInContext(source, context);
  vm.runInContext(uiSource, context);
  return {elements, windowEvents, opened, copied, messages, removalRequests, confirmQuestions, context,
    setSession: id => { signedInAs = id; }, setConfirmResult: result => { confirmResult = result; },
    allowLegacyErase: () => blockedDeletes.clear()};
}

function enterProfile(page, firstName, lastName, save = true) {
  const fields = {
    ghostFirstNameInput: firstName,
    ghostLastNameInput: lastName,
    ghostCityInput: 'Tampa',
    ghostStateInput: 'FL',
    ghostEmailInput: 'person@example.com'
  };
  for (const [id, value] of Object.entries(fields)) {
    page.elements[id].value = value;
    page.elements[id].events[id === 'ghostStateInput' ? 'change' : 'input']();
  }
  if (save) page.elements.goGhostProfileForm.events.submit({preventDefault() {}});
}

async function main() {
  const local = new Map([['safeScanGoGhostProfile', JSON.stringify({name: 'Legacy Secret'})]]);
  const a = page('account-A', local, new Map());
  assert.equal(a.elements.goGhostLegacyNotice.hidden, true);
  assert.equal(a.elements.goGhostLegacyActions.hidden, true);
  assert.equal(a.elements.ghostFirstNameInput.value, '', 'legacy profile must not be shown or imported');
  assert.equal(local.has('safeScanGoGhostProfile'), false, 'unowned legacy data is erased on page load');
  a.elements.startGoGhostButton.events.click();
  enterProfile(a, 'Alice', 'Person');
  vm.runInContext("setGhostManualStatus('fastpeoplesearch', 'removed')", a.context);
  assert.equal(a.elements.ghostProgressCount.textContent, '0 / 18', 'reporting gone is unverified');
  vm.runInContext("ghostApplyManualEvent('fastpeoplesearch', 'begin_recheck')", a.context);
  vm.runInContext("ghostApplyManualEvent('fastpeoplesearch', 'recheck_absent', {method: 'user_recheck'})", a.context);
  assert.equal(a.elements.ghostProgressCount.textContent, '1 / 18');
  const aKey = 'safeScanGoGhostV2:account:account-A';
  assert.ok(local.has(aKey));

  const b = page('account-B', local, new Map());
  b.elements.startGoGhostButton.events.click();
  assert.equal(b.elements.ghostFirstNameInput.value, '', 'B must not see A’s profile');
  assert.equal(b.elements.ghostProgressCount.textContent, '0 / 18', 'B must not see A’s progress');
  enterProfile(b, 'Bob', 'Person');
  assert.ok(local.has('safeScanGoGhostV2:account:account-B'));
  assert.equal(JSON.parse(local.get(aKey)).subjects[JSON.parse(local.get(aKey)).activeSubjectId].profile.name, 'Alice Person');

  a.setSession('account-B');
  const accountCheck = a.windowEvents.focus();
  assert.equal(a.elements.goGhostWorkspace.hidden, true, 'focus must hide A details before the server responds');
  await accountCheck;
  assert.equal(a.elements.goGhostWorkspace.hidden, true, 'stale A tab must lock after account switch');
  assert.equal(a.elements.ghostFirstNameInput.value, '');
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
  enterProfile(guest, 'Guest', 'Person');
  assert.ok(guestSession.has('safeScanGoGhostV2:guest'));
  assert.equal(local.has('safeScanGoGhostV2:guest'), false, 'guest data must be tab-only');
  page('account-A', local, guestSession);
  assert.equal(guestSession.has('safeScanGoGhostV2:guest'), false, 'sign-in must not merge guest data');

  const family = page('account-C', local, new Map());
  family.elements.startGoGhostButton.events.click();
  enterProfile(family, 'Self', 'Person');
  family.elements.addGhostFamilyButton.events.click();
  assert.equal(family.elements.goGhostWorkspace.hidden, true, 'new subject needs its own consent');
  family.elements.startGoGhostButton.events.click();
  assert.equal(family.elements.ghostFamilyAttestationLabel.hidden, false);
  enterProfile(family, 'Family', 'Person');
  vm.runInContext("openGoGhostScopeModal('fastpeoplesearch')", family.context);
  await family.elements.goGhostScopeSearchButton.events.click();
  assert.equal(family.opened.length, 0, 'family search requires attestation');
  family.elements.ghostFamilyAttestationInput.checked = true;
  family.elements.ghostFamilyAttestationInput.events.change();
  await family.elements.goGhostScopeSearchButton.events.click();
  assert.equal(family.opened.length, 1);
  family.elements.ghostFirstNameInput.value = 'Different';
  family.elements.ghostFirstNameInput.events.input();
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
  await family.elements.goGhostScopeSubmittedButton.events.click();
  assert.equal(vm.runInContext("getGhostProgress().intelius", family.context), undefined,
    'family cannot claim completion of PeopleConnect self-use workflow');
  vm.runInContext("setGhostManualStatus('fastpeoplesearch', 'submitted')", family.context);
  const familyState = JSON.parse(local.get('safeScanGoGhostV2:account:account-C'));
  assert.equal(Object.keys(familyState.subjects).length, 2);
  const selfId = Object.values(familyState.subjects).find(subject => subject.kind === 'self').id;
  family.elements.ghostSubjectSelect.value = selfId;
  family.elements.ghostSubjectSelect.events.change();
  assert.equal(family.elements.ghostFirstNameInput.value, 'Self');
  assert.equal(family.elements.ghostLastNameInput.value, 'Person');
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

  const prefill = page('account-F', local, new Map(), {
    accountName: 'Amy Lee', accountEmail: 'amy@example.com'
  });
  prefill.elements.startGoGhostButton.events.click();
  assert.equal(prefill.elements.ghostFirstNameInput.value, 'Amy');
  assert.equal(prefill.elements.ghostLastNameInput.value, 'Lee');
  assert.equal(prefill.elements.ghostEmailInput.value, 'amy@example.com');
  assert.equal(vm.runInContext('ghostProfileIsReviewed()', prefill.context), false,
    'account metadata must not become a reviewed broker identity');
  prefill.elements.addGhostFamilyButton.events.click();
  prefill.elements.startGoGhostButton.events.click();
  assert.equal(prefill.elements.ghostFirstNameInput.value, '', 'family profile starts without the account name');
  assert.equal(prefill.elements.ghostEmailInput.value, '', 'family profile starts without the account email');

  const ambiguous = page('account-G', local, new Map(), {
    accountName: 'Mary Ann Smith', accountEmail: 'mary@example.com'
  });
  ambiguous.elements.startGoGhostButton.events.click();
  assert.equal(ambiguous.elements.ghostFirstNameInput.value, '', 'compound account name needs review');
  assert.equal(ambiguous.elements.ghostLastNameInput.value, '');
  assert.match(ambiguous.elements.ghostAccountNameHint.textContent, /Mary Ann Smith/);

  const oldId = '11111111-1111-4111-8111-111111111111';
  const oldKey = 'safeScanGoGhostV2:account:account-H';
  const oldProfile = {
    name: 'Mary Ann Doe', location: 'Tampa, FL', email: 'old@example.com',
    address: '123 Legacy Avenue', identifier: '555-0100'
  };
  local.set(oldKey, JSON.stringify({version: 2, activeSubjectId: oldId, subjects: {
    [oldId]: {id: oldId, kind: 'self', profile: oldProfile, progress: {
      fastpeoplesearch: {removed: true, finishReason: 'No matching profile found.'},
      whitepages: {removed: true},
      spokeo: {state: 'client_recheck_absent', source: 'manual', updatedAt: '2026-11-15T00:00:00.000Z'},
      unknown: {removed: true}
    },
      consentAcceptedAt: '2026-11-10T00:00:00.000Z', familyAttestedAt: ''}
  }}));
  const older = page('account-H', local, new Map(), {accountName: 'Different Name'});
  assert.equal(vm.runInContext("getGhostProgress().fastpeoplesearch.state", older.context), 'not_found');
  assert.equal(vm.runInContext("getGhostProgress().whitepages.state", older.context), 'user_reported_removed');
  assert.equal(vm.runInContext("getGhostProgress().spokeo.state", older.context), 'not_started',
    'a stored absent flag without recheck provenance is downgraded');
  assert.equal(vm.runInContext("getGhostProgress().unknown", older.context), undefined);
  assert.equal(older.elements.ghostFirstNameInput.value, '', 'old scoped name must not be split by guessing');
  assert.equal(older.elements.ghostLastNameInput.value, '');
  assert.equal(older.elements.ghostCityInput.value, '', 'old scoped location must not be guessed');
  assert.equal(older.elements.ghostAddressInput.value, '123 Legacy Avenue');
  assert.equal(older.elements.ghostPhoneInput.value, '555-0100');
  assert.match(older.elements.ghostSavedProfileHint.textContent, /Mary Ann Doe.*Tampa, FL/);
  assert.equal(vm.runInContext('getGhostProfile().name', older.context), '');
  vm.runInContext("openGoGhostScopeModal('fastpeoplesearch')", older.context);
  await older.elements.goGhostScopeSearchButton.events.click();
  assert.equal(older.opened.length, 0, 'old unreviewed scoped profile cannot trigger a broker search');

  older.elements.ghostFirstNameInput.value = 'Mary Ann';
  older.elements.ghostFirstNameInput.events.input();
  older.elements.ghostLastNameInput.value = 'Doe';
  older.elements.ghostLastNameInput.events.input();
  older.elements.ghostCityInput.value = 'Tampa';
  older.elements.ghostCityInput.events.input();
  older.elements.ghostStateInput.value = 'FL';
  older.elements.ghostStateInput.events.change();
  older.elements.ghostMiddleNameInput.value = 'PrivateMiddle';
  older.elements.ghostMiddleNameInput.events.input();
  older.elements.ghostBirthYearInput.value = '1978';
  older.elements.ghostBirthYearInput.events.input();
  older.elements.ghostPreviousCitiesInput.value = 'PrivatePrevious';
  older.elements.ghostPreviousCitiesInput.events.input();
  older.elements.ghostOtherNamesInput.value = 'PrivateAlias';
  older.elements.ghostOtherNamesInput.events.input();
  older.elements.goGhostProfileForm.events.submit({preventDefault() {}});
  assert.equal(vm.runInContext('ghostProfileIsReviewed()', older.context), true);
  assert.equal(JSON.parse(local.get(oldKey)).subjects[oldId].profile.name, 'Mary Ann Doe');
  await older.elements.goGhostScopeSearchButton.events.click();
  assert.equal(older.opened.length, 1);
  assert.equal(older.opened[0], 'https://www.fastpeoplesearch.com/');
  assert.doesNotMatch(older.opened[0], /Private|123|555|1978|old%40|old@/i);
  await older.elements.goGhostScopeCopyButton.events.click();
  assert.match(older.copied.at(-1), /Name: Mary Ann Doe/);
  assert.doesNotMatch(older.copied.at(-1), /PrivateMiddle|PrivatePrevious|PrivateAlias|123 Legacy|555-0100|1978/);

  older.elements.ghostCityInput.value = 'Miami';
  older.elements.ghostCityInput.events.input();
  await older.elements.goGhostScopeSearchButton.events.click();
  assert.equal(older.opened.length, 1, 'editing a reviewed field requires saving again');
  older.elements.goGhostProfileForm.events.submit({preventDefault() {}});
  older.elements.ghostStateInput.value = 'OUTSIDE_US';
  older.elements.ghostStateInput.events.change();
  older.elements.ghostCityInput.value = 'Toronto';
  older.elements.ghostCityInput.events.input();
  older.elements.goGhostProfileForm.events.submit({preventDefault() {}});
  await older.elements.goGhostScopeSearchButton.events.click();
  assert.equal(older.opened.at(-1), 'https://www.fastpeoplesearch.com/optout',
    'outside U.S. search opens static broker instructions');

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
