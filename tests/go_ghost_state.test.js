const assert = require('node:assert/strict');
const Ghost = require('../static/go-ghost-state.js');

const AT = '2026-11-15T00:00:00.000Z';
const BROKERS = ['intelius', 'ussearch', 'instantcheckmate', 'truthfinder'];

function event(type, extra = {}) {
  return {type, at: AT, source: 'manual', ...extra};
}

function testLegacyInterpretation() {
  assert.equal(Ghost.migrateLegacyEntry({removed: true, submitted: true, noMatch: true}).state, 'not_found');
  assert.equal(Ghost.migrateLegacyEntry({removed: true, finishReason: 'No matching profile found.'}).state, 'not_found');
  assert.equal(Ghost.migrateLegacyEntry({removed: true, submitted: true}).state, 'user_reported_removed');
  assert.equal(Ghost.migrateLegacyEntry({submitted: true}).state, 'submitted');
  assert.equal(Ghost.migrateLegacyEntry({}).state, 'not_started');
  assert.equal(Ghost.migrateLegacyEntry(null).state, 'not_started');

  const migrated = Ghost.migrateLegacyProgress({
    intelius: {removed: true, name: 'Private Person', address: '123 Private Street',
      updatedAt: AT, automation: {detail: 'person@example.test'}},
    ussearch: {removed: true, finishReason: 'No match', updatedAt: 'not-a-date'},
    ignored: {removed: true}
  }, BROKERS);
  assert.deepEqual(Object.keys(migrated), ['intelius', 'ussearch']);
  assert.deepEqual(migrated.intelius, {
    state: 'user_reported_removed', source: 'legacy_manual', updatedAt: AT
  });
  assert.deepEqual(migrated.ussearch, {
    state: 'not_found', source: 'legacy_manual', updatedAt: null
  });
  assert.doesNotMatch(JSON.stringify(migrated), /Private|person@|finishReason|automation/);
  assert.throws(() => Ghost.migrateLegacyProgress({}, []), /broker ID list/i);
}

function testManualAndVerificationPath() {
  const initial = Ghost.emptyEntry();
  const submitted = Ghost.transition(initial, event('mark_submitted'));
  const reported = Ghost.transition(submitted, event('report_removed'));
  assert.equal(reported.state, 'user_reported_removed');
  assert.equal('recheck' in reported, false);
  assert.throws(() => Ghost.transition(reported, event('recheck_absent', {method: 'user_recheck'})), /Cannot/);

  const verifying = Ghost.transition(reported, event('begin_recheck'));
  assert.throws(() => Ghost.transition(verifying, event('recheck_absent')), /recheck method/i);
  assert.throws(() => Ghost.transition(verifying, event('recheck_absent', {method: 'extension_recheck'})), /match the event source/i);
  const recheckedAbsent = Ghost.transition(verifying, event('recheck_absent', {method: 'user_recheck'}));
  assert.deepEqual(recheckedAbsent, {
    state: 'client_recheck_absent', source: 'manual', updatedAt: AT,
    recheck: {method: 'user_recheck', checkedAt: AT}
  });
  assert.equal(Ghost.transition(recheckedAbsent, event('reset')).state, 'not_started');
  assert.equal(Ghost.transition(recheckedAbsent, event('begin_recheck')).state, 'verifying',
    'a previously absent listing can be checked again later');

  const stillListed = Ghost.transition(verifying, event('recheck_present', {method: 'extension_recheck', source: 'extension'}));
  assert.equal(stillListed.state, 'still_listed');
  assert.equal(stillListed.recheck.method, 'extension_recheck');
  assert.equal(Ghost.transition(stillListed, event('mark_submitted')).state, 'submitted');
}

function testTransitionGraph() {
  const extras = {
    needs_human: {reason: 'captcha'},
    mark_failed: {code: 'layout_changed'},
    recheck_absent: {method: 'user_recheck'},
    recheck_present: {method: 'user_recheck'}
  };
  for (const state of Ghost.STATES) {
    for (const type of Ghost.EVENTS) {
      const action = event(type, extras[type]);
      if (type === 'reset') {
        assert.equal(Ghost.transition({state}, action).state, 'not_started');
        continue;
      }
      const allowed = Ghost.TRANSITIONS[type].from.includes(state);
      if (allowed) {
        const next = Ghost.transition({state}, action);
        assert.equal(next.state, Ghost.TRANSITIONS[type].to, `${state} -> ${type}`);
        if (next.state === 'client_recheck_absent') {
          assert.equal(type, 'recheck_absent', 'only an explicit absent recheck can record absence');
          assert.equal(state, 'verifying');
        }
      } else {
        assert.throws(() => Ghost.transition({state}, action), /Cannot/, `${state} -> ${type} must be refused`);
      }
    }
  }
  assert.throws(() => Ghost.transition(Ghost.emptyEntry(), event('verify_removed')), /Unknown/);
  assert.throws(() => Ghost.transition(Ghost.emptyEntry(), {...event('mark_submitted'), at: 'tomorrow'}), /ISO/);
  assert.throws(() => Ghost.transition(Ghost.emptyEntry(), {...event('mark_submitted'), source: 'server'}), /source/);
  assert.throws(() => Ghost.transition({state: 'nonsense'}, event('reset')), /Invalid current/);
  assert.throws(() => Ghost.transition({state: 'submitting'}, event('needs_human', {reason: 'marketing'})), /checkpoint/);
  assert.throws(() => Ghost.transition({state: 'scanning'}, event('mark_failed', {code: 'Private Person'})), /failure code/);
}

function testPerBrandIsolationAndCounts() {
  const legacy = Ghost.migrateLegacyProgress({
    intelius: {removed: true},
    ussearch: {removed: true, finishReason: 'No match'},
    truthfinder: {submitted: true}
  }, BROKERS);
  const before = JSON.stringify(legacy);
  let progress = Ghost.applyBrokerEvent(legacy, 'intelius', event('begin_recheck'), BROKERS);
  progress = Ghost.applyBrokerEvent(progress, 'intelius', event('recheck_absent', {method: 'user_recheck'}), BROKERS);
  assert.equal(progress.intelius.state, 'client_recheck_absent');
  assert.equal(progress.ussearch.state, 'not_found');
  assert.equal(progress.truthfinder.state, 'submitted');
  assert.equal(progress.instantcheckmate, undefined);
  assert.equal(JSON.stringify(legacy), before, 'the previous progress object remains unchanged');
  assert.throws(() => Ghost.applyBrokerEvent(progress, 'peopleconnect', event('reset'), BROKERS), /Unknown broker/);

  const withExtraData = {...progress, ussearch: {...progress.ussearch, address: '123 Private Street'}};
  const sanitized = Ghost.applyBrokerEvent(withExtraData, 'truthfinder', event('reset'), BROKERS);
  assert.doesNotMatch(JSON.stringify(sanitized), /Private Street/);

  assert.deepEqual(Ghost.summarize(progress, BROKERS), {
    total: 4, not_started: 1, not_found: 1,
    user_reported_removed: 0, client_recheck_absent: 1,
    in_progress: 1, failed: 0, skipped: 0
  });
  const forged = {
    intelius: {state: 'client_recheck_absent', source: 'manual', updatedAt: AT},
    ussearch: {state: 'still_listed', source: 'extension', updatedAt: AT,
      recheck: {method: 'user_recheck', checkedAt: AT}}
  };
  assert.equal(Ghost.summarize(forged, BROKERS).client_recheck_absent, 0,
    'a stored status without valid recheck provenance cannot count as rechecked absent');
  assert.equal(Ghost.summarize(forged, BROKERS).not_started, 4);
  const cleaned = Ghost.applyBrokerEvent(forged, 'truthfinder', event('mark_submitted'), BROKERS);
  assert.equal(cleaned.intelius.state, 'not_started');
  assert.equal(cleaned.ussearch.state, 'not_started');
  assert.throws(() => Ghost.summarize(progress, [...BROKERS, 'intelius']), /unique/);
}

testLegacyInterpretation();
testManualAndVerificationPath();
testTransitionGraph();
testPerBrandIsolationAndCounts();
console.log('Go Ghost state machine tests passed');
