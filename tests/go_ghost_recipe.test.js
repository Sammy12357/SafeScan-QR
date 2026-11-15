const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const Recipe = require('../extension/lib/recipe.js');
const Interpreter = require('../extension/lib/interpreter.js');
const Match = require('../extension/lib/match.js');

const fixtureDir = path.join(__dirname, 'go_ghost_fixtures', 'fictional');
const fixture = (name) => fs.readFileSync(path.join(fixtureDir, name), 'utf8');
const recipe = JSON.parse(fixture('recipe.json'));
const schema = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'extension', 'recipes', 'schema.json')));
const profile = {
  firstName: 'Jane', lastName: 'Doe', middleName: 'A', city: 'Saratoga', state: 'NY',
  email: 'jane@example.test', birthYear: 1986, streetAddress: '12 Test Lane',
  phone: '212-555-1234'
};
const clearMatch = {
  name: 'Jane A Doe Jr', age: 40, city: 'Saratoga', state: 'NY',
  url: 'https://broker.example.test/record/1'
};

class FixtureDriver {
  constructor({searchHtml = fixture('search.html'), candidates = [clearMatch], resultHtml = fixture('results.html')} = {}) {
    this.pages = {
      '/search': searchHtml,
      '/remove': fixture('optout_step1.html'),
      '/results': resultHtml,
      '/done': '<p id="success">Request received</p>'
    };
    this.candidates = candidates;
    this.url = 'about:blank';
    this.values = [];
    this.checked = [];
    this.locked = false;
  }
  lockToHosts(domains) { this.domains = domains; this.locked = true; }
  currentUrl() { return this.url; }
  navigate(url) {
    assert(this.locked, 'the driver must lock hosts before navigation');
    const parsed = new URL(url);
    assert(this.domains.includes(parsed.hostname), 'the driver must block a foreign host before network access');
    this.url = url;
  }
  get html() { return this.pages[new URL(this.url).pathname] || ''; }
  query(selector) {
    if (!selector.startsWith('#')) return [];
    const id = selector.slice(1);
    const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const matches = [...this.html.matchAll(new RegExp(`\\bid=["']${escaped}["']`, 'g'))];
    return matches.map(() => ({selector}));
  }
  fill(element, value) { this.values.push([element.selector, value]); }
  select(element, value) { this.values.push([element.selector, value]); }
  check(element) { this.checked.push(element.selector); }
  click(element) {
    if (element.selector === '#search') this.url = 'https://broker.example.test/results';
    if (element.selector === '#submit') this.url = 'https://broker.example.test/done';
  }
  waitFor(selector) { return this.query(selector); }
  read(element) { return element.selector === '#success' ? 'Request received' : ''; }
  listCandidates(selector) { assert.equal(selector, '.card'); return this.candidates; }
}

function copy(value) { return structuredClone(value); }

function testRecipeValidation() {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.additionalProperties, false);
  assert.equal(Recipe.validateRecipe(recipe), recipe);
  const badField = copy(recipe);
  badField.search[1].field = 'socialSecurityNumber';
  assert.throws(() => Recipe.validateRecipe(badField), {code: 'invalid_recipe'});
  const extraInstruction = copy(recipe);
  extraInstruction.optOut[1].script = 'window.location';
  assert.throws(() => Recipe.validateRecipe(extraInstruction), {code: 'invalid_recipe'});
  const badCheck = copy(recipe);
  badCheck.optOut[2].meaning = 'marketing_consent';
  assert.throws(() => Recipe.validateRecipe(badCheck), {code: 'invalid_recipe'});
  const profileUrl = copy(recipe);
  profileUrl.search[0].url = 'https://broker.example.test/search?name={firstName}';
  assert.throws(() => Recipe.validateRecipe(profileUrl), {code: 'off_domain'});
  const queryUrl = copy(recipe);
  queryUrl.search[0].url = 'https://broker.example.test/search?fixed=true';
  assert.throws(() => Recipe.validateRecipe(queryUrl), {code: 'off_domain'});
  const foreignUrl = copy(recipe);
  foreignUrl.search[0].url = 'https://broker.example.test.evil.test/search';
  assert.throws(() => Recipe.validateRecipe(foreignUrl), {code: 'off_domain'});
  const insecure = copy(recipe);
  insecure.search[0].url = 'http://broker.example.test/search';
  assert.throws(() => Recipe.validateRecipe(insecure), {code: 'off_domain'});
  const remoteScript = copy(recipe);
  remoteScript.search.push({op: 'eval', code: 'bad'});
  assert.throws(() => Recipe.validateRecipe(remoteScript), {code: 'invalid_recipe'});
}

function testPlainScriptLoading() {
  const context = vm.createContext({URL});
  for (const name of ['recipe.js', 'match.js', 'interpreter.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'extension', 'lib', name), 'utf8'), context);
  }
  assert.equal(typeof context.GoGhostRecipe.validateRecipe, 'function');
  assert.equal(typeof context.GoGhostMatch.selectBest, 'function');
  assert.equal(typeof context.GoGhostInterpreter.runSteps, 'function');
  context.GoGhostRecipe.validateRecipe(recipe);
}

function testMatching() {
  assert.equal(Match.scoreCandidate(profile, clearMatch, {year: 2026}).score, 8);
  assert.equal(Match.selectBest(profile, [clearMatch], {year: 2026}).status, 'matched');
  assert.equal(Match.selectBest(profile, [clearMatch, {...clearMatch, url: 'https://broker.example.test/record/2'}], {year: 2026}).status, 'needs_review');
  const wrongAge = {...clearMatch, age: 25};
  assert.equal(Match.selectBest(profile, [wrongAge], {year: 2026}).status, 'needs_review');
  assert.equal(Match.selectBest({...profile, middleName: 'Anne'}, [{...clearMatch, name: 'Jane Abigail Doe'}],
    {year: 2026}).status, 'needs_review');
  assert.equal(Match.selectBest(profile, [{...clearMatch, name: 'Janet Doe'}], {year: 2026}).status, 'needs_review');
  assert.equal(Match.selectBest({firstName: 'Sam', lastName: 'Doe', city: 'Saratoga', state: 'NY'},
    [{...clearMatch, name: 'Samuel Doe'}], {year: 2026}).status, 'needs_review');
  assert.equal(Match.selectBest({firstName: 'Sam', lastName: 'Doe', city: 'Saratoga', state: 'NY',
    birthYear: 1986, aliases: ['Samuel Doe']}, [{...clearMatch, name: 'Samuel Doe'}], {year: 2026}).status, 'matched');
  assert.equal(Match.scoreCandidate({firstName: 'Anne-Marie', lastName: 'Smith', city: 'Saratoga', state: 'NY'},
    {name: 'Anne Marie Smith III', city: 'Saratoga', state: 'NY'}).eligible, true);
  assert.equal(Match.scoreCandidate(profile, {...clearMatch, city: 'East Saratoga'}).reasons.includes('current_location'), false);
  assert.throws(() => Match.selectBest(profile, Array(51).fill(clearMatch)), /at most 50/);
}

async function testInterpreter() {
  let driver = new FixtureDriver();
  const search = await Interpreter.runSteps(recipe, 'search', driver, profile, {year: 2026});
  assert.equal(search.status, 'completed');
  assert.equal(search.selectedListing.url, clearMatch.url);
  assert.deepEqual(driver.values, [['#first', 'Jane'], ['#last', 'Doe']]);

  driver = new FixtureDriver({candidates: [], resultHtml: fixture('no_results.html')});
  assert.deepEqual(await Interpreter.runSteps(recipe, 'search', driver, profile), {status: 'not_found'});

  driver = new FixtureDriver({searchHtml: fixture('changed_layout.html')});
  await assert.rejects(Interpreter.runSteps(recipe, 'search', driver, profile), {code: 'layout_changed'});
  driver = new FixtureDriver({searchHtml: fixture('ambiguous_layout.html')});
  await assert.rejects(Interpreter.runSteps(recipe, 'search', driver, profile), {code: 'layout_changed'});

  driver = new FixtureDriver({candidates: [clearMatch, {...clearMatch, url: 'https://broker.example.test/record/2'}]});
  assert.deepEqual(await Interpreter.runSteps(recipe, 'search', driver, profile, {year: 2026}),
    {status: 'needs_review', reason: 'ambiguous'});

  driver = new FixtureDriver();
  await assert.rejects(Interpreter.runSteps(recipe, 'optOut', driver, profile,
    {subject: 'family', approvedCheckMeanings: ['i_am_the_subject']}), {code: 'needs_human'});
  assert.deepEqual(driver.checked, []);
  driver = new FixtureDriver();
  await assert.rejects(Interpreter.runSteps(recipe, 'optOut', driver, profile,
    {subject: 'self'}), {code: 'needs_human'});
  driver = new FixtureDriver();
  assert.deepEqual(await Interpreter.runSteps(recipe, 'optOut', driver, profile,
    {subject: 'self', approvedCheckMeanings: ['i_am_the_subject']}),
    {status: 'needs_human', reason: 'captcha', nextStep: 4});
  assert.deepEqual(driver.checked, ['#subject']);

  const noCaptcha = copy(recipe);
  noCaptcha.optOut.splice(3, 1);
  driver = new FixtureDriver();
  assert.equal((await Interpreter.runSteps(noCaptcha, 'optOut', driver, profile,
    {subject: 'self', approvedCheckMeanings: ['i_am_the_subject']})).status, 'completed');

  driver = new FixtureDriver();
  driver.click = () => { driver.url = 'https://foreign.example.test/'; };
  await assert.rejects(Interpreter.runSteps(recipe, 'search', driver, profile), {code: 'off_domain'});

  driver = new FixtureDriver();
  driver.click = () => { driver.url = 'https://broker.example.test/results?first=Jane'; };
  await assert.rejects(Interpreter.runSteps(recipe, 'search', driver, profile), {code: 'off_domain'});

  driver = new FixtureDriver();
  driver.navigate = () => { throw new Error('network failure with private data'); };
  await assert.rejects(Interpreter.runSteps(recipe, 'search', driver, profile), {code: 'driver_failure', message: 'driver_failure'});
}

testRecipeValidation();
testPlainScriptLoading();
testMatching();
testInterpreter().then(() => console.log('Go Ghost offline recipe tests passed'));
