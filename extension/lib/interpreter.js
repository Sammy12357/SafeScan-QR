/* Pure on-device recipe interpreter. There is deliberately no extension manifest or live recipe. */
const GoGhostInterpreter = (() => {
  const Recipe = typeof module !== "undefined" && module.exports
    ? require("./recipe.js") : globalThis.GoGhostRecipe;
  const Match = typeof module !== "undefined" && module.exports
    ? require("./match.js") : globalThis.GoGhostMatch;
  const {RecipeError} = Recipe;

  async function callDriver(driver, method, ...args) {
    try {
      if (typeof driver[method] !== "function") throw new Error("missing driver method");
      return await driver[method](...args);
    } catch (error) {
      if (error instanceof RecipeError) throw error;
      throw new RecipeError("driver_failure");
    }
  }

  async function assertHost(driver, domains) {
    const url = await callDriver(driver, "currentUrl");
    Recipe.checkedUrl(url, domains, true);
  }

  async function exactlyOne(driver, selector) {
    const matches = await callDriver(driver, "query", selector);
    if (!Array.isArray(matches) || matches.length !== 1) throw new RecipeError("layout_changed");
    return matches[0];
  }

  function formValue(profile, field) {
    const value = profile[field];
    if (!(typeof value === "string" || Number.isInteger(value))) throw new RecipeError("missing_field");
    const text = String(value).trim();
    if (!text || text.length > 256) throw new RecipeError("missing_field");
    return text;
  }

  async function runSteps(recipe, phase, driver, profile, options = {}) {
    Recipe.validateRecipe(recipe);
    if (!["search", "optOut"].includes(phase) || !driver || typeof driver !== "object"
        || !profile || typeof profile !== "object") throw new RecipeError("invalid_recipe");
    // A real driver must block off-host navigation before any request is sent.
    // The post-step URL check alone is insufficient to protect profile data.
    await callDriver(driver, "lockToHosts", [...recipe.domains]);
    const extracted = Object.create(null);
    let selectedListing = null;
    for (let index = 0; index < recipe[phase].length; index += 1) {
      const step = recipe[phase][index];
      if (step.op !== "goto") await assertHost(driver, recipe.domains);
      switch (step.op) {
        case "goto": {
          const target = Recipe.checkedUrl(step.url, recipe.domains, true);
          await callDriver(driver, "navigate", target);
          break;
        }
        case "fill": {
          const element = await exactlyOne(driver, step.selector);
          await callDriver(driver, "fill", element, formValue(profile, step.field));
          break;
        }
        case "select": {
          const element = await exactlyOne(driver, step.selector);
          await callDriver(driver, "select", element, step.optionText);
          break;
        }
        case "check": {
          const approved = Array.isArray(options.approvedCheckMeanings)
            && options.approvedCheckMeanings.includes(step.meaning);
          if (!approved || (step.meaning === "i_am_the_subject" && options.subject !== "self")) {
            throw new RecipeError("needs_human");
          }
          const element = await exactlyOne(driver, step.selector);
          await callDriver(driver, "check", element);
          break;
        }
        case "click": {
          const element = await exactlyOne(driver, step.selector);
          await callDriver(driver, "click", element);
          break;
        }
        case "waitFor": {
          const maxWaitMs = Number.isInteger(options.maxWaitMs)
            ? Math.max(1, Math.min(options.maxWaitMs, 10000)) : 5000;
          const matches = await callDriver(driver, "waitFor", step.selector, maxWaitMs);
          if (!Array.isArray(matches) || matches.length !== 1) throw new RecipeError("layout_changed");
          break;
        }
        case "expect": {
          const element = await exactlyOne(driver, step.selector);
          const actual = await callDriver(driver, "read", element, "text");
          if (typeof actual !== "string" || actual.trim() !== step.text) {
            throw new RecipeError("unexpected_result");
          }
          break;
        }
        case "captchaPause":
          return {status: "needs_human", reason: "captcha", nextStep: index + 1};
        case "pickListing": {
          const candidates = await callDriver(driver, "listCandidates", step.selector);
          if (!Array.isArray(candidates) || candidates.length > 50) throw new RecipeError("layout_changed");
          const noResults = await callDriver(driver, "query", step.noResultsSelector);
          if (!Array.isArray(noResults) || noResults.length > 1 || (candidates.length && noResults.length)) {
            throw new RecipeError("layout_changed");
          }
          if (!candidates.length) {
            if (noResults.length === 1) return {status: "not_found"};
            throw new RecipeError("layout_changed");
          }
          for (const candidate of candidates) {
            if (!candidate || typeof candidate !== "object") throw new RecipeError("layout_changed");
            if (candidate.url) Recipe.checkedUrl(candidate.url, recipe.domains);
          }
          const choice = Match.selectBest(profile, candidates, {year: options.year});
          if (choice.status !== "matched") return {status: "needs_review", reason: choice.reason};
          selectedListing = choice.candidate;
          break;
        }
        case "extract": {
          const element = await exactlyOne(driver, step.selector);
          const value = await callDriver(driver, "read", element, step.attribute);
          if (typeof value !== "string" || value.length > 2048) throw new RecipeError("unexpected_result");
          if (step.attribute === "href") Recipe.checkedUrl(value, recipe.domains);
          extracted[step.as] = value;
          break;
        }
      }
      await assertHost(driver, recipe.domains);
    }
    return {status: "completed", selectedListing, extracted};
  }

  return {runSteps};
})();

if (typeof module !== "undefined" && module.exports) module.exports = GoGhostInterpreter;
else globalThis.GoGhostInterpreter = GoGhostInterpreter;
