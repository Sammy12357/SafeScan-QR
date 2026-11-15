/* Runtime checks for locally bundled, reviewed recipe data. This file has no network entry point. */
const GoGhostRecipe = (() => {
  const PROFILE_FIELDS = new Set([
    "firstName", "lastName", "middleName", "city", "state", "email",
    "birthYear", "streetAddress", "phone"
  ]);
  const CHECK_MEANINGS = new Set(["terms_of_removal", "i_am_the_subject"]);
  const STEP_KEYS = Object.freeze({
    goto: ["op", "url"],
    fill: ["op", "selector", "field"],
    select: ["op", "selector", "optionText"],
    check: ["op", "selector", "meaning"],
    click: ["op", "selector"],
    waitFor: ["op", "selector"],
    expect: ["op", "selector", "text"],
    captchaPause: ["op"],
    pickListing: ["op", "selector", "noResultsSelector"],
    extract: ["op", "selector", "as", "attribute"]
  });

  class RecipeError extends Error {
    constructor(code) {
      super(code);
      this.name = "RecipeError";
      this.code = code;
    }
  }

  function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function exactKeys(value, required) {
    if (!isRecord(value)) throw new RecipeError("invalid_recipe");
    const actual = Object.keys(value).sort();
    if (actual.length !== required.length || actual.some((key, i) => key !== [...required].sort()[i])) {
      throw new RecipeError("invalid_recipe");
    }
  }

  function boundedString(value, max) {
    return typeof value === "string" && value.length > 0 && value.length <= max;
  }

  function validSelector(value) {
    return boundedString(value, 256) && !/[{}]/.test(value);
  }

  function validDomain(domain) {
    return typeof domain === "string" && domain.length <= 253
      && /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(domain)
      && !/^[0-9]+(?:\.[0-9]+){3}$/.test(domain)
      && domain.split(".").every((part) => part.length <= 63);
  }

  function checkedUrl(raw, domains, fixed = false) {
    if (!boundedString(raw, 2048) || /[{}]/.test(raw) || !raw.startsWith("https://")) {
      throw new RecipeError("off_domain");
    }
    let url;
    try { url = new URL(raw); } catch { throw new RecipeError("off_domain"); }
    if (url.protocol !== "https:" || url.username || url.password || url.port
        || !domains.includes(url.hostname) || url.hash
        || (fixed && (raw.includes("?") || raw.includes("#")
          || !/^https:\/\/[^/?#]+\//.test(raw)))) {
      throw new RecipeError("off_domain");
    }
    return url.href;
  }

  function validateStep(step, domains) {
    if (!isRecord(step) || !Object.hasOwn(STEP_KEYS, step.op)) throw new RecipeError("invalid_recipe");
    exactKeys(step, STEP_KEYS[step.op]);
    if (Object.hasOwn(step, "selector") && !validSelector(step.selector)) throw new RecipeError("invalid_recipe");
    switch (step.op) {
      case "goto": checkedUrl(step.url, domains, true); break;
      case "fill":
        if (!PROFILE_FIELDS.has(step.field)) throw new RecipeError("invalid_recipe");
        break;
      case "select":
        if (!boundedString(step.optionText, 120)) throw new RecipeError("invalid_recipe");
        break;
      case "check":
        if (!CHECK_MEANINGS.has(step.meaning)) throw new RecipeError("invalid_recipe");
        break;
      case "expect":
        if (!boundedString(step.text, 256)) throw new RecipeError("invalid_recipe");
        break;
      case "pickListing":
        if (!validSelector(step.noResultsSelector)) throw new RecipeError("invalid_recipe");
        break;
      case "extract":
        if (!/^[a-z][a-zA-Z0-9]{0,39}$/.test(step.as)
            || !["text", "href"].includes(step.attribute)) throw new RecipeError("invalid_recipe");
        break;
    }
  }

  function validateRecipe(recipe) {
    exactKeys(recipe, ["schemaVersion", "id", "group", "domains", "search", "optOut"]);
    if (recipe.schemaVersion !== 1 || !/^[a-z][a-z0-9_-]{1,63}$/.test(recipe.id)
        || !/^[a-z][a-z0-9_-]{1,63}$/.test(recipe.group)) throw new RecipeError("invalid_recipe");
    if (!Array.isArray(recipe.domains) || !recipe.domains.length || recipe.domains.length > 8
        || !recipe.domains.every(validDomain)
        || new Set(recipe.domains).size !== recipe.domains.length) throw new RecipeError("invalid_recipe");
    for (const steps of [recipe.search, recipe.optOut]) {
      if (!Array.isArray(steps) || !steps.length || steps.length > 64) throw new RecipeError("invalid_recipe");
      for (const step of steps) validateStep(step, recipe.domains);
    }
    return recipe;
  }

  return {RecipeError, checkedUrl, validateRecipe};
})();

if (typeof module !== "undefined" && module.exports) module.exports = GoGhostRecipe;
else globalThis.GoGhostRecipe = GoGhostRecipe;
