/* Local-only listing match. No broker network access or profile serialization. */
const GoGhostMatch = (() => {
  function words(value) {
    if (typeof value !== "string") return [];
    return value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
      .toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/).filter(Boolean);
  }

  function nameWords(value) {
    const parts = words(value);
    if (["jr", "sr", "ii", "iii", "iv"].includes(parts.at(-1))) parts.pop();
    return parts;
  }

  function equalsParts(left, right) {
    return left.length === right.length && left.every((part, index) => part === right[index]);
  }

  function nameMatch(profile, candidate) {
    const actual = nameWords(candidate.name);
    const first = nameWords(profile.firstName);
    const last = nameWords(profile.lastName);
    if (!actual.length || !first.length || !last.length) return {matches: false, middle: []};
    const aliases = Array.isArray(profile.aliases) ? profile.aliases : [];
    if (aliases.some((alias) => equalsParts(nameWords(alias), actual))) {
      return {matches: true, middle: []};
    }
    if (actual.length < first.length + last.length) return {matches: false, middle: []};
    if (!equalsParts(actual.slice(0, first.length), first)
        || !equalsParts(actual.slice(-last.length), last)) {
      return {matches: false, middle: []};
    }
    return {matches: true, middle: actual.slice(first.length, -last.length)};
  }

  function sameLocation(left, right) {
    const city = words(left?.city);
    const state = words(left?.state);
    return city.length > 0 && state.length > 0
      && equalsParts(city, words(right?.city))
      && equalsParts(state, words(right?.state));
  }

  function candidateLocations(candidate) {
    const locations = Array.isArray(candidate.locations) ? candidate.locations : [];
    if (typeof candidate.city === "string" && typeof candidate.state === "string") {
      return [{city: candidate.city, state: candidate.state}, ...locations];
    }
    return locations;
  }

  function matchingPhone(profile, candidate) {
    const profileDigits = String(profile.phone || "").replace(/\D/g, "");
    const candidateDigits = String(candidate.phone || "").replace(/\D/g, "");
    return profileDigits.length >= 7 && candidateDigits.length >= 7
      && profileDigits.slice(-7) === candidateDigits.slice(-7);
  }

  function scoreCandidate(profile, candidate, options = {}) {
    if (!profile || typeof profile !== "object" || !candidate || typeof candidate !== "object") {
      return {eligible: false, score: -Infinity, reasons: []};
    }
    const name = nameMatch(profile, candidate);
    if (!name.matches) return {eligible: false, score: -Infinity, reasons: []};
    const reasons = ["name"];
    let score = 0;
    const middle = nameWords(profile.middleName);
    const middleMatches = middle.length && name.middle.length
      && (equalsParts(name.middle, middle)
        || (middle.length === 1 && name.middle.length === 1
          && (middle[0].length === 1 || name.middle[0].length === 1)
          && name.middle[0][0] === middle[0][0]));
    if (middle.length && name.middle.length && !middleMatches) {
      return {eligible: false, score: -Infinity, reasons: ["middle_conflict"]};
    }
    if (middleMatches) {
      score += 2;
      reasons.push("middle_name");
    }
    const locations = candidateLocations(candidate);
    if (locations.some((location) => sameLocation(profile, location))) {
      score += 3;
      reasons.push("current_location");
    }
    const previous = Array.isArray(profile.previousCities) ? profile.previousCities : [];
    if (previous.some((prior) => locations.some((location) => sameLocation(prior, location)))) {
      score += 2;
      reasons.push("previous_location");
    }
    const year = Number.isInteger(options.year) ? options.year : new Date().getUTCFullYear();
    const birthYear = profile.birthYear === null || profile.birthYear === undefined || profile.birthYear === ""
      ? NaN : Number(profile.birthYear);
    const age = candidate.age === null || candidate.age === undefined || candidate.age === ""
      ? NaN : Number(candidate.age);
    if (Number.isInteger(birthYear) && birthYear >= 1900 && birthYear <= year
        && Number.isInteger(age) && age >= 0 && age <= 125) {
      const difference = Math.abs((year - birthYear) - age);
      if (difference <= 1) {
        score += 3;
        reasons.push("age");
      } else if (difference > 2) {
        score -= 6;
        reasons.push("age_conflict");
      }
    }
    const street = words(profile.streetAddress);
    const candidateStreet = words(candidate.streetAddress);
    if ((street.length >= 2 && equalsParts(street, candidateStreet)) || matchingPhone(profile, candidate)) {
      score += 4;
      reasons.push("address_or_phone");
    }
    return {eligible: true, score, reasons};
  }

  function selectBest(profile, candidates, options = {}) {
    if (!Array.isArray(candidates) || candidates.length > 50) {
      throw new TypeError("Expected at most 50 listing candidates");
    }
    const ranked = candidates.map((candidate, index) => ({
      index, candidate, ...scoreCandidate(profile, candidate, options)
    })).filter((entry) => entry.eligible).sort((a, b) => b.score - a.score);
    if (!ranked.length) return {status: "needs_review", reason: "no_name_match"};
    const lead = ranked[0];
    const second = ranked[1];
    if (lead.score < 6 || (second && lead.score - second.score < 3)) {
      return {status: "needs_review", reason: "ambiguous"};
    }
    return {status: "matched", index: lead.index, candidate: lead.candidate,
      score: lead.score, reasons: lead.reasons};
  }

  return {scoreCandidate, selectBest};
})();

if (typeof module !== "undefined" && module.exports) module.exports = GoGhostMatch;
else globalThis.GoGhostMatch = GoGhostMatch;
