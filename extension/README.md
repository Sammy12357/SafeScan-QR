# Go Ghost extension groundwork

This directory is **not an installable extension**. It has no manifest, content
script, host permissions, or live broker recipes. `recipes/schema.json` and the
plain JavaScript modules are an offline foundation for a future reviewed release.
The only recipe fixture uses the fictional `broker.example.test` host under
`tests/go_ghost_fixtures/` and is never loaded by the website.

The interpreter accepts only fixed HTTPS navigation URLs on an exact host
allowlist. It does not expand profile values into URLs. `fill` reads a named
profile field and sends it only to the caller's page driver. Every selector must
match exactly one element; an ambiguous or changed layout stops the run. A
`check` step requires an explicit approved meaning, and an `i_am_the_subject`
attestation is refused for family profiles. `captchaPause` yields control to a
person; it does not inspect or solve the challenge. Listing matches below the
conservative score threshold remain for human review.

The page driver is a trusted boundary. Before navigation, it must enforce the
exact host allowlist, HTTPS, and reject query strings or profile details in any
URL, including redirects and GET form submissions. It must return plain text from
`read` and never execute page-provided code. The interpreter also checks the
current URL after each step, but that check cannot undo a request already made.
The driver must select an exact, unique visible option for `select` and must
never guess a form control when a selector is missing.
No live driver exists yet. Future work must satisfy
[`go-ghost-on-device-release-gate.md`](../docs/security/go-ghost-on-device-release-gate.md)
before adding a broker recipe or installing an extension.

Run offline checks with `node tests/go_ghost_recipe.test.js` or
`python -m pytest tests/test_go_ghost_recipe.py -q` in the project test runtime.
