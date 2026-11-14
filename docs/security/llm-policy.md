# LLM use in SafeScan

SafeScan's current `generate_ai_verdict` is deterministic rule-based code. It does
not call an LLM. Scores, risk bands, provider findings, verification coverage,
and allowlist decisions are computed from trusted checks, not generated prose.

If an LLM is introduced later:

- Its output is advisory text only. It must never set or override the score,
  verdict, verification status, provider findings, or allowlist.
- Treat QR contents, redirect destinations, and fetched page text as untrusted
  data. Pass them as quoted data with explicit boundaries, never as instructions.
- Cap input and output lengths before any model call. Do not include secrets,
  session credentials, or unrelated user data in the prompt.
- Enforce both per-account and global token budgets before sending a request.
  An exhausted budget leaves the deterministic verdict available and reports
  the explanation as unavailable.
- Do not follow links, run code, or call tools on the model's instruction.
  Any such action needs a separate validated, authorized application path.
- Test prompt-injection strings in QR payloads and page content. The resulting
  score, verdict, and allowlist decision must match the deterministic path.

Any future LLM integration needs a separate security review and release gate.
