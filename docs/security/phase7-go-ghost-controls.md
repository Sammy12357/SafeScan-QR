# Go Ghost automation limits

The browser automation route accepts at most one active job per web worker. A second request returns HTTP 429 with `Retry-After: 5` before consuming the user's three-per-day quota. A SQLite reservation also rejects another live job for the same user across workers. Runs have a 60-second outer deadline; timeouts and cancelled requests update the existing job row, and a job left `running` by a process crash becomes `interrupted` after two minutes.

When the submitted profile email differs from the signed-in account email, the user must check a confirmation that they have the person's permission. The API enforces a literal boolean `delegateAttestation: true`; the checkbox alone is not trusted. A successful delegated reservation atomically records the actor, job ID, broker, and attestation in `audit_logs`. It does not copy the person's name, email, address, phone, IP, or user agent into that attestation row. The confirmation is a user declaration, not independent proof of authorization.

This is a draft control. The in-process semaphore is global only within one worker and one instance; keep Render at one web worker and one instance until a shared job queue replaces it. No background queue or email verification is implied by the job status row.
