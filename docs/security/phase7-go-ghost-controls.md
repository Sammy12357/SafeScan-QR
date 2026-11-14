# Go Ghost automation limits

The browser automation route accepts at most one active job per web worker. A second request returns HTTP 429 with `Retry-After: 5` before consuming the user's three-per-day quota. A SQLite reservation also rejects another live job for the same user across workers. Runs have a 60-second outer deadline; timeouts and cancelled requests update the existing job row, and a job left `running` by a process crash becomes `interrupted` after two minutes.

This is a draft control. The in-process semaphore is global only within one worker and one instance; keep Render at one web worker and one instance until a shared job queue replaces it. The profile-email ownership decision remains open: the route still accepts a different email in the submitted profile, so this phase must not be released as an abuse-complete control without Sam's decision on family or delegated requests. No background queue or email verification is implied by the job status row.
