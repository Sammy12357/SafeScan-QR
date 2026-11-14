# Phase 6 Bandit baseline review

On 2026-11-14, the admin authorization change inserted three lines in
`hackabull/admin_data.py` before four existing B608 findings. The new lines
defer admin page data loading until after the role check. No SQL construction
at those findings changed. The exact baseline was refreshed for their shifted
line numbers and surrounding-code hashes; the other 22 findings are unchanged.
