# Phase 8 static-analysis baseline review

The integrated Phase 8 branch has 25 Bandit medium/high findings, the same
count and rule mix as Phase 7: 17 B704 `Markup` calls and eight B608 SQL
construction warnings. An AST comparison of `routes_pages.py` against Phase 7
found all 17 `Markup` call expressions unchanged. Removing two unused imports
shifted their line and context hashes. The single shifted `schema.py` B608
uses a question-mark placeholder for each value in the unchanged admin
denylist update; new schema additions moved its line. The other seven B608
entries are identical. The exact baseline was refreshed after this review.

The new Phase 8 ownership export SQL uses fixed query strings with bound
parameters, so it adds no B608 exceptions. See the earlier
[output-encoding review](phase4-bandit-review.md) for the existing B704 calls.
