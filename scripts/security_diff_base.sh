#!/usr/bin/env bash
# Print the commit that CI should compare against for diff-aware scanners.
set -euo pipefail

candidate="${SECURITY_BASE_SHA:-}"
if [[ "$candidate" =~ ^[0-9a-f]{40}$ ]] && [[ "$candidate" != "0000000000000000000000000000000000000000" ]] && git cat-file -e "$candidate^{commit}" 2>/dev/null; then
  printf '%s\n' "$candidate"
  exit 0
fi

# Branch creation and manually dispatched runs have no usable before SHA.
# Compare the latest commit with its parent rather than scanning old history.
git rev-parse --verify HEAD^ 2>/dev/null
