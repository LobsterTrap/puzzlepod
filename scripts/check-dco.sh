#!/usr/bin/env bash
# Check that all commits in a PR branch have a Signed-off-by: line (DCO).
# Usage: scripts/check-dco.sh [target-branch]
#   target-branch defaults to origin/main
# Exit 0 if all commits pass, exit 1 listing offending commits.

set -euo pipefail

TARGET_BRANCH="${1:-origin/main}"

# Find the merge base between HEAD and the target branch.
MERGE_BASE="$(git merge-base HEAD "$TARGET_BRANCH" 2>/dev/null)" || {
    echo "ERROR: Cannot find merge base between HEAD and $TARGET_BRANCH."
    echo "Ensure the target branch is fetched: git fetch origin main"
    exit 1
}

# Get all commit SHAs between the merge base and HEAD.
COMMITS="$(git log --format='%H' "$MERGE_BASE..HEAD")"

if [[ -z "$COMMITS" ]]; then
    echo "OK: No commits to check (HEAD is at merge base)."
    exit 0
fi

failing=()

while IFS= read -r sha; do
    if ! git log -1 --format='%B' "$sha" | grep -qE '^Signed-off-by: .+ <.+>'; then
        short_sha="$(git log -1 --format='%h' "$sha")"
        subject="$(git log -1 --format='%s' "$sha")"
        failing+=("$short_sha $subject")
    fi
done <<< "$COMMITS"

if [[ ${#failing[@]} -eq 0 ]]; then
    echo "OK: All commits have a Signed-off-by line."
    exit 0
else
    echo "FAIL: The following commits are missing a Signed-off-by line:"
    echo "  Each commit must contain: Signed-off-by: Your Name <your@email.com>"
    echo "  Use 'git commit --signoff' or 'git commit --amend --signoff' to fix."
    echo ""
    for entry in "${failing[@]}"; do
        echo "  $entry"
    done
    echo ""
    echo "${#failing[@]} commit(s) missing DCO sign-off."
    exit 1
fi
