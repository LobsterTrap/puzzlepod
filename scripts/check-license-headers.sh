#!/usr/bin/env bash
# Check that all .rs files contain the SPDX license header.
# Usage: scripts/check-license-headers.sh
# Exit 0 if all files pass, exit 1 with a list of failing files.

set -euo pipefail

HEADER="// SPDX-License-Identifier: Apache-2.0"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(cd "$(dirname "$0")/.." && pwd)")"

failing=()

while IFS= read -r -d '' file; do
    if ! head -n 5 "$file" | grep -qF "$HEADER"; then
        failing+=("$file")
    fi
done < <(find "$REPO_ROOT" -name '*.rs' -not -path '*/target/*' -print0)

if [[ ${#failing[@]} -eq 0 ]]; then
    echo "OK: All .rs files contain SPDX license header."
    exit 0
else
    echo "FAIL: The following .rs files are missing the SPDX license header:"
    echo "  Expected: $HEADER"
    echo ""
    for file in "${failing[@]}"; do
        echo "  $file"
    done
    echo ""
    echo "${#failing[@]} file(s) missing header."
    exit 1
fi
