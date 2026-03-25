Triage GitHub issue #$ARGUMENTS using the product-manager skill.

1. Read `skills/product-manager.md` for triage guidelines
2. Fetch issue: `gh issue view $ARGUMENTS`
3. Analyze:
   - Is the issue well-formed? (Goal + Acceptance Criteria present?)
   - What component is affected? (puzzled, puzzlectl, puzzled-types, puzzle-proxy, puzzle-hook, puzzle-init)
   - What priority should it be? (P0-critical, P1-high, P2-medium, P3-low)
   - Are there related or duplicate issues? `gh issue list --search "..."`
4. Suggest labels: type (bug/enhancement/task/spike), priority (P0-P3), component (comp:puzzled, etc.)
5. If bug: check if agent diagnostics section is present
6. Post triage comment: `gh issue comment $ARGUMENTS --body "..."`
