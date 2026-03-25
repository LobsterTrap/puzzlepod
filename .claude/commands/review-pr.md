Review pull request #$ARGUMENTS using the engineer and adversarial-qe skills.

1. Read `skills/engineer.md` and `skills/adversarial-qe.md` for review guidelines
2. Fetch the PR diff: `gh pr diff $ARGUMENTS`
3. Read the linked issue from the PR description
4. Review the changes against:
   - Acceptance criteria from the linked issue
   - PuzzlePod code conventions from AGENTS.md
   - All adversarial-qe attack dimensions (correctness, edge cases, security, concurrency, sandbox escape, D-Bus, OPA bypass)
5. Post a structured review comment on the PR using `gh pr review $ARGUMENTS --comment --body "..."`
6. Include findings ordered by severity with evidence and suggestions
7. Add AI attribution footer per `docs/AI_POLICY.md`
