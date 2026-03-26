---
name: process
description: >
  Development process discipline for PuzzlePod. Defines the workflow from issue
  creation through merge. GitHub Issues-first, conventional commits, DCO sign-off,
  CI gates, and Definition of Done.
---

# Development Process

## Core Principle

**If it is not in GitHub Issues, it does not exist.**

No work begins without an issue. No code merges without a linked issue. No issue
closes without passing the Definition of Done.

## Issue Format

Every issue uses the **Goal + Acceptance Criteria** format:

```markdown
## Goal

<What the user or system should be able to do after this work is complete.
Write from the user's perspective. One to three sentences.>

## Acceptance Criteria

- [ ] <Specific, testable condition 1>
- [ ] <Specific, testable condition 2>
- [ ] <Specific, testable condition 3>

## Context

<Why this matters now. Link to PRD section, user feedback, or dependency.>

## Out of Scope

<What this issue explicitly does NOT cover, to prevent scope creep.>
```

## Issue Types and Labels

**Type labels:**

| Label | Use |
|-------|-----|
| `epic` | Large body of work spanning multiple issues |
| `story` | User-visible feature or capability |
| `task` | Implementation work item |
| `spike` | Time-boxed research or investigation |
| `bug` | Defect in existing functionality |

**Priority labels:** `P0-critical`, `P1-high`, `P2-medium`, `P3-low`

**Component labels:** `comp:puzzled`, `comp:puzzlectl`, `comp:types`, `comp:proxy`,
`comp:hook`, `comp:init`, `comp:policy`, `comp:sandbox`, `comp:dbus`, `comp:selinux`

## Conventional Commits with DCO

Follow the commit format defined in `CONTRIBUTING.md` § Branching and Commits.

**The DCO sign-off is required.** Use `git commit -s` to add it automatically.

**AI attribution trailers** (per `docs/AI_POLICY.md`):

- `Assisted-by: Claude Code <noreply@anthropic.com>` -- AI helped write code
- `Generated-by: Claude Code <noreply@anthropic.com>` -- AI generated most of the code

## PR Checklist

Every PR must satisfy before merge:

| Requirement | How to Verify |
|-------------|---------------|
| Linked issue | PR body contains `Closes #N`, `Fixes #N`, or `Resolves #N` |
| Passing CI | `gh pr checks <number>` shows all green |
| DCO sign-off | Every commit has `Signed-off-by:` trailer |
| AI attribution | If AI-assisted, `Assisted-by:` or `Generated-by:` trailer present |
| Human review | At least 1 approval (2 for security-sensitive paths) |
| Docs updated | User-facing changes include documentation updates |

## Security-Sensitive Paths

These paths require **2 human approvals** per `docs/AI_POLICY.md`:

- `crates/puzzled/src/sandbox/`
- `policies/rules/`
- `selinux/`
- `bpf/`
- `crates/puzzled/src/dbus.rs`
- `crates/puzzle-init/`

## Definition of Done

An issue is done when all of the following are true:

| Criterion | Details |
|-----------|---------|
| **Tests pass** | `make ci` is green (fmt + clippy + test + deny) |
| **CI green** | GitHub Actions workflow passes on the PR |
| **Docs updated** | If the change is user-facing, docs are updated in the same PR |
| **Issue closed** | The GitHub Issue is closed with a link to the merged PR |
| **No regressions** | Existing tests continue to pass; no new warnings |
| **Breaking changes documented** | If applicable, migration guide exists in `docs/` |
| **Security review complete** | If touching security-sensitive paths, 2 approvals obtained |

## Policy Reminder

All AI-assisted development on PuzzlePod must follow `docs/AI_POLICY.md`:

- AI attribution trailers on every AI-assisted commit
- Human review requirements (1 standard, 2 for security-sensitive)
- DCO sign-off on every commit
- No secrets, credentials, or PII in issues, PRs, or commits
