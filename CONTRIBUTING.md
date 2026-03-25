# Contributing to PuzzlePod

PuzzlePod is a userspace governance daemon (`puzzled`) and CLI (`puzzlectl`) for automated governance of AI agent workloads in containers on Linux. It composes with Podman and systemd to provide **Fork, Explore, Commit** semantics -- agents execute in isolated OverlayFS branches, changes are evaluated by OPA/Rego policy, approved changes are committed, rejections roll back cleanly.

This guide covers how to contribute effectively, whether you are a human developer, an AI-assisted developer, or an AI agent operating under human supervision.

---

## Table of Contents

1. [Agent-First Development](#1-agent-first-development)
2. [Quick Start](#2-quick-start)
3. [Skills-Based Workflow](#3-skills-based-workflow)
4. [Issue Guidelines](#4-issue-guidelines)
5. [Branching and Commits](#5-branching-and-commits)
6. [Vouch System (External Contributors)](#6-vouch-system-external-contributors)
7. [Development Setup](#7-development-setup)
8. [Test Suite Overview](#8-test-suite-overview)
9. [Code Guidelines](#9-code-guidelines)
10. [Adding Tests](#10-adding-tests)
11. [CI Pipeline](#11-ci-pipeline)
12. [AI Policy](#12-ai-policy)
13. [Available Make Targets](#13-available-make-targets)

---

## 1. Agent-First Development

PuzzlePod treats AI coding assistants (Claude Code, GitHub Copilot, and similar tools) as **production-grade development tools**, not toys. Every workflow in this project is designed to work when an AI agent is driving the keyboard under human supervision.

**Core principles:**

- **You must understand your code.** AI assists; humans are accountable. Every commit bearing your name is your responsibility, regardless of how the code was produced. If you cannot explain a change line-by-line to a reviewer, do not submit it.
- **Start every task with an issue.** Issues are the unit of work. Before writing code, ensure a GitHub Issue exists with clear acceptance criteria. This gives both human and AI contributors a shared definition of "done."
- **Load the relevant skill.** The `skills/` directory contains role-specific instruction files. Reference the appropriate skill file in your AI assistant prompt before starting work. Skills encode project conventions, quality expectations, and workflow steps so the AI operates within project norms.
- **Work through the SDLC.** Follow the full software development lifecycle: requirements (issue), design, implementation, testing, review, merge. Do not skip steps because "the AI got it right the first time." Verify that claim.

**What this means in practice:**

- AI-generated code goes through the same review process as human-written code.
- AI-generated tests must actually exercise the acceptance criteria, not just exist.
- Security-sensitive paths (`crates/puzzled/src/sandbox/`, seccomp filters, Landlock rulesets, policy evaluation) require extra human scrutiny on AI-generated changes.

---

## 2. Quick Start

```bash
# Check that build dependencies are installed
make check-deps

# Build the workspace
make build

# Run CI checks locally (fmt + clippy + tests + cargo-deny)
make ci

# Full test suite (requires root + Linux)
sudo make test-all
```

If you are on macOS, see [Development Setup](#7-development-setup) for Lima VM instructions.

---

## 3. Skills-Based Workflow

The `skills/` directory contains role-specific instruction files that you load into your AI assistant prompt. Each skill encodes the project's conventions, quality bars, and workflow steps for a particular role in the SDLC.

### Available Skills

| Skill | File | When to Use |
|-------|------|-------------|
| Product Manager | `skills/pm.md` | Writing issues, defining acceptance criteria, prioritizing work |
| Engineer | `skills/engineer.md` | Implementing features, fixing bugs, writing production code |
| Test QE | `skills/test-qe.md` | Writing tests against acceptance criteria, verifying coverage |
| Adversarial QE | `skills/adversarial-qe.md` | Breaking things on purpose, fuzzing, edge cases, security testing |
| Security | `skills/security.md` | Security review, threat modeling, hardening analysis |
| Performance | `skills/performance.md` | Benchmarking, profiling, optimization, regression detection |
| UX Design | `skills/uxd.md` | CLI ergonomics, error messages, help text, user workflows |
| Documentation | `skills/docs.md` | Writing and updating docs, README, guides, API references |
| Release/XE | `skills/xe.md` | Release engineering, packaging, CI/CD, deployment |
| Code Review | `skills/code-review.md` | Reviewing PRs, providing structured feedback |

### Typical Workflow

The standard flow through skills follows the SDLC:

```
PM --> Engineer --> Test QE --> Adversarial QE --> (Security, Performance, UXD, Docs, XE as needed)
```

1. **PM** defines the issue with goal, context, and acceptance criteria.
2. **Engineer** implements the feature or fix against the acceptance criteria.
3. **Test QE** writes tests that verify each acceptance criterion.
4. **Adversarial QE** tries to break the implementation with edge cases and malicious inputs.
5. **Security / Performance / UXD / Docs / XE** are applied as the change warrants.

### Example Prompts

Start a feature implementation:

```
Using skills/engineer.md: implement issue #42. Read the acceptance criteria
from the issue, then implement the changes in crates/puzzled/src/sandbox/.
```

Follow up with tests against the same acceptance criteria:

```
Using skills/test-qe.md: write tests for issue #42. Read the acceptance
criteria from the issue and write unit and integration tests that verify
each criterion. Place unit tests in the source file and integration tests
in crates/puzzled/tests/.
```

Run adversarial testing:

```
Using skills/adversarial-qe.md: try to break the implementation from
issue #42. Focus on malicious inputs, race conditions, resource exhaustion,
and sandbox escape vectors.
```

---

## 4. Issue Guidelines

**GitHub Issues** is the issue tracker for PuzzlePod. Every code change should trace back to an issue.

### Issue Templates

Use the provided issue templates when creating issues:

- **`bug_report.yml`** -- For reporting defects. Include reproduction steps, expected vs. actual behavior, and environment details. Where possible, include agent diagnostics (D-Bus error output, `puzzlectl` JSON output, journal logs from `journalctl -u puzzled`).
- **`feature_request.yml`** -- For proposing new functionality. Every feature request must include a **Goal** (what problem does this solve?) and **Acceptance Criteria** (how do we know it is done?).

### Labels

Issues are categorized with the following label scheme:

**Type labels:**

| Label | Use |
|-------|-----|
| `bug` | Something is broken |
| `enhancement` | New feature or improvement |
| `epic` | Large body of work spanning multiple issues |
| `story` | User-facing capability (child of an epic) |
| `task` | Concrete implementation unit (child of a story) |
| `spike` | Time-boxed research or investigation |

**Priority labels:**

| Label | Meaning |
|-------|---------|
| `P0` | Critical -- blocks release or causes data loss / security breach |
| `P1` | High -- must fix this milestone |
| `P2` | Medium -- should fix this milestone |
| `P3` | Low -- fix when convenient |

**Component labels:**

| Label | Component |
|-------|-----------|
| `comp:puzzled` | Governance daemon |
| `comp:puzzlectl` | CLI tool |
| `comp:puzzled-types` | Shared types crate |
| `comp:puzzle-proxy` | Proxy component |
| `comp:puzzle-hook` | OCI hook |
| `comp:puzzle-init` | Init component |
| `comp:policy` | OPA/Rego policies and profiles |
| `comp:sandbox` | Sandbox enforcement (Landlock, seccomp, namespaces) |
| `comp:dbus` | D-Bus API |
| `comp:ci` | CI/CD and build system |

---

## 5. Branching and Commits

### Branch Naming

Use the format `<type>/<issue#>-<short-description>`:

```
feat/42-landlock-ruleset
fix/87-wal-corruption
refactor/103-dbus-error-handling
docs/115-admin-guide
test/99-adversarial-seccomp
```

### Conventional Commits with DCO

Every commit message follows Conventional Commits format:

```
<type>(<scope>): <description>
```

**Types:**

| Type | Use |
|------|-----|
| `feat` | New feature |
| `fix` | Bug fix |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `docs` | Documentation changes |
| `ci` | CI/CD changes |
| `perf` | Performance improvement |
| `chore` | Maintenance (dependencies, tooling, config) |

**Scopes:**

| Scope | Component |
|-------|-----------|
| `puzzled` | Governance daemon |
| `puzzlectl` | CLI tool |
| `puzzled-types` | Shared types crate |
| `puzzle-proxy` | Proxy component |
| `puzzle-hook` | OCI hook |
| `puzzle-init` | Init component |
| `policy` | OPA/Rego policies and profiles |
| `sandbox` | Sandbox enforcement |
| `dbus` | D-Bus API |

### DCO Sign-Off (Required)

All commits **must** include a `Signed-off-by:` line to certify the [Developer Certificate of Origin](https://developercertificate.org/). Use the `-s` flag:

```bash
git commit -s -m "feat(puzzled): add Landlock ruleset v5 support"
```

This produces:

```
feat(puzzled): add Landlock ruleset v5 support

Signed-off-by: Your Name <your.email@example.com>
```

### AI Attribution Trailers

When AI tools assist with code, add an attribution trailer. See `docs/AI_POLICY.md` for full details.

- **`Assisted-by: <tool>`** -- Default for AI-assisted work. You directed the work, reviewed the output, and edited the result.
- **`Generated-by: <tool>`** -- For large generated blocks with minimal human editing. Signals reviewers that extra scrutiny is warranted.

```bash
git commit -s -m "feat(puzzled): add Landlock ruleset v5 support

Assisted-by: Claude Code <noreply@anthropic.com>
Signed-off-by: Your Name <your.email@example.com>"
```

### PR Process

1. **Create a branch** from the issue using the naming convention above.
2. **Make changes** and commit with DCO sign-off and AI attribution (if applicable).
3. **Push** and open a pull request linking to the issue (use `Closes #42` or `Fixes #42` in the PR body).
4. **AI agent review** runs automatically on the PR.
5. **At least 1 human approval** is required. Security-sensitive paths (`crates/puzzled/src/sandbox/`, seccomp filters, Landlock rulesets, policy evaluation, SELinux modules) require **2 human approvals**.
6. **All CI checks must pass** before merge.

---

## 6. Vouch System (External Contributors)

First-time external contributors need a maintainer vouch before their PRs are reviewed and merged. This protects the project from unsolicited changes that do not align with the project's direction.

**How it works:**

1. **Open a Discussion** in the GitHub Discussions tab describing your intended changes. Write this in your own words -- explain what you want to change, why, and your approach.
2. **A maintainer reviews** your proposal and responds with `/vouch` to approve you as a contributor.
3. **Once vouched**, your PRs proceed through normal review.
4. **Unvouched PRs** are automatically held by the `vouch.yml` workflow until a maintainer vouches for the contributor.

This is a one-time process. Once vouched, you do not need to be vouched again for future contributions.

---

## 7. Development Setup

### Linux (Native)

PuzzlePod requires Linux kernel primitives (namespaces, cgroups, Landlock, OverlayFS). Native Linux is the primary development environment.

**Supported distributions:** RHEL 10+, Fedora 42+, CentOS Stream 10

```bash
# Check what's already installed
make check-deps

# Install build dependencies
sudo dnf install -y gcc gcc-c++ make cmake pkg-config \
  openssl-devel dbus-devel systemd-devel \
  clang llvm libseccomp-devel bpftool libbpf-devel \
  xfsprogs xfsprogs-devel nftables audit ima-evm-utils jq \
  rust cargo cargo-deny clippy rustfmt

# Build
make build
```

### macOS (Lima VM)

On macOS, use the included Lima VM to get a Linux environment:

```bash
# Create and start the VM (~10 min first time)
./scripts/lima-dev.sh setup

# Enter the VM at the project directory
./scripts/lima-dev.sh shell
```

Once inside the VM, follow the Linux (Native) instructions above.

### Running puzzled for Development

```bash
# Create directories, install config/profiles/policies
sudo make dev-setup

# Start puzzled in foreground (Ctrl+C to stop)
sudo make dev-start

# In another terminal, create a test branch:
mkdir -p /tmp/test
sudo target/release/puzzlectl branch create \
  --profile=restricted \
  --base=/tmp/test \
  --command='["/bin/sleep","300"]'

# List active branches:
sudo target/release/puzzlectl branch list
```

---

## 8. Test Suite Overview

PuzzlePod has 5 test suites with different requirements. Run what you can locally; CI covers the rest.

| # | Suite | Make Target | Standalone Command | Requires |
|---|-------|-------------|---------------------|----------|
| 1 | Security shell tests | `sudo make test-security` | `sudo tests/security/run_all.sh` | Root + Linux |
| 2 | Rogue agent (sandboxed) | -- | `sudo puzzle-sandbox-demo exec -- bash test_rogue_agent.sh` | Root + Linux + puzzle-sandbox-demo built |
| 3 | Live D-Bus integration | `make test-dbus` | `cargo test -p puzzled --test live_dbus_integration -- --test-threads=1` | Running puzzled (script handles this automatically) |
| 4 | Cargo unit tests | `make test` | `cargo test --workspace` | Any platform |
| 5 | Cargo integration tests | `sudo make test-integration` | `sudo cargo test --workspace -- --include-ignored --test-threads=1` | Root + Linux |

### Running the full suite

```bash
# All 5 suites
sudo make test-all
```

### Quick mode

Use `--quick` to skip slow suites when iterating:

```bash
sudo scripts/run_all_tests.sh --quick
```

### Minimum before pushing

At an absolute minimum, run the unit tests and CI checks:

```bash
make ci
```

---

## 9. Code Guidelines

- **Rust** for all userspace components. Build via Cargo workspace (`make build`).
- Run `make fmt` before committing. CI rejects unformatted code.
- Run `make clippy` locally. CI enforces zero warnings. Note: Clippy on macOS skips `#[cfg(target_os = "linux")]` files -- CI catches lint errors that macOS misses.
- All D-Bus methods must be **idempotent**. Clients may retry any call safely.
- `puzzlectl` output must be machine-parseable with `--output=json`. Every command that produces output must support this flag.
- **Async runtime:** tokio. Do not introduce other async runtimes.
- **D-Bus:** zbus (async, pure Rust).
- **CLI:** clap derive macros.
- **Policy engine:** regorus (pure-Rust OPA/Rego evaluator).
- **Profiles:** YAML, validated against JSON schema.

### Code Comment Conventions

Source comments use prefixed tags to categorize design decisions and security measures:

| Prefix | Meaning | Example |
|--------|---------|---------|
| `H` | Hardening measure | `H8: Policy evaluation timeout` |
| `M` | Mitigation (for specific threat) | `M10: Rate limiting branch creation` |
| `SC` | Seccomp-specific design | `SC1: TOCTOU-safe execve via ADDFD` |
| `DC` | Design choice (trade-off) | `DC2: Idempotency cache for D-Bus` |
| `PM` | Phase 2 feature (planned) | `PM3: BPF LSM file-level policy` |
| `L` | Lifecycle constraint | `L1: Must drop before sandbox entry` |
| `A` / `B` / `C` | v6 audit fix categories | `A3: Input validation on profile names` |

---

## 10. Adding Tests

- **Unit tests** go in the source file (as `#[cfg(test)] mod tests`) or in `crates/<crate>/tests/<module>.rs`.
- **Integration tests** that require root should be marked with `#[ignore]` and a comment explaining why:
  ```rust
  #[ignore] // Requires root on Linux (Landlock, mount namespaces)
  ```
- **Security shell tests** go in `tests/security/test_<name>.sh`. They are auto-discovered by `run_all.sh`.
- **CRITICAL:** When adding a new integration test file to `crates/puzzled/tests/`, you **must** update both `scripts/run_all_tests.sh` and `.github/workflows/ci.yml` to include the new test in the explicit `--test` lists. The `live_dbus_integration` test binary is excluded from general `cargo test` runs to prevent hangs; other test binaries need explicit listing for the same reason.

---

## 11. CI Pipeline

CI runs on GitHub Actions. The following workflows operate on the repository:

| Workflow | File | Trigger | What It Does |
|----------|------|---------|--------------|
| **CI** | `ci.yml` | Push/PR to main | Formatting, Clippy lint, unit tests, feature flag matrix, cargo-deny (advisories, licenses, sources, bans) |
| **D-Bus Integration** | `ci.yml` (integration job) | Push/PR to main (after CI passes) | Starts D-Bus + puzzled, runs live D-Bus integration tests |
| **Security Tests** | `ci.yml` (security-test job) | Manual dispatch | Integration tests (root), security shell tests, rogue agent test on privileged runner |
| **Release Build** | `ci.yml` (release job) | Manual dispatch (main only) | Release binary build + RPM spec validation |
| **DCO** | `dco.yml` | Pull requests | Enforces `Signed-off-by` trailer on all commits |
| **Vouch** | `vouch.yml` | Pull requests | Holds PRs from unvouched external contributors |
| **Security Scan** | `security-scan.yml` | Push/PR/scheduled | SAST analysis, dependency vulnerability scanning, secret detection, container image scanning |
| **Performance** | `performance.yml` | Push/PR | Benchmark regression detection, comparison against baseline |
| **Agent Review** | `agent-review.yml` | Pull requests | AI-powered code review providing automated feedback |
| **Docs** | `docs.yml` | Push/PR (docs changes) | Documentation build and link validation |
| **Dev Release** | `release-dev.yml` | Push to main | Development snapshot builds |
| **Tag Release** | `release-tag.yml` | Tag push (`v*`) | Versioned release builds and artifacts |
| **Auto Tag** | `auto-tag.yml` | Push to main | Automatic version tagging based on conventional commits |

### CI Requirements for Merge

All of the following must pass before a PR can merge:

- Formatting (`cargo fmt --check`)
- Clippy (zero warnings)
- Unit tests (all crates)
- Feature flag matrix (`puzzlectl` with/without `tui` and `sim`)
- Dependency audit (`cargo-deny`)
- DCO sign-off present on all commits

---

## 12. AI Policy

PuzzlePod has a comprehensive AI code assistant policy. See **[docs/AI_POLICY.md](docs/AI_POLICY.md)** for the full document.

**Key points:**

- **Human accountability.** The person whose name is on the commit is responsible for the code, regardless of whether AI generated it.
- **Attribution is required.** Use `Assisted-by:` (default) or `Generated-by:` (for large generated blocks) commit trailers. See [AI Attribution Trailers](#ai-attribution-trailers) above.
- **No secrets in prompts.** Never paste API keys, credentials, private keys, or customer data into AI assistant prompts.
- **Security-critical code gets extra scrutiny.** AI-generated changes to sandbox enforcement, seccomp filters, Landlock rulesets, and policy evaluation require careful human review.
- **Test AI output.** Do not assume AI-generated code is correct. Run it, test it, break it.

---

## 13. Available Make Targets

Run `make help` for a full list of available targets. Key targets:

| Target | Description |
|--------|-------------|
| `make` | Build everything (Rust + BPF + SELinux) |
| `make build` | Build Rust workspace (debug) |
| `make release` | Build edge-optimized release |
| `make check` | Run `fmt --check` + `clippy` |
| `make fmt` | Format all Rust code |
| `make clippy` | Run Clippy lints |
| `make deny` | Run cargo-deny (advisories, licenses, sources, bans) |
| `make test` | Run unit tests |
| `make test-integration` | Run integration tests (requires root + Linux) |
| `make test-dbus` | Run live D-Bus integration tests |
| `make test-security` | Run security shell tests (requires root + Linux) |
| `make test-all` | Run all 5 test suites |
| `make ci` | Run CI checks (fmt + clippy + test + deny) |
| `make container` | Build container image |
| `make install` | Install binaries, configs, man pages, units, policies |
| `make uninstall` | Remove installed files |
| `make dev-setup` | Create directories and install configs for development |
| `make dev-start` | Start puzzled in foreground for development |
| `make dev-stop` | Stop development puzzled |
| `make docs` | Build documentation |
| `make clean` | Remove build artifacts |
| `make check-deps` | Verify build dependencies are installed |
| `make version` | Show current version |
| `make srpm` | Build source RPM |
| `make rpm-lint` | Lint RPM spec files |
| `make help` | Show all available targets |

---

## Questions?

If something in this guide is unclear or you get stuck, open a GitHub Discussion. We would rather answer a question than debug a bad PR.
