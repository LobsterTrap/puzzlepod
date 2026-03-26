# Contributing to PuzzlePod

PuzzlePod is a userspace governance daemon (`puzzled`) and CLI (`puzzlectl`) for automated governance of AI agent workloads in containers on Linux. It composes with Podman and systemd to provide **Fork, Explore, Commit** semantics -- agents execute in isolated OverlayFS branches, changes are evaluated by OPA/Rego policy, approved changes are committed, rejections roll back cleanly.

This guide covers how to contribute effectively, whether you are a human developer, an AI-assisted developer, or an AI agent operating under human supervision.

---

## Table of Contents

1. [Agent-First Development](#1-agent-first-development)
2. [Quick Start](#2-quick-start)
3. [Skills-Based Workflow](#3-skills-based-workflow)
4. [Branching and Commits](#4-branching-and-commits)
5. [Development Setup](#5-development-setup)
6. [Test Suite Overview](#6-test-suite-overview)
7. [Code Guidelines](#7-code-guidelines)
8. [Adding Tests](#8-adding-tests)
9. [CI Pipeline](#9-ci-pipeline)
10. [AI Policy](#10-ai-policy)
11. [Available Make Targets](#11-available-make-targets)

---

## 1. Agent-First Development

PuzzlePod treats AI coding assistants (Claude Code, GitHub Copilot, and similar tools) as **production-grade development tools**, not toys. Every workflow in this project is designed to work when an AI agent is driving the keyboard under human supervision.

**Core principles:**

- **You must understand your code.** AI assists; humans are accountable. Every commit bearing your name is your responsibility, regardless of how the code was produced.
- **Start every task with an issue.** Before writing code, ensure a GitHub Issue exists with clear acceptance criteria. This gives both human and AI contributors a shared definition of "done."
- **Load the relevant skill.** The `skills/` directory contains role-specific instruction files. Reference the appropriate skill file in your AI assistant prompt before starting work.
- **Work through the SDLC.** Follow the full lifecycle: requirements (issue), design, implementation, testing, review, merge. Do not skip steps because "the AI got it right the first time."

Security-sensitive paths (`crates/puzzled/src/sandbox/`, seccomp filters, Landlock rulesets, policy evaluation) require extra human scrutiny on AI-generated changes.

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

If you are on macOS, see [Development Setup](#5-development-setup) for Lima VM instructions.

---

## 3. Skills-Based Workflow

The `skills/` directory contains role-specific instruction files that you load into your AI assistant prompt. Each skill encodes the project's conventions, quality bars, and workflow steps.

### Available Skills

| Skill | File | When to Use |
|-------|------|-------------|
| Engineer | `skills/engineer.md` | Implementing features, fixing bugs, writing tests, code review |
| Adversarial QE | `skills/adversarial-qe.md` | Security review, breaking things on purpose, edge cases, sandbox escape testing |
| Process | `skills/process.md` | Writing issues, defining acceptance criteria, understanding PR/commit conventions |

Additionally, three auto-activating skills in `.claude/skills/` provide context automatically when editing relevant files:

| Skill | Activates On | Purpose |
|-------|-------------|---------|
| Governance Domain | `crates/puzzled/` | Fork-Explore-Commit model, sandbox layers, design principles |
| Rust Conventions | `*.rs` files | tokio, zbus, clap, regorus, error handling, comment tags |
| Testing Patterns | `tests/` files | Test organization, registration requirements, benchmark patterns |

### Example Prompts

```
Using skills/engineer.md: implement issue #42. Read the acceptance criteria
from the issue, then implement the changes in crates/puzzled/src/sandbox/.
```

```
Using skills/adversarial-qe.md: try to break the implementation from
issue #42. Focus on malicious inputs, race conditions, resource exhaustion,
and sandbox escape vectors.
```

---

## 4. Branching and Commits

### Branch Naming

Use the format `<type>/<issue#>-<short-description>`:

```
feat/42-landlock-ruleset
fix/87-wal-corruption
refactor/103-dbus-error-handling
test/99-adversarial-seccomp
```

### Conventional Commits with DCO

Every commit message follows Conventional Commits format with a DCO sign-off:

```
<type>(<scope>): <description>

<optional body explaining why, not what>

Closes #<issue>
Signed-off-by: Name <email>
Assisted-by: Claude Code <noreply@anthropic.com>
```

Use `git commit -s` to add the sign-off automatically.

**Types:** `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `perf`, `chore`

**Scopes:** `puzzled`, `puzzlectl`, `puzzled-types`, `puzzle-proxy`, `puzzle-hook`,
`puzzle-init`, `policy`, `sandbox`, `dbus`

### AI Attribution Trailers

- **`Assisted-by: <tool>`** -- Default for AI-assisted work.
- **`Generated-by: <tool>`** -- For large generated blocks with minimal human editing.

See `docs/AI_POLICY.md` for full details.

### PR Process

1. Create a branch from the issue using the naming convention above.
2. Commit with DCO sign-off and AI attribution (if applicable).
3. Open a PR linking to the issue (`Closes #42` or `Fixes #42` in the body).
4. At least **1 human approval** required. Security-sensitive paths require **2 approvals**.
5. All CI checks must pass before merge.

---

## 5. Development Setup

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

```bash
# Create and start the VM (~10 min first time)
./scripts/lima-dev.sh setup

# Enter the VM at the project directory
./scripts/lima-dev.sh shell
```

Once inside the VM, follow the Linux instructions above.

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
```

---

## 6. Test Suite Overview

PuzzlePod has 5 test suites with different requirements:

| # | Suite | Make Target | Requires |
|---|-------|-------------|----------|
| 1 | Cargo unit tests | `make test` | Any platform |
| 2 | Cargo integration tests | `sudo make test-integration` | Root + Linux |
| 3 | Live D-Bus integration | `make test-dbus` | Running puzzled |
| 4 | Security shell tests | `sudo make test-security` | Root + Linux |
| 5 | Rogue agent (sandboxed) | -- | Root + Linux + puzzle-sandbox-demo |

```bash
# All suites
sudo make test-all

# Minimum before pushing
make ci
```

---

## 7. Code Guidelines

- **Rust** for all userspace components. Build via Cargo workspace (`make build`).
- Run `make fmt` before committing. CI rejects unformatted code.
- Run `make clippy` locally. CI enforces zero warnings.
- All D-Bus methods must be **idempotent**.
- `puzzlectl` output must be machine-parseable with `--output=json`.
- **Async runtime:** tokio. Do not introduce other async runtimes.
- **D-Bus:** zbus (async, pure Rust).
- **CLI:** clap derive macros.
- **Policy engine:** regorus (pure-Rust OPA/Rego evaluator).

### Comment Tag Conventions

| Prefix | Meaning | Example |
|--------|---------|---------|
| `H` | Hardening measure | `H8: Policy evaluation timeout` |
| `M` | Mitigation (for specific threat) | `M10: Rate limiting branch creation` |
| `SC` | Seccomp-specific design | `SC1: TOCTOU-safe execve via ADDFD` |
| `DC` | Design choice (trade-off) | `DC2: Idempotency cache for D-Bus` |
| `PM` | Phase 2 feature (planned) | `PM3: BPF LSM file-level policy` |
| `L` | Lifecycle constraint | `L1: Must drop before sandbox entry` |
| `A`/`B`/`C` | v6 audit fix categories | `A3: Input validation on profile names` |

### Documentation Conventions

- **Rustdoc:** Every `pub` item gets a doc comment. First line is a one-sentence summary.
  Include `# Examples` with compilable code blocks where useful.
- **Man pages:** Follow standard sections: NAME, SYNOPSIS, DESCRIPTION, OPTIONS,
  EXIT STATUS, FILES, ENVIRONMENT, EXAMPLES, SEE ALSO, BUGS.

---

## 8. Adding Tests

- **Unit tests** go in the source file as `#[cfg(test)] mod tests`.
- **Integration tests** requiring root: mark with `#[ignore] // Requires root on Linux`.
- **Security shell tests** go in `tests/security/test_<name>.sh`.
- **CRITICAL:** When adding a new integration test file to `crates/puzzled/tests/`, you **must** update both `scripts/run_all_tests.sh` and `.github/workflows/ci.yml` to include the new test in the explicit `--test` lists.

---

## 9. CI Pipeline

| Workflow | File | Trigger | What It Does |
|----------|------|---------|--------------|
| **CI** | `ci.yml` | Push/PR to main | License headers, formatting, Clippy, unit tests, feature flag matrix, cargo-deny |
| **DCO** | `dco.yml` | Pull requests | Enforces `Signed-off-by` trailer on all commits |
| **Security Scan** | `security-scan.yml` | Push/PR/weekly | Secret detection (gitleaks), container image scanning (trivy) |
| **Docs** | `docs.yml` | Push to main | Rustdoc build and GitHub Pages deployment |
| **Issue Triage** | `issue-triage.yml` | New issues | Auto-labels bug reports missing diagnostics |
| **Agent Dispatch** | `agent-dispatch.yml` | Issue labeled `agent:*` | Goose implements issue, creates draft PR |
| **Tag Release** | `release-tag.yml` | Tag push (`v*`) | Versioned release builds and artifacts |

### CI Requirements for Merge

- Formatting (`cargo fmt --check`)
- Clippy (zero warnings)
- Unit tests (all crates)
- Feature flag matrix (`puzzlectl` with/without `tui` and `sim`)
- Dependency audit (`cargo-deny`)
- DCO sign-off present on all commits

---

## 10. AI Policy

See **[docs/AI_POLICY.md](docs/AI_POLICY.md)** for the full document.

**Key points:**

- **Human accountability.** The person whose name is on the commit is responsible for the code, regardless of whether AI generated it.
- **Attribution is required.** Use `Assisted-by:` or `Generated-by:` commit trailers.
- **No secrets in prompts.** Never paste API keys, credentials, private keys, or customer data into AI assistant prompts.
- **Security-critical code gets extra scrutiny.** AI-generated changes to sandbox enforcement, seccomp filters, Landlock rulesets, and policy evaluation require careful human review.

---

## 11. Available Make Targets

Run `make help` for a full list. Key targets:

| Target | Description |
|--------|-------------|
| `make build` | Build Rust workspace (debug) |
| `make release` | Build edge-optimized release |
| `make fmt` | Format all Rust code |
| `make clippy` | Run Clippy lints |
| `make deny` | Run cargo-deny |
| `make test` | Run unit tests |
| `make test-integration` | Integration tests (root + Linux) |
| `make test-dbus` | Live D-Bus integration tests |
| `make test-security` | Security shell tests (root + Linux) |
| `make test-all` | All 5 test suites |
| `make ci` | CI checks (fmt + clippy + test + deny) |
| `make dev-setup` | Install configs for development |
| `make dev-start` | Start puzzled in foreground |
| `make check-deps` | Verify build dependencies |
| `make help` | Show all targets |

---

## 12. Agent Dispatch Workflow

PuzzlePod uses [Goose](https://block.github.io/goose/) to automatically implement issues. A maintainer triggers this by adding a label to a GitHub issue.

### Trigger Labels

| Label | Effect |
|-------|--------|
| `agent:implement` | Implement a feature from the issue |
| `agent:fix` | Fix a bug described in the issue |
| `agent:test` | Write tests described in the issue |

### How It Works

1. A maintainer reviews the issue (clear goal + acceptance criteria) and adds a trigger label.
2. The `agent-dispatch.yml` workflow starts Goose with Google AI (Gemini).
3. Goose reads the issue, researches the codebase, implements the change, and verifies with `cargo check/test/fmt/clippy`.
4. A **draft PR** is created linking `Closes #<issue>`.
5. A human must review and approve the PR before merge.

### State Labels

| Label | Meaning |
|-------|---------|
| `agent:in-progress` | Goose is working (prevents duplicate runs) |
| `agent:pr-created` | Goose succeeded; draft PR exists |
| `agent:failed` | Goose failed; see workflow log for details |

### Retrying After Failure

Remove the `agent:failed` label and re-add the trigger label (`agent:implement`, `agent:fix`, or `agent:test`).

### Setup

Required GitHub secret: `GOOGLE_API_KEY` (Google AI API key for Gemini).
Optional GitHub variable: `GOOSE_MODEL` (defaults to `gemini-3.1-pro-preview`).

---

## Questions?

If something in this guide is unclear or you get stuck, open a GitHub Discussion.
