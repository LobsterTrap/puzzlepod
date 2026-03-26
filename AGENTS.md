# AGENTS.md

## Project overview

**PuzzlePod** is a userspace governance daemon (`puzzled`) and CLI (`puzzlectl`) for automated governance of AI agent workloads in containers on Linux. It composes with Podman and systemd — not reinvents them. Core concept: **Fork, Explore, Commit** — agents execute in isolated OverlayFS branches, changes are evaluated by OPA/Rego policy, approved changes are committed, rejections roll back cleanly. No kernel modifications required.

Targets: RHEL 10+, Fedora 42+, CentOS Stream 10 on x86_64/aarch64. Designed for data center servers and edge devices (4GB+ RAM).

## Components

| Component | Location | Description |
|---|---|---|
| `puzzled` | `crates/puzzled/` | Governance daemon (Rust, tokio, zbus). D-Bus API, OverlayFS branching, OPA/Rego policy, sandbox setup |
| `puzzlectl` | `crates/puzzlectl/` | CLI tool (Rust, clap). Branch/profile/policy management, TUI, governance simulator |
| `puzzled-types` | `crates/puzzled-types/` | Shared types crate (Branch, Change, CommitResult) |
| `puzzle-sim-worker` | `crates/puzzlectl/src/bin/puzzle_sim_worker.rs` | Sandbox executor for simulator (not user-facing) |
| `puzzle-podman` | `podman/puzzle-podman` | Bash wrapper for Podman-native mode |
| OCI hook | `podman/hooks/` | Bash OCI runtime hook for branch annotation |
| Profiles | `policies/profiles/` | YAML agent profiles (restricted, standard, privileged) |
| Commit rules | `policies/rules/` | OPA/Rego governance policies |
| SELinux module | `selinux/` | Type enforcement for `puzzlepod_t` domain |
| systemd units | `systemd/` | Service, template, and slice units |

## Build and test commands

```bash
# Build
make build                    # or: cargo build --workspace

# Unit tests (no root required)
make test                     # or: cargo test --workspace

# CI checks (fmt + clippy + test + deny)
make ci

# Integration tests (root + Linux required)
sudo make test-integration

# Live D-Bus integration tests (requires running puzzled)
make test-dbus

# Security tests (root + Linux required)
sudo make test-security

# Full test suite
sudo make test-all

# All make targets
make help
```

## Code style and conventions

- **Language:** Rust for all userspace components; C for BPF LSM programs
- **Async runtime:** tokio
- **D-Bus:** zbus (async, pure Rust). All D-Bus methods must be idempotent
- **CLI:** clap derive macros. Output must be machine-parseable (JSON with `--output=json`)
- **Policy engine:** regorus (pure-Rust OPA/Rego evaluator)
- **Profiles:** YAML, validated against JSON schema
- **Commit rules:** Rego, tested with `puzzlectl policy test`
- **Config auto-detection:** `DaemonConfig::load_or_default()` — checks `/etc/puzzled/puzzled.conf`, then user config, then defaults
- **D-Bus bus name:** `org.lobstertrap.PuzzlePod1.Manager` (system) or session bus (rootless)

### Comment tag conventions

Source comments use prefixed tags. Key prefixes: `H` (hardening), `M` (mitigation), `SC` (seccomp design), `PM` (Phase 2 feature), `DC` (design choice), `L` (lifecycle constraint), `A`/`B`/`C` (v6 audit fixes).

### Optional Cargo features (puzzlectl)

| Feature | Default | Description |
|---|---|---|
| `tui` | yes | Interactive terminal UI (`puzzlectl tui`) with Live/Log mode toggle and audit log viewer |
| `sim` | yes | Governance simulator and `puzzle-sim-worker` binary. `--pace` flag adds delays for TUI visibility |

## Design principles

1. **Zero kernel modifications** — compose existing upstream primitives only
2. **Kernel enforces, userspace decides** — puzzled configures Landlock/seccomp/namespaces/cgroups; kernel enforces irrevocably; puzzled evaluates OPA/Rego policy
3. **Defense in depth** — Landlock, BPF LSM, seccomp, SELinux, namespaces, cgroups are independent layers
4. **Fail closed** — if governance cannot be determined, rollback (not commit)
5. **Deterministic behavior** — no ML, heuristics, or probabilistic decisions in governance path
6. **Composable** — SELinux, audit, Podman, systemd continue unchanged

## Key files

| File | Purpose |
|---|---|
| `Makefile` | Build system — `make help` for all targets |
| `docs/PRD.md` | Full Product Requirements Document (architecture, enforcement model, performance targets, open questions, safety, operational details) |
| `docs/podman_puzzled_architecture.md` | Podman-native mode architecture spec |
| `docs/Kernel_vs_userspace.md` | Architectural decision: why userspace-first |
| `docs/demo-guide.md` | Demo walkthrough (all 5 demos) |
| `demo/run_demo_rootless.sh` | Rootless demo script |
| `scripts/dev-setup-user.sh` | User-mode puzzled setup (no root required) |
| `crates/puzzled/src/dbus.rs` | D-Bus API implementation (16 methods, 8 signals) |

## Author

Francis Chow
