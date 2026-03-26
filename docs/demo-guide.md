# PuzzlePod Demo Guide

This document describes how to run the PuzzlePod demos, what each demo covers, and how they relate to each other.

## Overview

PuzzlePod includes six complementary demo scripts that showcase the system's capabilities:

| Demo | Script | Root? | Requires | Scope |
|---|---|---|---|---|
| **Phase 1: Core** | `demo/run_demo_phase1.sh` | Yes | `puzzle-sandbox-demo` binary | Fork-Explore-Commit lifecycle, kernel enforcement |
| **Phase 2: Hardening** | `demo/run_demo_phase2.sh` | Yes | `puzzle-phase2-demo` binary | Network gating, behavioral monitoring, advanced governance |
| **Sandbox Live** | `demo/sandbox-live-demo.sh` | Yes | Running `puzzled` + `puzzlectl` | Live sandboxed agent with /proc inspection of 8 enforcement properties |
| **Rootless** | `demo/run_demo_rootless.sh` | **No** | `puzzlectl`, `fuse-overlayfs` | Fork-Explore-Commit without root: fuse-overlayfs, OPA/Rego, Landlock, seccomp |
| **E2E Governance** | `demo/e2e_governance_demo.sh` | Yes | Rust test binary | Full governance lifecycle: trust scoring, provenance, attestation, identity |
| **TUI** | `demo/run_demo_tui.sh` | **No** | Running `puzzled` + `puzzlectl` | Interactive terminal UI with real-time governance events and audit log review |

**The demos are complementary, not overlapping.** Phase 1 demonstrates the foundational Fork-Explore-Commit transactional model and kernel-enforced containment. Phase 2 demonstrates hardening features built on top of that foundation. The Sandbox Live demo shows a real agent process running under full kernel enforcement with live inspection of `/proc` to prove containment. The Rootless demo proves that the core governance engine works fully without root privileges — using fuse-overlayfs instead of kernel OverlayFS, D-Bus session bus instead of system bus, and the same OPA/Rego + Landlock + seccomp enforcement. The E2E Governance demo exercises the cross-cutting governance modules (trust, provenance, attestation, identity) through a 3-act narrative. For a complete walkthrough, run Phase 1 first, then Phase 2, then the Sandbox Live demo, then the Rootless demo, then the E2E Governance demo.

---

## Prerequisites

### Hardware / VM Requirements

- Linux kernel 6.7+ (for Landlock ABI v4)
- Root access (required for Phase 1, Phase 2, Sandbox Live, and E2E demos)
- Rust toolchain (for building demo binaries)

The **Rootless demo** does not require root — only `fuse-overlayfs`, `fuse3`, and the built workspace binaries. Install with: `sudo dnf install fuse-overlayfs fuse3`

### Fedora/RHEL Linux Users: libvirt VM Setup

To run all demos inside a VM (rather than directly on your host), use the libvirt convenience script:

```bash
# Install prerequisites
sudo dnf install libvirt virt-install qemu-kvm genisoimage passt rsync
sudo systemctl enable --now libvirtd

# Create and provision the VM (downloads Fedora 42 Cloud image, installs Rust + deps)
./scripts/libvirt-dev.sh setup

# Enter the VM
./scripts/libvirt-dev.sh shell

# Or run demos directly without entering the VM
./scripts/libvirt-dev.sh demo phase1    # Root demos
./scripts/libvirt-dev.sh demo rootless  # Rootless demo (runs as unprivileged user)
```

The VM rsyncs the project source into `~/puzzlepod` inside the guest. Run `./scripts/libvirt-dev.sh sync` after making local changes to update the VM copy.

See `./scripts/libvirt-dev.sh` (no arguments) for all available commands.

### macOS Users: Lima VM Setup

The demos require a Linux kernel. On macOS, use a Lima VM with Fedora 42:

```bash
# Create and start the VM
limactl create --name=puzzled-dev puzzled-dev.yaml
limactl start puzzled-dev

# Enter the VM
limactl shell puzzled-dev

# Navigate to the project (path matches where you cloned the repo)
cd /path/to/puzzlepod
```

### Building Demo Binaries

All demos require compiled Rust binaries:

```bash
# Build all workspace crates in release mode
# On Lima VM, use CARGO_TARGET_DIR to avoid host filesystem overhead:
sudo CARGO_TARGET_DIR=/var/tmp/puzzlepod-target cargo build --workspace --release

# Verify binaries exist
ls ${CARGO_TARGET_DIR:-target}/release/puzzle-sandbox-demo ${CARGO_TARGET_DIR:-target}/release/puzzle-phase2-demo ${CARGO_TARGET_DIR:-target}/release/puzzlectl
```

The build produces three key binaries:

| Binary | Crate | Purpose |
|---|---|---|
| `puzzle-sandbox-demo` | `crates/puzzle-sandbox-demo/` | Phase 1 — live Landlock + seccomp + cgroup enforcement |
| `puzzle-phase2-demo` | `crates/puzzle-phase2-demo/` | Phase 2 — 10 hardening feature demonstrations |
| `puzzlectl` | `crates/puzzlectl/` | CLI for branch management — used by Sandbox Live demo |
| `puzzled` | `crates/puzzled/` | Governance daemon — must be running for Sandbox Live demo |

The E2E Governance demo does not require separate binaries — it runs as a Rust integration test via `cargo test`.

---

## Phase 1 Demo: Core Fork-Explore-Commit

### Running

```bash
sudo demo/run_demo_phase1.sh
```

The demo is interactive — press Enter to advance between sections.

### What It Demonstrates

The Phase 1 demo walks through the complete agent lifecycle using real kernel primitives:

#### Section 0: Prerequisites Check

Verifies that the host kernel supports all required primitives:
- Landlock LSM enabled
- cgroups v2 unified hierarchy
- OverlayFS module loaded
- PID namespace support

#### Section 1: Agent Profiles & Governance Policy

- Displays the three base profiles: `restricted`, `standard`, `privileged`
- Shows the OPA/Rego governance rules from `policies/rules/commit.rego`
- Explains the five default enforcement rules:
  - No sensitive files (credentials, SSH keys, `.env`)
  - No persistence mechanisms (cron jobs, systemd units)
  - No executable permission changes
  - Total change size within limits
  - No system file modifications

#### Section 2: Fork — Create OverlayFS Branch

Demonstrates branch creation with real kernel primitives:
- Creates the directory structure: `base/`, `upper/`, `work/`, `merged/`
- Mounts OverlayFS with lower (base), upper (writes), and work layers
- Creates a cgroup scope with memory and PID limits
- Shows that the merged view contains base files

#### Section 3: Explore — Agent Writes in Sandbox

Simulates an agent writing files:
- Agent creates Python source files in the merged directory
- Demonstrates copy-on-write: writes land only in the upper layer
- Verifies the base filesystem is completely untouched
- Shows the upper layer contains only the agent's new files

#### Section 4: Commit (Approved)

Walks through a successful commit:
1. Freezes agent via `cgroup.freeze` (TOCTOU protection)
2. Generates diff by walking the OverlayFS upper layer
3. Evaluates OPA/Rego policy — passes all rules
4. Writes a WAL entry for crash safety
5. Commits changes to the base filesystem
6. Generates an IMA-signed manifest
7. Verifies the base filesystem now contains the agent's changes

#### Section 5: Commit (Rejected)

Tests governance rejection with malicious changesets:
- Uses sample changesets from `demo/sample_changesets/`:
  - `malicious_changeset.json` — contains `.env` file, cron backdoor, system binary exploit
  - `credential_theft.json` — attempts to exfiltrate credentials
- Runs policy evaluation — **REJECTED** with violations listed
- Performs rollback: discards upper layer with zero residue
- Verifies base filesystem remains untouched

#### Section 6: Live Kernel Enforcement

Runs the `puzzle-sandbox-demo` binary (if available) to demonstrate real enforcement:
- **Landlock:** Attempts to access files outside the allowlist — blocked
- **seccomp-BPF:** Attempts escape-vector syscalls — blocked
- **cgroup limits:** Attempts to exceed memory/PID limits — enforced
- Shows the defense-in-depth summary: 8 independent enforcement layers

#### Section 7: Security Test Suite Overview

Lists the security test categories (50+ attack vectors across 6 categories):
- Namespace escape attempts
- Landlock bypass attempts
- seccomp evasion attempts
- cgroup escape attempts
- OverlayFS exploitation attempts
- Privilege escalation attempts

Each escape vector is blocked by at least 2 independent mechanisms.

### Sample Changesets

The demo uses pre-built changesets in `demo/sample_changesets/`:

| File | Purpose | Expected Result |
|---|---|---|
| `safe_changeset.json` | 3 files added/modified in project scope | Approved |
| `malicious_changeset.json` | `.env` file, cron backdoor, system binary exploit | Rejected (3 violations) |
| `credential_theft.json` | Credential exfiltration attempt | Rejected |
| `concurrent_branch_a.json` | Concurrent branch scenario (branch A) | Used in conflict detection |
| `concurrent_branch_b.json` | Concurrent branch scenario (branch B) | Used in conflict detection |

---

## Phase 2 Demo: Hardening Features

### Running

```bash
sudo demo/run_demo_phase2.sh
```

### What It Demonstrates

Phase 2 covers 10 hardening features. Each section exercises real Rust code from the `puzzle-phase2-demo` binary (sections 1-9) or shell-driven kernel primitives (section 10).

#### Section 1: Expanded Profile Library

- Loads and validates all 23 domain-specific profiles from `policies/profiles/`
- Shows profiles organized by category: DevOps, ML/AI, Security, Edge, Safety-Critical, General
- Demonstrates profile validation against JSON schema

```bash
# Equivalent standalone command:
target/release/puzzle-phase2-demo profiles --profiles-dir policies/profiles/
```

#### Section 2: Cross-Branch Conflict Detection

- Creates two branches modifying overlapping files
- Demonstrates conflict detection strategies:
  - **Reject:** Block conflicting commits
  - **LastWriterWins:** Allow latest commit to overwrite
- Shows conflict resolution workflow

```bash
target/release/puzzle-phase2-demo conflict
```

#### Section 3: Adaptive Budget Engine

- Demonstrates the trust-through-behavior escalation model
- Shows state transitions: Restricted → Standard → Extended
- Budget tracking: exec calls consumed, files modified, network bytes
- Demonstrates how clean commits earn trust escalation

```bash
target/release/puzzle-phase2-demo budget
```

#### Section 4: Persistent Audit Storage

- Writes audit events for agent lifecycle operations
- Queries events by branch ID, event type, and time range
- Exports audit data in JSON and CSV formats
- Verifies audit event integrity

```bash
target/release/puzzle-phase2-demo audit
```

#### Section 5: Network Journal

- Demonstrates side-effect capture for network operations
- Operations: append (record), read (inspect), discard (rollback)
- Shows how HTTP requests are journaled for commit-time replay

```bash
target/release/puzzle-phase2-demo journal
```

#### Section 6: HTTP Proxy with Domain Filtering

- Starts an HTTP proxy for application-level network gating
- Demonstrates domain allowlist enforcement
- Shows how GET requests pass through, POST/PUT/DELETE are queued

```bash
target/release/puzzle-phase2-demo proxy
```

#### Section 7: seccomp USER_NOTIF with Argument Inspection

**Linux only.** Demonstrates the two-tier seccomp architecture:
- **Tier 1 (Static Deny):** 57 escape-vector syscalls permanently blocked via KillProcess action (< 1 μs; 58 on x86_64)
- **Tier 2 (USER_NOTIF):** `execve`/`connect`/`bind` forwarded to daemon for policy evaluation (~50-100 μs)
- Shows argument inspection: daemon reads the actual binary path from the agent's address space

```bash
target/release/puzzle-phase2-demo seccomp
```

#### Section 8: fanotify Behavioral Monitoring

**Linux only.** Demonstrates file access pattern monitoring:
- Sets up fanotify marks on the agent's upper layer
- Triggers behavioral alerts:
  - **Mass deletion:** Agent deletes more files than threshold
  - **Credential access:** Agent accesses `.ssh/`, `.env`, `credentials*`
  - **Excessive reads:** Agent exceeds read rate limit

```bash
target/release/puzzle-phase2-demo fanotify
```

#### Section 9: BPF LSM Exec Rate Limiting

**Linux only.** Demonstrates per-cgroup exec counting and rate limiting:
- Loads BPF LSM program that counts `execve` calls per cgroup
- Shows how rate limits are enforced when the agent exceeds its exec budget

```bash
target/release/puzzle-phase2-demo bpf-lsm
```

#### Section 10: Network Namespace Isolation

**Linux only, shell-driven.** Demonstrates all three network modes with real kernel namespaces:

| Mode | Setup | Behavior |
|---|---|---|
| **Blocked** | Empty network namespace (loopback only) | Zero network access — `curl` fails immediately |
| **Gated** | veth pair + nftables rules (DNS + HTTPS only) + HTTP proxy | Domain allowlist enforced, connections proxied |
| **Monitored** | veth pair + nftables logging rules | Full access with all connections logged |

Each mode is created in a real network namespace using `ip netns`, `ip link`, and `nftables`.

---

## Sandbox Live Demo: Real Agent Under Kernel Enforcement

### Running

The Sandbox Live demo requires a running `puzzled` daemon. Start it in a separate terminal first:

```bash
# Terminal 1: Start puzzled
sudo scripts/dev-setup.sh start

# Terminal 2: Run the demo
sudo demo/sandbox-live-demo.sh
```

The demo runs non-interactively (no Enter prompts) and completes in about 5 seconds.

### What It Demonstrates

The Sandbox Live demo creates a **real sandboxed agent process** using `puzzled`'s D-Bus API, then inspects `/proc` to prove that all 8 enforcement properties are active. Unlike Phase 1 and Phase 2 (which use standalone binaries), this demo exercises the full `puzzled` → `puzzlectl` → `clone3()` → kernel enforcement pipeline.

#### Demo 1: Creating a Sandboxed Branch

Uses the two-step branch lifecycle:
1. **`puzzlectl branch create`** — Creates the OverlayFS workspace (upper/work/merged dirs) with the `restricted` profile. No process is spawned yet.
2. **`puzzlectl branch activate`** — Spawns a sandboxed process (`/usr/bin/cat`) inside the branch via `clone3()`. Sets up PID namespace, mount namespace, network namespace, cgroup scope, Landlock ruleset, seccomp-BPF filter, and capability dropping.

The two-step flow reflects the production architecture: branch creation is separate from process activation, enabling Podman-native mode where Podman creates the container and puzzled only creates the governance workspace.

#### Demo 2: Verifying Kernel Enforcement

Reads `/proc/<PID>/status` and `/proc/<PID>/ns/*` to verify 8 enforcement properties on the live agent process:

| Check | What It Verifies | Expected |
|---|---|---|
| Seccomp | `Seccomp: 2` in `/proc/PID/status` | BPF filter active (mode=2) |
| Capabilities | `CapEff: 0, CapPrm: 0` | All capabilities dropped |
| Credentials | `Uid: 65534` | Running as nobody (non-root) |
| PID namespace | `/proc/PID/ns/pid` differs from host | Isolated PID namespace |
| Mount namespace | `/proc/PID/ns/mnt` differs from host | Isolated mount namespace |
| Network namespace | `/proc/PID/ns/net` differs from host | Isolated network namespace |
| cgroup | `/proc/PID/cgroup` contains `puzzle.slice` | In agent cgroup with memory + PID limits |
| cmdline | `/proc/PID/cmdline` contains expected binary | Correct command executed |

#### Demo 3: Exec Allowlist Enforcement

Creates a second branch and attempts to activate it with `/usr/bin/sleep` — a binary **not** in the `restricted` profile's exec allowlist. The seccomp USER_NOTIF handler in puzzled inspects the `execve` arguments, determines `/usr/bin/sleep` is not allowed, and denies the syscall. The child process dies (becomes a zombie), demonstrating that:

- The seccomp filter gates `execve` through the daemon (USER_NOTIF, not static deny)
- The daemon applies profile-specific allowlists
- Denied binaries never execute — the process is killed

#### Demo 4: OverlayFS Copy-on-Write Isolation

Inspects the OverlayFS upper layer directory from Demo 1. Any files written by the agent appear here (copy-on-write). On rollback, the entire upper directory is deleted — zero residue on the base filesystem.

#### Demo 5: Landlock Filesystem Restriction

Verifies that Landlock is active on the kernel (checks ABI version, kernel config, or LSM list). The `restricted` profile limits reads to `/usr/bin`, `/usr/share`, `/usr/lib`, `/usr/lib64`. Landlock enforcement is in-kernel (< 1 μs per check) and survives puzzled crash — once applied, even killing puzzled cannot remove the Landlock ruleset from the agent process.

#### Demo 6: Network Isolation (Blocked Mode)

Verifies the agent is in a separate network namespace with no interfaces (Blocked mode). Uses `nsenter --net` to inspect the agent's network namespace from the host. The agent cannot reach any network — there are no interfaces to send traffic through.

#### Summary Table

Prints a summary table of all enforcement layers with their survival properties:

```
Layer          | Status       | Survives puzzled crash?
---------------|--------------|------------------------
Seccomp        | mode=2 (BPF) | Yes (irrevocable)
Landlock       | active       | Yes (attached to process)
Capabilities   | CapEff=0     | Yes (irrevocable after setuid)
Credentials    | Uid=65534    | Yes (irrevocable after setuid)
PID namespace  | isolated     | Yes (namespace persists)
Mount namespace| isolated     | Yes (namespace persists)
Net namespace  | isolated     | Yes (namespace persists)
cgroup limits  | puzzle.slice  | Yes (cgroup persists)
```

#### Cleanup

Kills the agent processes and rolls back both branches (Demo 1 cat branch + Demo 3 denied sleep branch). The OverlayFS upper layers and cgroup scopes are cleaned up.

### Key Architecture Insight

This demo highlights the **two-step branch lifecycle** that is central to the puzzled architecture:

```
puzzlectl branch create          puzzlectl branch activate
        │                               │
        ▼                               ▼
  CreateBranch (D-Bus)          ActivateBranch (D-Bus)
        │                               │
        ▼                               ▼
  OverlayFS dirs created        clone3() → child process
  BranchInfo { pid: None }      Landlock + seccomp + cgroups
  State: Ready                  BranchInfo { pid: Some(N) }
                                State: Active
```

`CreateBranch` is a lightweight workspace operation. `ActivateBranch` is where kernel enforcement is configured and the sandboxed process is spawned. This separation enables both direct mode (puzzled spawns the process) and Podman-native mode (Podman spawns the container, puzzled only creates the governance workspace).

---

## Rootless Demo: Governance Without Root

### Running

```bash
demo/run_demo_rootless.sh
```

Do **not** run with `sudo` — the demo explicitly checks that it is running as a non-root user.

The demo is interactive — press Enter to advance between sections.

**Prerequisites:** `fuse-overlayfs` and `fuse3` installed, workspace built (`cargo build --workspace --release`), D-Bus session bus available. If running via SSH without a D-Bus session, wrap with: `dbus-run-session -- demo/run_demo_rootless.sh`

**Via libvirt VM:**

```bash
./scripts/libvirt-dev.sh demo rootless
```

### What It Demonstrates

The Rootless demo proves that PuzzlePod governance works fully without root privileges. It walks through the complete Fork-Explore-Commit lifecycle using only unprivileged operations.

#### Section 1: Rootless Capability Matrix

Displays a feature-by-feature comparison of what works rootless vs. what requires root:

| Feature | Rootless Status | Notes |
|---|---|---|
| Landlock filesystem ACL | **Enabled** | Unprivileged since kernel 5.13 |
| seccomp-BPF (static deny) | **Enabled** | Unprivileged |
| seccomp USER_NOTIF | **Enabled** | Unprivileged since kernel 5.0 |
| OPA/Rego policy engine | **Enabled** | Pure userspace (regorus) |
| WAL-based crash-safe commit | **Enabled** | Filesystem-level |
| Audit chain | **Enabled** | Userspace logging |
| D-Bus governance API | **Enabled** | Session bus |
| OverlayFS branching | **Degraded** | fuse-overlayfs (~15-20% I/O overhead) |
| BPF LSM (exec rate limit) | Disabled | Requires CAP_BPF |
| fanotify (FAN_REPORT_FID) | Disabled | Requires CAP_SYS_ADMIN |
| XFS project quotas | Disabled | Requires root |
| Kernel OverlayFS (mount) | Disabled | Requires CAP_SYS_ADMIN |

Key insight: the governance engine (OPA/Rego), containment (Landlock + seccomp), and crash safety (WAL) all work without root. The root-only features are performance optimizations (kernel OverlayFS, BPF LSM) or monitoring (fanotify).

#### Section 2: User-Mode Directory Setup

Creates XDG-compliant directory structure under `$HOME`:

```
~/.config/puzzled/           # Config, profiles, policies
~/.local/share/puzzled/      # Branches, audit logs
$XDG_RUNTIME_DIR/puzzled/    # Socket, PID file
```

No system directories are modified.

#### Section 3: Agent Profiles & Governance Policy

Displays the agent profiles (restricted, standard, privileged) and OPA/Rego governance rules installed to user-mode paths.

#### Section 4: Fork — fuse-overlayfs Branch Creation

Creates a branch using `fuse-overlayfs` instead of kernel `mount -t overlay`. No mount privileges required — FUSE handles the mount in userspace. Creates a base directory with sample project files and mounts the overlay.

#### Section 5: Explore — Agent Writes in Sandbox

Simulates agent modifications (creating docs, modifying source files) in the merged view. Demonstrates copy-on-write isolation: writes land only in the upper layer, base directory remains untouched.

#### Section 6: Commit (Approved)

Evaluates OPA/Rego governance policy against a safe changeset (docs.md, main.rs, src/helper.rs). Policy passes — no sensitive files, no persistence mechanisms, size within limits. WAL-based commit merges changes into the base.

#### Section 7: Commit (Rejected)

Tests a malicious changeset containing `.env` (credentials), `.ssh/id_rsa` (SSH key exfiltration), and `crontab` (persistence mechanism). Policy rejects. Demonstrates zero-residue rollback — the OverlayFS upper layer is discarded.

#### Section 8: Landlock Enforcement

Verifies Landlock availability and explains that it works fully unprivileged since kernel 5.13. Once applied via `landlock_restrict_self()`, restrictions are irrevocable and kernel-enforced — they survive puzzled crash.

#### Section 9: seccomp Enforcement

Describes the two-tier seccomp strategy (static deny + USER_NOTIF), both of which work unprivileged. If puzzled crashes, USER_NOTIF-gated calls return ENOSYS (fail-closed).

#### Section 10: Podman Rootless Integration

If Podman is installed, shows its rootless mode status and explains how `puzzle-podman` integrates governance with Podman rootless containers.

### User-Mode puzzled Setup

For running puzzled itself in user mode (separate from the demo), use the setup script:

```bash
# Set up user directories, config, profiles, policies
scripts/dev-setup-user.sh setup

# Start puzzled on session bus (foreground)
scripts/dev-setup-user.sh start

# Or background
scripts/dev-setup-user.sh startbg

# Check status
scripts/dev-setup-user.sh status

# Stop
scripts/dev-setup-user.sh stop

# Clean runtime state
scripts/dev-setup-user.sh clean
```

Alternatively, install the systemd user unit.
**Note:** Run `scripts/dev-setup-user.sh setup` first to create the required directories and config files.

```bash
scripts/dev-setup-user.sh setup
mkdir -p ~/.config/systemd/user
cp systemd/puzzled-user.service ~/.config/systemd/user/puzzled.service
systemctl --user enable --now puzzled
systemctl --user status puzzled
journalctl --user -u puzzled -f
```

---

## E2E Governance Lifecycle Demo

### Running

The E2E Governance demo runs as a Rust integration test. No running `puzzled` is needed — it exercises the governance modules directly in-process.

```bash
# On Linux (or Lima VM):
sudo cargo test -p puzzled --test e2e_governance_lifecycle -- --include-ignored --nocapture 2>&1 | head -500

# On Lima VM with separate build target:
sudo CARGO_TARGET_DIR=/var/tmp/puzzlepod-target cargo test -p puzzled \
  --test e2e_governance_lifecycle -- --include-ignored --nocapture 2>&1 | head -500
```

The test produces rich narrative output (not just pass/fail) showing each governance decision, trust score evolution, provenance records, and third-party verification steps.

### What It Demonstrates

The E2E demo tells a story across three acts, following a single agent through its governance lifecycle:

| Act | Title | Modules Exercised | What Happens |
|---|---|---|---|
| **Act 1** | The Cooperative Agent | TrustManager, OPA/Rego, AuditStore, ProvenanceStore | Agent makes a safe commit. Trust score rises. Provenance recorded. Attestation chain verified. |
| **Act 2** | The Rogue Attempt | TrustManager, OPA/Rego, AuditStore, MerkleTree | Agent attempts a malicious commit (cron backdoor + credential theft). Governance rejects. Trust score drops. Attestation proves the rejection happened. |
| **Act 3** | Redemption | TrustManager, OPA/Rego, AuditStore, IdentityManager | Agent returns to safe behavior. Trust score recovers. JWT-SVID identity token issued. Third-party verification demonstrated. |

### Cast of Characters

The demo introduces four participants:

| Who | What | In Linux Terms |
|---|---|---|
| **Operator** | The human who deploys PuzzlePod | The sysadmin who runs `useradd agent-ci` and starts `puzzled` |
| **Agent** | The AI workload being governed | A process tree running under UID 1001 inside a sandbox (PID ns + mount ns + Landlock + seccomp + cgroup) |
| **puzzled** | The governance daemon | A root-owned process evaluating OPA/Rego policies, tracking trust scores, signing attestation chains |
| **Third Party** | An external service the agent interacts with | e.g., `api.github.com` — receives a JWT-SVID bearer token and verifies it offline using a cached JWKS public key |

### Trust Scoring

Trust scores are per-UID (POSIX user identity, assigned by the operator via `useradd`). The five tiers and their score ranges:

| Tier | Score Range | Meaning |
|---|---|---|
| Untrusted | 0-19 | Emergency lockdown candidate |
| Restricted | 20-39 | Minimal access, heavy monitoring |
| Standard | 40-59 | Normal operating range |
| Elevated | 60-79 | Earned broader access |
| Trusted | 80-100 | Maximum trust |

**What changes at each tier (today):** Tier transitions emit `trust_transition` D-Bus signals and update JWT-SVID claims (the `trust_level` claim changes). Dynamic Landlock/seccomp tightening based on trust tier is future work.

### Third-Party Verification

The demo shows the end-to-end flow for how a third party (e.g., GitHub) can verify an agent's identity:

1. **Agent requests token:** Agent calls `GetIdentityToken` on puzzled's D-Bus API (local, UID-checked). puzzled returns a JWT-SVID containing SPIFFE ID, trust level, trust score, and branch ID.
2. **Agent presents token:** Agent attaches the JWT-SVID as a bearer token in its HTTP request to the third party (e.g., `Authorization: Bearer <token>`).
3. **Third party verifies:** The third party verifies the token offline using a cached JWKS public key (Ed25519). No network call to puzzled needed. No UID exposed — the SPIFFE ID is the identity.

**Current limitations demonstrated:**
- No published claims schema (third parties need documentation to interpret claims)
- No JWKS HTTP endpoint (key distribution is manual or in-process today)
- No client SDK for third-party verification libraries

### Attestation Chain

At each act, the demo verifies the attestation chain:
- Each audit event is signed with Ed25519
- Events are organized in a Merkle tree
- Merkle inclusion proofs verify that a specific event belongs to the tree
- This provides tamper-evident forensic proof — puzzled cannot retroactively alter governance decisions without breaking the chain

---

## TUI Demo: Interactive Governance Dashboard

### What This Demo Shows

The TUI demo launches the PuzzlePod interactive terminal UI while running governance simulation scenarios in the background. You watch branches being created, policy-evaluated, committed, and rejected in real time through a cyberpunk-themed dashboard.

The demo showcases two modes:
- **Live mode** — real-time view of active branches as governance scenarios execute
- **Log mode** — review all historical branch activity from the persistent audit log

### Running the Demo

**From the host (via libvirt VM):**

```bash
./scripts/libvirt-dev.sh demo tui
```

**Inside the VM directly:**

```bash
demo/run_demo_tui.sh
```

The script starts `puzzled` (if not already running), launches 7 governance scenarios in the background with paced delays, and opens the TUI in the foreground.

### What Happens

1. **Splash screen** (3 seconds) — PuzzlePod ASCII art logo
2. **Dashboard** appears showing the branch table (initially empty)
3. Background scenarios begin executing every ~10 seconds:
   - `safe_code_edit` — standard profile, should commit (currently denied due to exec permission policy)
   - `credential_leak` — policy violation, rejected
   - `persistence_attack` — policy violation, rejected
   - `network_exfiltration` — policy violation, rejected
   - `multi_file_refactor` — standard profile, should commit
   - `mixed_safe_and_sensitive` — rejected (sensitive content)
   - `exec_attempt` — rejected
4. Each scenario creates a branch (visible in Live mode during `--pace` delays), executes file changes, and submits for policy review
5. The title bar shows `LIVE` (green) or `LOG` (yellow) mode indicator

### Key Bindings

| Key | Context | Action |
|-----|---------|--------|
| `m` | Dashboard | Toggle between Live and Log mode |
| `L` | Dashboard | Open full audit log viewer with filtering |
| `j/k` | Any | Navigate up/down |
| `Enter` | Dashboard | Open branch detail view |
| `Esc` | Detail/Log | Return to Dashboard |
| `h/l` | Detail | Cycle through tabs (Logs, Diff/Draft, Policy, Settings) |
| `Tab` | Dashboard | Cycle focus (status, tabs, branch table) |
| `r` | Any | Refresh data |
| `c` | Dashboard | Create new branch |
| `q` | Dashboard | Quit |

### Live vs Log Mode

**Live mode** polls the daemon every 2 seconds for active branches. Branches are ephemeral — they appear while a scenario is running (thanks to `--pace` delays) and disappear after commit/rollback. Notification toasts appear for D-Bus signals.

**Log mode** reconstructs all historical branches from the persistent audit event store. Press `m` to switch. Every branch that was ever created appears in the table with its final state (Committed, Denied, RolledBack). Select any branch and press Enter to view its full audit trail in the Logs tab.

### Audit Log Viewer

Press `L` (shift-L) from the Dashboard to open the full audit log screen. This shows all governance events chronologically with:
- Timestamp, event type, branch ID, and detail summary
- Color coding: green (created/committed), red (violations/rejected), yellow (review/rollback)
- Filterable by branch ID and event type (Tab to switch filter fields, type to filter, Enter to reload)

---

## Demo Architecture

### How the Demos Use Kernel Primitives

| Kernel Primitive / Module | Phase 1 Demo | Phase 2 Demo | Sandbox Live Demo | Rootless Demo | E2E Governance Demo |
|---|---|---|---|---|---|
| OverlayFS | Branch creation, copy-on-write, diff, commit | — | Upper layer inspection | fuse-overlayfs (userspace) | — |
| Landlock LSM | Live enforcement via `puzzle-sandbox-demo` | — | ABI detection, live on agent | ABI detection (works unprivileged) | — |
| seccomp-BPF | Live enforcement via `puzzle-sandbox-demo` | USER_NOTIF argument inspection | Live filter on agent, exec allowlist | Description (works unprivileged) | — |
| PID namespace | Process isolation demo | — | `/proc/PID/ns/pid` verification | — | — |
| Mount namespace | — | — | `/proc/PID/ns/mnt` verification | — | — |
| cgroups v2 | Memory/PID limits, `cgroup.freeze` | — | Live cgroup scope with limits | — | — |
| Capabilities | — | — | CapEff/CapPrm = 0 verification | — | — |
| fanotify | — | Behavioral monitoring triggers | — | Disabled (noted) | — |
| BPF LSM | — | Exec counting, rate limiting | — | Disabled (noted) | — |
| Network namespace | — | Blocked/Gated/Monitored modes | Blocked mode, nsenter inspection | — | — |
| nftables | — | Per-namespace firewall rules | — | — | — |
| XFS quotas | Mentioned (setup) | — | — | Disabled (noted) | — |
| OPA/Rego | Policy evaluation (approve/reject) | — | — | Policy eval (approve + reject) | Commit governance (approve + reject) |
| WAL | Crash-safe commit | — | — | WAL commit simulation | — |
| IMA | Changeset signing | — | — | — | — |
| clone3() | — | — | Live process creation with CLONE_INTO_CGROUP | — | — |
| TrustManager | — | — | — | — | Per-UID trust scoring across 5 tiers |
| ProvenanceStore | — | — | — | — | Tool/model/source provenance records |
| AuditStore + MerkleTree | — | — | — | — | Signed audit events + Merkle inclusion proofs |
| IdentityManager | — | — | — | — | JWT-SVID tokens + JWKS verification (requires `ima` feature) |

### Demo Binary Architecture

```
demo/run_demo_phase1.sh
  ├── Shell-driven OverlayFS + cgroup setup
  ├── OPA policy evaluation
  └── target/release/puzzle-sandbox-demo
        └── Live Landlock + seccomp + cgroup enforcement

demo/run_demo_phase2.sh
  ├── target/release/puzzle-phase2-demo
  │     ├── profiles    — Profile library validation
  │     ├── conflict    — Cross-branch conflict detection
  │     ├── budget      — Adaptive budget engine
  │     ├── audit       — Persistent audit storage
  │     ├── journal     — Network journal
  │     ├── proxy       — HTTP proxy with domain filtering
  │     ├── seccomp     — seccomp USER_NOTIF (Linux only)
  │     ├── fanotify    — Behavioral monitoring (Linux only)
  │     └── bpf-lsm     — BPF LSM rate limiting (Linux only)
  └── Shell-driven network namespace isolation (Linux only)

demo/sandbox-live-demo.sh
  ├── Requires: puzzled running (sudo scripts/dev-setup.sh start)
  ├── puzzlectl branch create   → D-Bus → puzzled CreateBranch
  ├── puzzlectl branch activate → D-Bus → puzzled ActivateBranch → clone3()
  ├── /proc/<PID> inspection   → 8 enforcement property verification
  └── puzzlectl agent kill      → cleanup + rollback

demo/run_demo_rootless.sh (NO ROOT REQUIRED)
  ├── fuse-overlayfs mount     → userspace OverlayFS (no mount privileges)
  ├── Agent file writes        → copy-on-write isolation in upper layer
  ├── OPA/Rego policy eval     → approve safe / reject malicious changesets
  ├── WAL commit simulation    → crash-safe commit protocol
  ├── Landlock ABI check       → confirms unprivileged enforcement available
  ├── seccomp description      → confirms unprivileged enforcement available
  └── Podman rootless check    → integration with rootless containers

cargo test -p puzzled --test e2e_governance_lifecycle
  ├── No puzzled needed (in-process governance modules)
  ├── Act 1: Safe commit      → OPA approve → trust +5 → provenance → attestation
  ├── Act 2: Malicious commit  → OPA reject → trust -10 → attestation proves rejection
  ├── Act 3: Redemption        → OPA approve → trust recovers → JWT-SVID issued
  └── Third-party verification → Merkle proofs + Ed25519 signatures + JWT-SVID
```

---

## Running Individual Phase 2 Features

Each Phase 2 feature can be tested independently using the `puzzle-phase2-demo` binary:

```bash
# Run a single feature
sudo target/release/puzzle-phase2-demo <feature>

# Available features:
target/release/puzzle-phase2-demo profiles --profiles-dir policies/profiles/
target/release/puzzle-phase2-demo conflict
target/release/puzzle-phase2-demo budget
target/release/puzzle-phase2-demo audit
target/release/puzzle-phase2-demo journal
target/release/puzzle-phase2-demo proxy
target/release/puzzle-phase2-demo seccomp    # Linux only
target/release/puzzle-phase2-demo fanotify   # Linux only
target/release/puzzle-phase2-demo bpf-lsm   # Linux only
```

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---|---|
| `puzzle-sandbox-demo` or `puzzle-phase2-demo` not found | Run `sudo CARGO_TARGET_DIR=/var/tmp/puzzlepod-target cargo build --workspace --release` |
| "puzzlectl not found" (Sandbox Live) | Same build command. Scripts check `CARGO_TARGET_DIR` first, then `./target/release/` |
| "puzzled is not running" (Sandbox Live) | Start puzzled first: `sudo scripts/dev-setup.sh start` in another terminal |
| Sandbox Live Demo 3 hangs | Ensure `timeout` is installed. The demo uses `timeout 10` to handle activation blocking |
| "Landlock not supported" | Ensure kernel 5.13+ with Landlock enabled. Check: `cat /sys/kernel/security/lsm` |
| "cgroups v2 not available" | Boot with `systemd.unified_cgroup_hierarchy=1`. Check: `stat /sys/fs/cgroup/cgroup.controllers` |
| "OverlayFS mount failed" | Run as root. Check: `modprobe overlay && lsmod \| grep overlay` |
| seccomp/fanotify/BPF sections skipped | These require a real Linux kernel (not macOS). Use Lima VM |
| Network namespace section fails | Requires root and `ip` / `nftables` utilities installed |
| "Permission denied" on demo script | Run with `sudo`: `sudo demo/run_demo_phase1.sh` (not needed for rootless demo) |
| "This demo must NOT run as root" (rootless) | Run without `sudo`: `demo/run_demo_rootless.sh` |
| "fuse-overlayfs not found" (rootless) | Install: `sudo dnf install fuse-overlayfs fuse3` |
| "DBUS_SESSION_BUS_ADDRESS not set" (rootless) | Wrap with: `dbus-run-session -- demo/run_demo_rootless.sh` |
| "$HOME is not set" (rootless/user-mode) | Set `$HOME` or use `--config` with an explicit config path |
| Cargo build doesn't detect changes on Lima VM | Touch the modified file first: `touch crates/puzzlectl/src/main.rs` then rebuild |

### Lima VM Tips

```bash
# Start the VM
limactl start puzzled-dev

# Enter the VM
limactl shell puzzled-dev

# Rebuild after code changes (use CARGO_TARGET_DIR on Lima)
sudo CARGO_TARGET_DIR=/var/tmp/puzzlepod-target cargo build --workspace --release

# If changes aren't detected, touch the modified file first
touch crates/puzzlectl/src/main.rs

# Check kernel version
uname -r

# Start puzzled for Sandbox Live demo
sudo scripts/dev-setup.sh start &

# Check puzzled status
sudo scripts/dev-setup.sh status
```

---

## Presenting the Demos

### Recommended Presentation Order

For a complete technical walkthrough (approximately 60-70 minutes):

1. **Phase 1** (15-20 minutes) — establishes the foundational concepts
   - Focus on Sections 2-5: Fork → Explore → Commit (Approved) → Commit (Rejected)
   - Section 6 (Live Kernel Enforcement) is the highlight
2. **Phase 2** (15-20 minutes) — shows production hardening
   - Focus on Sections 1, 3, 7, 10: Profiles → Budget Escalation → seccomp → Network Isolation
   - Other sections can be shown as time permits
3. **Sandbox Live** (5-10 minutes) — proves it all works end-to-end
   - Show the real agent process, inspect `/proc` for enforcement proof
   - Demo 3 (exec allowlist) is the strongest "wow" moment — seccomp denies a binary in real time
4. **Rootless** (5-10 minutes) — proves governance works without root
   - Show the capability matrix: what works vs. what degrades
   - Fork-Explore-Commit with fuse-overlayfs — same lifecycle, no privileges
   - Key message: core governance engine is identical in both modes
5. **E2E Governance** (10 minutes) — demonstrates cross-cutting governance
   - Follow the 3-act narrative: cooperative → rogue → redemption
   - Show trust score evolution across acts
   - Highlight third-party verification (JWT-SVID + Merkle attestation)

### Quick Demo (15 minutes)

For a condensed executive overview:

1. **Sandbox Live demo** (5 minutes) — real agent, real kernel enforcement, real `/proc` proof
2. Phase 1, Sections 4-5: Commit approved vs. rejected (governance)
3. **E2E Governance** Act 2 only (5 minutes) — show a rogue attempt being rejected with trust score impact and tamper-evident attestation

### Developer Onboarding Demo (10 minutes)

For developers who want to try PuzzlePod without root access:

1. **Rootless demo** (10 minutes) — no root required, shows the full governance lifecycle
   - Highlights that Landlock + seccomp + OPA/Rego all work unprivileged
   - Shows XDG-compliant user-mode directory structure
   - Demonstrates Podman rootless integration path

### Deep Technical Demo (15 minutes)

For an engineering audience:

1. **Sandbox Live demo** (5 minutes) — establish that enforcement is real, not simulated
2. Phase 2, Section 7: seccomp USER_NOTIF argument inspection — show the two-tier seccomp architecture
3. Phase 2, Section 10: Network namespace isolation — Blocked/Gated/Monitored modes

### Key Talking Points

- **"The kernel enforces, the agent cannot escape."** — Landlock and seccomp are irrevocable once applied
- **"Zero kernel modifications."** — Everything uses existing upstream primitives
- **"Zero residue rollback."** — Rejected branches are discarded completely
- **"Defense in depth."** — 8 independent enforcement properties, each survives failure of the others
- **"Trust through behavior."** — Agents earn broader access through demonstrated safe behavior
- **"Survives daemon crash."** — All enforcement is kernel-level; killing puzzled doesn't remove restrictions from the agent process
- **"Works without root."** — Core governance (OPA/Rego, Landlock, seccomp, WAL) is fully functional rootless; root-only features are performance optimizations
- **"Two-step lifecycle."** — Create workspace, then activate process — enables both direct and Podman-native modes
- **"Tamper-evident audit."** — Every governance decision is signed (Ed25519) and organized in a Merkle tree — retroactive alteration breaks the chain
- **"Third-party verifiable."** — Agents carry JWT-SVID identity tokens that external services can verify offline using a public key — no trust in the agent required
