# PuzzlePod Technical Design

> Kernel-enforced governance for autonomous AI agents on Linux.

**Version:** 1.0
**Date:** 2026-03-24
**Repository:** [https://github.com/LobsterTrap/PuzzlePod](https://github.com/LobsterTrap/PuzzlePod)
**Target platforms:** RHEL 10+, Fedora 42+, CentOS Stream 10
**Target architectures:** x86_64, aarch64
**Target environments:** Data center servers, edge computing nodes (4GB+ RAM), safety-certified deployments

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Kernel Primitives](#2-kernel-primitives)
3. [Core Containment Architecture](#3-core-containment-architecture)
4. [Defense-in-Depth](#4-defense-in-depth)
5. [Userspace Components](#5-userspace-components)
6. [Tier 1: Regulatory and Liability Capabilities](#6-tier-1-regulatory-and-liability-capabilities)
7. [Tier 2: Technical Moat Capabilities](#7-tier-2-technical-moat-capabilities)
8. [Tier 3: Ecosystem Capabilities](#8-tier-3-ecosystem-capabilities)
9. [Security Model](#9-security-model)
10. [Performance Analysis](#10-performance-analysis)
11. [Functional Safety](#11-functional-safety)
12. [Testing Strategy](#12-testing-strategy)
13. [Appendix A: D-Bus API Specification](#appendix-a-d-bus-api-specification)
14. [Appendix B: Configuration Schema](#appendix-b-configuration-schema)
15. [Appendix C: Original Kernel Extension Designs (Historical Reference)](#appendix-c-original-kernel-extension-designs-historical-reference)

---

## 1. Architecture Overview

### 1.1 System Architecture

PuzzlePod is a userspace governance daemon (`puzzled`) and CLI (`puzzlectl`) that add automated governance to AI agent workloads running in containers on Linux. It composes with Podman and systemd -- not reinvents them. Container isolation (namespaces, cgroups, seccomp, SELinux) is handled by Podman/crun as usual; `puzzled` adds the governance layer on top: OPA/Rego policy evaluation on changesets, automated commit/rollback decisions, and optional runtime mediation of specific syscalls.

The core concept is **Fork, Explore, Commit** -- agents execute in isolated copy-on-write filesystem branches (OverlayFS), their changes are reviewed by the governance policy engine, and only approved changes are committed. Failures and rejections result in clean rollback with zero residue. No kernel modifications are required.

PuzzlePod supports two operating modes for container lifecycle management. Both provide the same governance guarantees; they differ in who creates the container:

| Mode | Container created by | Use case | Root required? | Mac/Windows? | Status |
|---|---|---|---|---|---|
| **Direct mode** | puzzled via `clone3()` | Edge devices, safety-critical, minimal TCB | Yes | No | **Implemented** |
| **Podman-native mode** | Podman/crun (unmodified) | Data center, developer workstations, CI/CD | No (rootless supported) | Yes (via `podman machine`) | **Proposed** |

#### System Architecture (Direct Mode)

```
+-------------------------------------------------------------+
|                    USERSPACE (all new code)                  |
|                                                             |
|  +-------------+  +--------------+  +---------------+      |
|  |   puzzled   |  |   puzzlectl  |  |  OPA/Rego     |      |
|  | (Rust,      |  |   (Rust,     |  |  Policies     |      |
|  |  tokio,     |  |   clap)      |  |  (Wasm via    |      |
|  |  zbus)      |  |              |  |   regorus)    |      |
|  |             |  |              |  |               |      |
|  | - clone3()  |  | - D-Bus      |  | - Commit      |      |
|  | - pidfd     |  |   client     |  |   governance  |      |
|  | - OverlayFS |  | - Branch     |  | - Path        |      |
|  | - Landlock  |  |   inspect    |  |   allowlists  |      |
|  | - cgroup.   |  | - Approve/   |  | - Quantitative|      |
|  |   freeze    |  |   reject     |  |   limits      |      |
|  | - WAL       |  |              |  |               |      |
|  |   commit    |  |              |  |               |      |
|  +------+------+  +--------------+  +---------------+      |
|         |                                                   |
|         | clone3() + pidfd + mount() + landlock + ...        |
|---------+---------------------------------------------------|
|         v          EXISTING KERNEL (unmodified)             |
|                                                             |
|  +-----------+ +----------+ +------------+ +--------+      |
|  | Landlock  | | BPF LSM  | | seccomp-BPF| |SELinux |      |
|  | (ABI v4+) | | (5.7+)   | |            | |        |      |
|  +-----------+ +----------+ +------------+ +--------+      |
|  +-----------+ +----------+ +------------+ +--------+      |
|  | PID NS    | | Mount NS | | Net NS     | |cgroups |      |
|  | + pidfd   | |+OverlayFS| |+nftables   | | v2     |      |
|  +-----------+ +----------+ +------------+ +--------+      |
|  +-----------+ +----------+ +------------+                  |
|  | XFS proj  | | Linux    | | IMA        |                  |
|  | quotas    | | Audit    | |            |                  |
|  +-----------+ +----------+ +------------+                  |
+-------------------------------------------------------------+
```

#### System Architecture (Podman-Native Mode -- Proposed)

```
+------------------------------------------------------------------+
|                     Developer Interface                           |
|                                                                   |
|  puzzle-podman run --profile=standard myimage ./agent.py          |
|  puzzle-podman agent list | inspect | approve | reject | diff     |
|                                                                   |
|  (bash wrapper -- delegates to podman + puzzled)                  |
+----------+------------------------------+------------------------+
           |                              |
    podman flags                    D-Bus calls
    (standard CLI)                  (puzzlectl/puzzled)
           |                              |
           v                              v
+-----------------------+  +----------------------------------+
|  Podman (unmodified)  |  |  puzzled (governance-only daemon) |
|                       |  |                                  |
| - OCI image mgmt     |  | - OverlayFS branch management   |
| - Namespace setup     +->| - OPA/Rego policy engine        |
| - cgroup v2 limits    |  | - seccomp USER_NOTIF handler    |
| - Network (netavark)  |  | - Landlock ruleset generation   |
| - Rootless mode       |  | - BPF LSM program loading       |
| - podman machine (VM) |  | - fanotify monitoring           |
|                       |  | - Audit chain (HMAC + IMA)      |
|  +------------------+ |  | - D-Bus API (16+4 methods)      |
|  | crun (OCI)       | |  | - Prometheus metrics            |
|  | seccomp notif ---+>+  +----------------------------------+
|  | OCI hooks -------+>+----> puzzle-hook (createRuntime,
|  +------------------+ |                  poststop)
+-----------------------+
```

### 1.2 Design Philosophy: Kernel Enforces, Userspace Decides

`puzzled` is a userspace daemon that **configures** kernel enforcement mechanisms on behalf of agent processes. Once configured, the enforcement is performed by the kernel and is **irrevocable by the agent**.

| Mechanism | Configured by (direct mode) | Configured by (Podman-native, proposed) | Enforced by (kernel) | Survives puzzled crash? |
|---|---|---|---|---|
| Landlock ruleset | puzzled applies via `landlock_restrict_self()` | `puzzle-init` shim inside container | Kernel LSM hook on every file access | **Yes** -- attached to process, not daemon |
| seccomp-BPF filter | puzzled loads via `seccomp()` | crun loads from OCI seccomp profile | Kernel checks on every syscall | **Yes** -- irrevocable once loaded |
| PID namespace | puzzled creates via `clone3()` | Podman/crun | Kernel process table isolation | **Yes** -- namespace persists with process |
| cgroup limits | puzzled writes to cgroup fs | Podman (via `--memory`, `--cpus`, etc.) | Kernel scheduler + OOM killer | **Yes** -- cgroup persists independently |
| Mount namespace | puzzled creates via `clone3()` | Podman/crun | Kernel VFS layer | **Yes** -- namespace persists with process |

This is categorically different from application-level guardrails (prompt engineering, SDK permission lists) where the agent process could bypass the check by calling the underlying syscall directly. **Containment is kernel-enforced and agent-irrevocable; governance (OPA/Rego policy evaluation, commit approval) is userspace logic within `puzzled`.**

### 1.3 Architectural Decision: Userspace-First

After detailed analysis, PuzzlePod adopts a **userspace-first architecture**. All security containment uses existing, unmodified kernel primitives. All new code runs in userspace. No kernel modifications are required for the core product.

#### What Existing Kernel Primitives Provide

Existing kernel primitives provide approximately **85-90%** of the required functionality without any kernel changes:

| Capability | Achievable without kernel changes? | How |
|---|---|---|
| Process isolation | Yes | PID namespace, mount namespace, network namespace (via `clone3`/`unshare`) |
| Filesystem access control | Yes | Landlock (unprivileged, self-applied) + SELinux (label-based) |
| Resource limits | Yes | cgroups v2 (cpu, memory, io, pids controllers) |
| Syscall filtering | Yes | Seccomp-BPF |
| CoW filesystem layer | Partially | OverlayFS provides CoW, but without lifecycle management |
| Agent lifecycle management | Yes | Userspace daemon manages process lifecycle via PID namespace |
| Policy evaluation | Yes | OPA/Rego in userspace (this is where policy belongs) |
| Telemetry and audit | Mostly | eBPF, cgroup stats, fanotify, audit subsystem |
| Network filtering | Mostly | nftables per-namespace, eBPF for deeper inspection |

#### Remaining Gaps and Userspace Mitigations

The remaining ~10-15% consists of transactional filesystem optimizations, not security gaps:

| Gap | Severity | Userspace Mitigation |
|---|---|---|
| OverlayFS copy-up artifacts in diff | Low-medium | Checksum comparison between upper and lower layers filters false positives (~5-15% false-positive rate) |
| Non-atomic multi-file commit | Medium | Write-ahead journal (WAL) in puzzled -- same approach as SQLite, PostgreSQL, RPM |
| O(n) diff at scale (large upper layers) | Low for typical workloads | fanotify-based real-time change tracking; upper-layer walk is <1s for 1,000 files on SSD |
| Orphaned upper layer on daemon crash | Low | systemd `ExecStopPost=` cleanup + puzzled startup scan for orphaned branches |
| Lifecycle management across multiple resources | Low-medium | puzzled tracks pidfd + cgroup path + overlay mount per agent; `clone3()` creates namespaces atomically |

**None of these gaps affect the security containment model.** Security enforcement is fully provided by existing kernel primitives. The gaps are in operational efficiency and crash resilience -- both addressable in userspace with well-understood techniques.

#### Enforcement vs. Policy Separation

| Concern | Where it lives | Mechanism |
|---|---|---|
| "Should this agent be allowed to read `/etc/passwd`?" | **Userspace** -- puzzled determines policy | Agent profile YAML -> Landlock ruleset construction |
| "Block this agent from reading `/etc/passwd`" | **Kernel** -- Landlock denies access | Landlock hierarchy-based rule (irrevocable, self-applied) |
| "Should this changeset be committed?" | **Userspace** -- puzzled evaluates governance policy | OPA/Rego rule evaluates changeset manifest |
| "Merge these files into the base filesystem" | **Userspace** -- puzzled performs merge | Write-ahead journal + per-file rename + fsync |
| "Has this agent exceeded its resource budget?" | **Kernel** -- cgroup/XFS enforces limit | `memory.max`, `pids.max`, XFS `bhard`/`ihard` |
| "What should the resource budget be?" | **Userspace** -- puzzled sets limits from profile | Profile YAML -> cgroup write + XFS quota set |
| "Has this agent exceeded its exec budget?" | **Kernel** -- BPF LSM denies | BPF program on `bprm_check_security`, counter in BPF map |

### 1.4 Execution Model: Fork, Explore, Commit

#### Direct Mode

```
1. Agent Registration
   Agent process -> puzzled -> D-Bus registration
   puzzled assigns: agent_id, policy_profile, resource_budget

2. Branch Creation (Fork)
   puzzled -> clone3(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC
                   | CLONE_NEWUTS | CLONE_NEWCGROUP | CLONE_PIDFD)
   -> child PID 1 in new PID namespace
   puzzled gets pidfd for race-free monitoring
   Sets up: OverlayFS mount, Landlock ruleset, seccomp-BPF filter,
            cgroup scope, BPF LSM hooks, fanotify marks
   Network namespace joined via setns() into pre-created named netns

3. Agent Execution (Explore)
   Agent reads/writes files -> CoW to OverlayFS upper layer
   Agent executes commands -> confined by Landlock + BPF LSM + SELinux
   Agent network calls -> filtered by nftables + HTTP proxy in net ns
   All writes captured in upper layer; base filesystem untouched
   puzzled monitors: pidfd (exit), cgroup events (OOM), fanotify

4. Governance Check (Pre-Commit)
   puzzled freezes agent cgroup (cgroup.freeze -> eliminates TOCTOU)
   puzzled walks OverlayFS upper layer, filters copy-up via checksums
   puzzled -> OPA/Rego policy engine evaluates changeset
   Policy checks:
     - File paths within allowed scope?
     - No sensitive files modified (credentials, system config)?
     - No persistence mechanisms installed?
     - Total change size within limits?
     - No executable permission changes?

5a. Commit (Success Path)
    puzzled writes commit journal (WAL) for crash recovery
    puzzled merges upper layer into base (per-file rename, fsync)
    puzzled generates IMA-signed changeset manifest
    Audit event logged
    Upper layer directory removed, cgroup/namespaces freed

5b. Rollback (Failure/Rejection Path)
    puzzled discards upper layer directory (rm -rf)
    puzzled logs audit event with rejection reason
    Killing PID 1 of PID namespace -> kernel kills all agent processes
    cgroup freed when empty, mount/network namespaces freed on last exit
    Base filesystem completely untouched
```

#### Podman-Native Mode (Proposed)

1. **Fork:** `puzzle-podman` wrapper calls puzzled (D-Bus) to create branch (OverlayFS upper layer), generate seccomp profile (with `SCMP_ACT_NOTIFY` + `listenerPath`), and generate Landlock rules file. Then runs `podman run` with the branch merged dir as a bind mount, the seccomp profile, the `puzzle-init` shim as entrypoint, and `run.oci.handler=puzzlepod` annotation. crun creates the container, loads the seccomp filter, and sends the notification fd to puzzled via the `listenerPath` socket. The `puzzle-init` shim applies Landlock (`landlock_restrict_self()`) then execs the real command.

2. **Explore:** Identical to direct mode -- same kernel enforcement primitives, same governance.

3. **Commit/Rollback:** On container exit, the OCI `poststop` hook triggers `puzzle-hook`, which calls puzzled to run governance (freeze -> diff -> OPA evaluate -> commit/rollback). Same WAL-based crash-safe commit.

---

## 2. Kernel Primitives

PuzzlePod composes the following existing, unmodified kernel primitives into a purpose-built containment environment for agentic workloads:

| Primitive | Kernel Version | Function in PuzzlePod |
|---|---|---|
| **Landlock LSM** | 5.13+ (ABI v4: 6.7+) | Unprivileged, irrevocable filesystem + network ACL per agent. Primary enforcement layer. |
| **BPF LSM** | 5.7+ | Programmable per-cgroup security hooks for exec counting and rate limiting. |
| **seccomp-BPF** | 3.5+ (USER_NOTIF: 5.0+) | Static deny for escape-vector syscalls + dynamic daemon-mediated gating for execve/connect/bind. |
| **PID namespaces** | 3.8+ | Process isolation. Kill PID 1 = kernel kills all processes in namespace. |
| **Mount namespaces** | 2.4.19+ | Per-agent filesystem view. OverlayFS branch mounted inside. |
| **Network namespaces** | 2.6.29+ | Per-agent network isolation with nftables rules. |
| **cgroups v2** | 4.5+ | Resource limits: CPU, memory, I/O, PIDs per agent. |
| **cgroup.freeze** | 5.2+ | Freeze agent process tree for TOCTOU-free diff reading. |
| **OverlayFS** | 3.18+ | Copy-on-write filesystem branching. Captures all agent writes in upper layer. |
| **XFS project quotas** | 3.0+ | Per-branch storage and inode limits on upper layer. Kernel-enforced `ENOSPC`. |
| **pidfd** | 5.3+ | Race-free process lifecycle management. Pollable via epoll. |
| **clone3()** | 5.3+ | Modern process creation with namespace flags. Atomic multi-namespace setup. |
| **fanotify** | 2.6.37+ (FID: 5.1+) | Real-time file access monitoring + behavioral triggers. |
| **Linux Audit** | 2.6+ | Security event logging for all governance actions. |
| **IMA** | 2.6.30+ | Integrity measurement for changeset signing. Ed25519 manifest signatures. |
| **SELinux** | 2.6+ | Mandatory label-based access control. `puzzlepod_t` domain for daemon, `puzzlepod_agent_t` for agents. |

**Minimum kernel requirement:** 6.7+ for Landlock ABI v4 (network restrictions). All features are upstream and available in RHEL 10+ and Fedora 42+ kernels.

**Landlock ABI versioning:**

| ABI Version | Kernel | Features Used |
|---|---|---|
| v1 | 5.13+ | Filesystem access control (base) |
| v2 | 5.19+ | `LANDLOCK_ACCESS_FS_REFER` (cross-directory renames) |
| v3 | 6.2+ | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| v4 | 6.7+ | `LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP` |
| v5 | 6.10+ | `LANDLOCK_ACCESS_FS_IOCTL_DEV` |
| v6 | 6.12+ | Signal + abstract Unix socket scoping |

---

## 3. Core Containment Architecture

### 3.1 Branch Context -- Agent Sandboxing

The Branch Context is the unifying abstraction. It binds namespace isolation, cgroup resource limits, filesystem branching, seccomp syscall filtering, and mandatory access control into a single managed sandbox orchestrated by puzzled using existing kernel primitives.

#### Privilege Model

Agents never hold elevated privileges. puzzled orchestrates all privileged operations:

```
puzzled (root / CAP_SYS_ADMIN)                 Agent process (unprivileged)
        |                                              |
        |  1. clone3(CLONE_NEWPID | CLONE_NEWNS        |
        |          | CLONE_NEWNET) -> child pidfd        |
        |  2. Creates cgroup scope under puzzle.slice    |
        |  3. Mounts OverlayFS in mount namespace       |
        |  4. Sets XFS project quota on upper layer     |
        |  5. Configures nftables in network namespace  |
        |  6. Loads BPF LSM programs for cgroup         |
        |  7. Prepares Landlock ruleset                 |
        |  8. Prepares seccomp-BPF filter               |
        |           |                                   |
        |  9. Agent child process (PID 1 in new NS):    |
        |      a. Self-applies Landlock ruleset         |
        |         (unprivileged, irrevocable)            |
        |      b. Installs seccomp-BPF filter           |
        |      c. PR_SET_NO_NEW_PRIVS                   |
        |      d. SELinux transition -> puzzlepod_agent_t  |
        |      e. Drops all capabilities                |
        |      f. execve() agent binary                 |
        |                                               |
        |  10. puzzled monitors via pidfd_send_signal()  |
        |      + cgroup events + timer                  |
```

#### Branch Context Diagram

```
                      puzzled CreateBranch()
                               |
                               v
                +---------------------------------+
                |  Branch Context (puzzled state)  |
                |                                 |
                |  +---------------------------+  |
                |  |    PID Namespace           |  |
                |  |  - Agent is PID 1          |  |
                |  |  - All children confined   |  |
                |  |  - Kill PID 1 = kill all   |  |
                |  +---------------------------+  |
                |                                 |
                |  +---------------------------+  |
                |  |    Mount Namespace         |  |
                |  |  - OverlayFS branch mount  |  |
                |  |  - Masked paths            |  |
                |  |  - Read-only /usr, /lib    |  |
                |  +---------------------------+  |
                |                                 |
                |  +---------------------------+  |
                |  |    Network Namespace       |  |
                |  |  - Isolated network        |  |
                |  |  - Side-effect gating      |  |
                |  |  - nftables rules loaded   |  |
                |  +---------------------------+  |
                |                                 |
                |  +---------------------------+  |
                |  |    cgroup Scope            |  |
                |  |  - CPU / memory / IO       |  |
                |  |  - Branch storage quota    |  |
                |  |  - PID limit               |  |
                |  +---------------------------+  |
                |                                 |
                |  +---------------------------+  |
                |  |    Seccomp-BPF Filter      |  |
                |  |  - Escape vector deny      |  |
                |  |  - USER_NOTIF for execve   |  |
                |  +---------------------------+  |
                |                                 |
                |  +---------------------------+  |
                |  |    Landlock Ruleset        |  |
                |  |  - Unprivileged FS ACL     |  |
                |  |  - Network port restrict   |  |
                |  |  - Irrevocable             |  |
                |  +---------------------------+  |
                |                                 |
                |  +---------------------------+  |
                |  |    BPF LSM + SELinux       |  |
                |  |  - Exec counting           |  |
                |  |  - Rate limiting           |  |
                |  |  - Label-based MAC         |  |
                |  +---------------------------+  |
                |                                 |
                |  +---------------------------+  |
                |  |    OverlayFS Branch        |  |
                |  |  - CoW upper layer         |  |
                |  |  - XFS quota enforcement   |  |
                |  +---------------------------+  |
                |                                 |
                +---------------------------------+
```

#### Lifecycle State Machine

```
                 puzzled CreateBranch()
                          |
                          v
                    +-----------+
                    |  CREATED  |
                    +-----------+
                          | Agent process forked
                          v
                    +-----------+
                    |  RUNNING  |<--------------------+
                    |           |                     |
                    +--+--+--+--+                     |
               PID 1   |  |  |  Lifetime /            |
               exits   |  |  |  quota exceeded        |
                       |  |  |                        |
          +------------+  |  +--------+               |
          v               |           v               |
   +------------+         |    +------------+         |
   |  EXITED    |         |    | TERMINATED |         |
   +------+-----+         |    +------+-----+         |
          |               |           |               |
          v               |           v               |
   +------------+         |    +------------+         |
   | GOVERNANCE |----+----+-->| ROLLED     |         |
   | REVIEW     |    |        | BACK       |         |
   |            |reject       +------------+         |
   | Changeset  |                                    |
   | evaluated  +----retry---------------------------+
   +------+-----+
          |
          | approve
          v
   +------------+
   | COMMITTED  |
   +------------+
```

**State transition guarantees:**

| Transition | Trigger | Guarantee |
|---|---|---|
| CREATED -> RUNNING | Agent process exec'd into context | All isolation mechanisms active before agent code runs |
| RUNNING -> EXITED | Agent PID 1 exits with code 0 | All child processes also terminated (PID namespace teardown) |
| RUNNING -> TERMINATED | Lifetime, quota, or OOM exceeded | SIGKILL sent to all processes; no graceful shutdown |
| EXITED -> GOVERNANCE REVIEW | Automatic | Changeset is frozen; no further writes possible |
| GOVERNANCE REVIEW -> COMMITTED | Policy engine approves | WAL-protected merge to base filesystem; audit event with signed manifest |
| GOVERNANCE REVIEW -> ROLLED BACK | Policy engine rejects, or timeout | All changes discarded; base filesystem untouched |
| GOVERNANCE REVIEW -> RUNNING | FailSilent/FailOperational recovery | Agent thawed and returned to running state for retry |
| TERMINATED -> ROLLED BACK | Always | No governance review for terminated contexts; immediate cleanup |
| Any -> ROLLED BACK | puzzled crash or exit | Fail-closed: branches rolled back on restart |

#### Sibling Branch Isolation

| Resource | Isolation Mechanism | Guarantee |
|---|---|---|
| Process visibility | Separate PID namespaces | Agent A cannot see Agent B's PIDs |
| Process signaling | PID namespace boundary | Agent A cannot signal Agent B's processes |
| Filesystem | Separate mount namespaces + separate OverlayFS branches | Agent A cannot read/write Agent B's branch |
| Network | Separate network namespaces | Agent A cannot connect to Agent B's network |
| IPC (SysV shared memory, message queues) | Separate IPC namespaces | Agent A cannot access Agent B's IPC objects |
| Unix domain sockets | Separate mount + network namespaces | Agent A cannot connect to Agent B's sockets |
| Shared memory (`/dev/shm`) | Per-context tmpfs mount | Agent A has its own `/dev/shm` |
| Temporary files (`/tmp`) | Per-context tmpfs mount | Agent A has its own `/tmp` |
| CPU/memory resources | Separate cgroup scopes | Agent A's resource usage cannot starve Agent B |

#### Core Data Structures

```rust
/// Branch Context object managed by puzzled (Rust representation)
pub struct BranchContext {
    /// Unique identifier
    id: Uuid,
    /// State machine
    state: AtomicU32,  // BranchState enum
    /// Owning puzzled PID (for lifecycle binding)
    owner_pid: Pid,
    /// PID namespace
    pid_ns: Arc<PidNamespace>,
    /// Mount namespace (contains OverlayFS branch overlay)
    mnt_ns: Arc<MountNamespace>,
    /// Network namespace (with gating rules)
    net_ns: Arc<NetNamespace>,
    /// cgroup scope (/sys/fs/cgroup/puzzle.slice/agent-{id}.scope)
    cgroup: Arc<CgroupScope>,
    /// OverlayFS branch (CoW upper layer + change tracker)
    branch: Arc<OverlayBranch>,
    /// BPF LSM + Landlock policy binding
    security_ctx: Arc<SecurityContext>,
    /// Seccomp-BPF filter (shared, immutable once loaded)
    seccomp: Arc<SeccompFilter>,
    /// Landlock ruleset descriptor (self-applied by agent, irrevocable)
    landlock_ruleset: Option<Arc<LandlockRuleset>>,
    /// Configuration snapshot (immutable after creation)
    config: BranchContextConfig,
    /// Creation timestamp
    created_at: Ktime,
    /// Audit trail reference
    audit_serial: u64,
}

/// Per-branch state tracked by puzzled
struct Branch {
    branch_id: Uuid,
    agent_pidfd: OwnedFd,          // pidfd for agent PID 1
    agent_uid: u32,                // UID assigned to agent
    cgroup_path: PathBuf,          // /sys/fs/cgroup/puzzle.slice/agent-{id}.scope
    overlay_upper: PathBuf,        // Upper layer directory
    overlay_work: PathBuf,         // Work directory
    overlay_merged: PathBuf,       // Merged mount point (visible to agent)
    base_path: PathBuf,            // Base filesystem
    state: BranchState,            // Creating, Active, Frozen, Committing, ...
    profile: AgentProfile,         // Loaded profile configuration
    created_at: SystemTime,
    expires_at: SystemTime,        // Automatic rollback deadline
    wal: WriteAheadLog,            // WAL for crash-safe commit
}
```

### 3.2 Transactional Filesystem Branching

#### Branch Storage Architecture

Each branch consists of:

```
/var/lib/puzzled/branches/{branch_id}/
+-- upper/          # Writable CoW layer (OverlayFS upperdir)
+-- work/           # OverlayFS workdir (required by OverlayFS internals)
+-- metadata.json   # Branch metadata (agent_id, policy, creation time, pid)
+-- manifest        # Auto-maintained list of modified inodes
```

The agent's mount namespace is configured so the agent sees:

```
Agent's view:       overlay(lower=base_fs, upper=branch_upper, work=branch_work)
Host's view:        base_fs (unchanged) + /var/lib/puzzled/branches/{id}/upper (diff)
```

#### Diff Generation

```
diff_branch(branch):
  1. Freeze agent processes via cgroup.freeze (eliminates TOCTOU)
  2. Walk upper layer directory recursively
  3. For each file in upper layer:
     a. If file does NOT exist in base layer -> CREATED
     b. If file exists in base layer:
        - Compare checksums (SHA-256 of content + metadata)
        - If checksums differ -> MODIFIED (intentional agent write)
        - If checksums match -> COPY-UP ARTIFACT (filter out)
     c. If whiteout file (OverlayFS convention) -> DELETED
     d. If redirect xattr present -> RENAMED
  4. Generate changeset manifest (JSON) with all changes
  5. Thaw agent processes (or keep frozen for commit)
```

**Changeset record:**

```rust
/// Per-file change record in the changeset manifest
struct Change {
    path: PathBuf,
    change_type: ChangeType,  // Created, Modified, Deleted, Renamed, PermissionChanged
    old_size: Option<u64>,
    new_size: u64,
    old_mode: Option<u32>,
    new_mode: u32,
    checksum: [u8; 32],       // SHA-256 of file content
    timestamp: SystemTime,
}
```

#### Conflict Detection

When multiple agents operate on branches of the same base filesystem:

| Strategy | Behavior | Use Case |
|---|---|---|
| `reject` | Reject commit; return conflict to puzzled | Default. Safety-first. |
| `last-writer-wins` | Overwrite with latest branch's version | Low-risk, non-critical files |
| `merge-if-text` | Attempt 3-way merge for text files; reject for binary | Source code modifications |
| `scope-partition` | Prevent conflict by assigning non-overlapping path scopes | Recommended for multi-agent |

#### Crash-Safe Commit (Write-Ahead Journal)

```
commit_branch(branch_id):
  1. Freeze agent processes via cgroup.freeze
  2. Set state = REVIEWING
  3. Generate changeset manifest (diff with checksum filtering)
  4. Evaluate OPA/Rego governance policy against manifest
  5. If policy rejects: set state = ROLLED_BACK, discard upper layer
  6. If policy approves:
     a. Run conflict detection against recently committed branches
     b. If conflicts: return conflict details to governance policy
     c. If no conflicts:
        -- WAL Phase: Log intended operations --
        d. Write WAL entry to /var/lib/puzzled/branches/{id}/wal.json
        e. fsync WAL file

        -- Execute Phase: Apply changes --
        f. For each CREATED file: copy from upper to staging directory
        g. For each MODIFIED file: copy from upper to staging directory
        h. For each DELETED file: record in staging manifest
        i. Rename staging directory into base (atomic per-directory)
        j. Apply deletes and renames in base
        k. fsync base filesystem

        -- Complete Phase: Mark done --
        l. Write completion marker to WAL
        m. Set state = COMMITTED
        n. Generate audit event with IMA-signed manifest
        o. Schedule upper layer cleanup (async)
  7. On timeout: set state = ROLLED_BACK, discard upper layer
```

**Crash recovery:** On startup, puzzled scans `/var/lib/puzzled/branches/` for incomplete WAL files. If a WAL exists without a completion marker, the commit was interrupted -- puzzled rolls back any partial changes. If a completion marker exists but cleanup was not finished, puzzled completes the cleanup. This guarantees zero partial commits.

### 3.3 Containment Profiles and Access Control

Agent containment profiles are defined as YAML files loaded by puzzled:

```yaml
# /etc/puzzled/profiles/code-assistant.yaml
name: code-assistant
description: Profile for code assistant agents
extends: standard              # optional, inherit from parent profile

filesystem:
  read_allowlist:
    - /home/{{user}}/projects/{{project}}
    - /usr/lib
    - /usr/share
    - /etc/localtime
    - /etc/resolv.conf
    - /proc/self
    - /dev/null
    - /dev/urandom

  read_denylist:
    - /home/{{user}}/.ssh
    - /home/{{user}}/.gnupg
    - /home/{{user}}/.aws
    - /etc/shadow
    - /etc/gshadow

  write_allowlist:
    - /home/{{user}}/projects/{{project}}
    - /tmp/agent-{{agent_id}}

  write_denylist:
    - /etc
    - /usr

  denylist:
    - /etc/shadow
    - /etc/gshadow
    - /etc/ssh

exec_allowlist:
  - /usr/bin/python3
  - /usr/bin/node
  - /usr/bin/git
  - /usr/bin/grep
  - /usr/bin/make
  - /usr/bin/cargo
  - /usr/bin/curl       # Allowed but network-gated

exec_denylist:
  - nsenter
  - unshare
  - chroot
  - mount
  - strace
  - gdb
  - su
  - sudo

resource_limits:
  memory_bytes: 536870912
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000

network:
  mode: Gated            # Blocked, Gated, Monitored, Unrestricted
  allowed_domains: []

behavioral:
  max_deletions: 50
  max_reads_per_minute: 1000
  credential_access_alert: true

fail_mode: FailClosed    # FailClosed, FailSilent, FailOperational, FailSafeState
seccomp_mode: Permissive # Permissive, Strict
allow_symlinks: false
```

**Profile inheritance:** When `extends` is specified, the child profile inherits all fields from the named parent. Child scalar fields always override. Vec fields (e.g., `exec_allowlist`, `read_allowlist`, `write_denylist`) inherit the parent's values when the child's list is empty; a non-empty child list fully replaces the parent's. Inheritance depth is bounded at 3 levels. Circular inheritance is detected and rejected at profile load time. **Note:** Scalar security fields (`fail_mode`, `seccomp_mode`, `allow_symlinks`, `allow_exec_overlay`) use serde defaults when omitted in a child profile, not the parent's values — always set these explicitly.

#### Enforcement Architecture

```
Agent file/exec/network request
       |
       v
  +--------------+     Deny     +---------+
  | Landlock     |--------------|  EACCES |  Layer 1: Path-based ACL
  | (kernel,     |              +---------+  (irrevocable, survives puzzled crash)
  |  per-process)|
  +------+-------+
         | Allow
         v
  +--------------+     Deny     +---------+
  | SELinux      |--------------|  EACCES |  Layer 2: Label-based MAC
  | (kernel,     |              +---------+  (system-wide, puzzlepod_agent_t domain)
  |  system-wide)|
  +------+-------+
         | Allow
         v
  +--------------+     Deny     +---------+
  | BPF LSM      |--------------|  EPERM  |  Layer 3: Programmable hooks
  | (kernel,     |              +---------+  (per-cgroup exec counting,
  |  per-cgroup) |                            rate limiting)
  +------+-------+
         | Allow
         v
  +--------------+
  |   ALLOWED    |
  +--------------+
```

### 3.4 Resource Management

All agents run under `puzzle.slice` using standard cgroup v2 controllers:

```
/sys/fs/cgroup/
+-- puzzle.slice/                          # Slice for all agent workloads
    +-- cpu.max                           # Collective CPU budget
    +-- memory.max                        # Collective memory limit
    +-- agent-abc123.scope/               # Scope for agent abc123
    |   +-- cgroup.controllers            # cpu memory io pids
    |   +-- cpu.max                       # CPU budget (e.g., "100000 100000")
    |   +-- cpu.weight                    # CPU share
    |   +-- memory.max                    # Memory hard limit (e.g., 2G)
    |   +-- memory.high                   # Memory throttle point
    |   +-- memory.events                 # OOM event notifications
    |   +-- io.max                        # I/O bandwidth limit
    |   +-- pids.max                      # PID limit (fork bomb prevention)
    |   +-- cgroup.freeze                 # Freeze agent for TOCTOU-free diff
    +-- agent-def456.scope/
        +-- ...
```

**Resource limits NOT in cgroup** (handled by other mechanisms):

| Resource | Mechanism | Location |
|---|---|---|
| Branch storage (bytes) | XFS project quota `bhard` on upper layer | Kernel VFS |
| Branch inodes (files) | XFS project quota `ihard` on upper layer | Kernel VFS |
| Branch lifetime | puzzled timer or systemd `RuntimeMaxSec=` | Userspace |
| Exec count | BPF LSM on `bprm_check_security` with per-cgroup BPF map | eBPF |
| Network egress | nftables byte counters in per-agent network namespace | Kernel netfilter |

**Quota enforcement defaults:**

| Quota | Default | Range | Enforcement |
|---|---|---|---|
| Storage (bytes written) | 1 GB | 1 MB -- 100 GB | XFS project quota `bhard`. `write()` returns `ENOSPC`. |
| Inodes (files created) | 10,000 | 100 -- 1,000,000 | XFS project quota `ihard`. `creat()` returns `ENOSPC`. |
| Branch lifetime | 1 hour | 1 min -- 24 hours | puzzled timer. Triggers auto-rollback. |
| Max processes | 64 | 8 -- 1,024 | cgroup `pids.max`. Prevents fork bombs. |
| Max exec() calls | 100 | 10 -- 10,000 | BPF LSM on `bprm_check_security`. |

### 3.5 Network Side-Effect Gating

Network operations are the primary class of side effects that cannot be rolled back. The network gating layer gates operations based on side-effect risk.

| Mode | Behavior | Use Case |
|---|---|---|
| `blocked` | All network access denied | Maximum security; offline agents |
| `gated` | GET/HEAD/OPTIONS allowed; POST/PUT/DELETE/PATCH queued for commit-time replay | Default. Balances utility with safety |
| `monitored` | All operations allowed but logged with full request/response capture | Debugging, low-risk environments |
| `unrestricted` | Standard network access; no gating | Trusted agents (not recommended) |

**Implementation:** The `puzzle-proxy` crate (Rust, async, tokio + hyper) runs a lightweight HTTP proxy inside each agent's network namespace. GET/HEAD requests are forwarded if domain is in allowlist. POST/PUT/DELETE/PATCH requests are serialized to a network journal on disk for replay at commit time. The agent's environment receives `HTTP_PROXY`/`HTTPS_PROXY` pointing to the in-namespace proxy endpoint.

**Network journal storage:**

```
/var/lib/puzzled/branches/{branch_id}/network_journal/
  000001.json    # Serialized HTTP request (method, URI, headers, base64 body, timestamp)
  000002.json
```

### 3.6 Seccomp Split Strategy

Syscalls are split into two tiers to avoid unnecessary overhead:

| Tier | Mechanism | Latency | Used For |
|---|---|---|---|
| **High-frequency, static policy** | Landlock (in-kernel) | < 1 us | `open`, `read`, `write`, `stat` |
| **Low-frequency, dynamic policy** | seccomp `SECCOMP_RET_USER_NOTIF` | ~50-100 us | `execve`, `connect`, `bind` |
| **Monitoring only** | fanotify (async) | Zero agent impact | File access patterns, behavioral triggers |

**Blocked syscalls (escape vectors -- static deny via `SECCOMP_RET_KILL_PROCESS`):**

| Syscall | Reason |
|---|---|
| `clone3` / `unshare` with namespace flags | Prevents creating nested namespaces to escape containment |
| `mount` / `umount2` | Prevents remounting filesystems to bypass OverlayFS |
| `pivot_root` / `chroot` | Prevents filesystem root manipulation |
| `ptrace` | Prevents tracing/debugging other processes |
| `process_vm_readv` / `process_vm_writev` | Prevents cross-process memory access |
| `keyctl` | Prevents kernel keyring manipulation |
| `bpf` | Prevents loading BPF programs |
| `perf_event_open` | Prevents performance counter access (side-channel attacks) |
| `init_module` / `finit_module` / `delete_module` | Prevents kernel module loading |
| `kexec_load` / `kexec_file_load` | Prevents kernel replacement |
| `reboot` | Prevents system reboot |
| `memfd_create` | Prevents anonymous memory execution bypass |
| `io_uring_setup` / `io_uring_enter` / `io_uring_register` | Prevents io_uring bypass |

**Daemon-mediated syscalls (dynamic gating via `SECCOMP_RET_USER_NOTIF`):**

| Syscall | Why Intercepted | Daemon Action |
|---|---|---|
| `execve` / `execveat` | Control what binaries the agent can run | Check binary path against profile `exec_allow` list; increment exec counter; TOCTOU-safe via SECCOMP_ADDFD |
| `connect` | Gate outbound network connections | Check destination against domain allowlist; log connection |
| `bind` | Prevent agent from listening on ports | Deny unless explicitly allowed in profile |

---

## 4. Defense-in-Depth

Every escape vector is blocked by at least two independent mechanisms:

| Layer | Mechanism | What It Enforces | Configured by | Survives puzzled crash? |
|---|---|---|---|---|
| 0 | **Landlock** (5.13+) | Irrevocable filesystem + TCP network ACL | puzzled / puzzle-init | **Yes** -- attached to process |
| 1 | **seccomp-BPF** (3.5+ / 5.0+) | Syscall filtering (static deny + USER_NOTIF) | puzzled / crun | **Yes** -- irrevocable; USER_NOTIF returns ENOSYS if puzzled crashes |
| 2 | **PID namespace** (3.8+) | Process isolation, reliable termination | puzzled (`clone3`) / Podman | **Yes** |
| 3 | **Mount namespace** (2.4.19+) | Filesystem view isolation | puzzled (`clone3`) / Podman | **Yes** |
| 4 | **Network namespace** (2.6.29+) | Network isolation | puzzled (`setns`) / Podman | **Yes** |
| 5 | **cgroups v2** (4.5+) | CPU, memory, I/O, PID limits | puzzled / Podman | **Yes** |
| 6 | **SELinux** (2.6+) | Label-based MAC (`puzzlepod_agent_t` domain) | puzzled / Podman | **Yes** |
| 7 | **BPF LSM** (5.7+) | Programmable per-cgroup hooks | puzzled (via OCI hook) | **Yes** |
| 8 | **User namespace** (3.8+) | UID mapping (rootless mode) | Podman | **Yes** |

**Escape vector analysis:**

| Escape Vector | Mitigation | Residual Risk |
|---|---|---|
| `setsid()` to escape process group | PID namespace makes `setsid()` harmless | None -- kernel-guaranteed |
| `clone(CLONE_NEWPID)` to create nested namespace | Blocked by seccomp-BPF; also requires `CAP_SYS_ADMIN` | None -- two independent blocks |
| `ptrace` sibling agent's processes | Blocked by seccomp-BPF; blocked by PID namespace (can't see sibling PIDs) | None |
| `kill(-1, SIGKILL)` to kill all user's processes | PID namespace limits visible PIDs | None -- kernel-guaranteed |
| Mount manipulation to escape overlay | `mount`/`umount` blocked by seccomp; no `CAP_SYS_ADMIN` | None |
| Exploit setuid binary for privilege escalation | `PR_SET_NO_NEW_PRIVS`; empty capability bounding set; nosuid mount | None -- three independent blocks |
| Cross-context communication via shared `/tmp` | Per-context tmpfs mount | None |
| File access outside branch via path traversal | Landlock + BPF LSM + mount namespace | None -- three independent layers |
| Network connection to unauthorized port | Landlock + nftables + network namespace | None -- three independent layers |

**Threat mitigation matrix:**

| Threat | Landlock | LSM | Branch | Governance | Network | cgroups |
|---|---|---|---|---|---|---|
| T1: Hallucinating Agent | Restricts FS scope | Limits paths | Isolates writes | Reviews changes | N/A | Limits resources |
| T2: Prompt Injection | Blocks unauthorized exec/net | Blocks dangerous commands | Contains damage | Detects suspicious changes | Blocks exfiltration | N/A |
| T3: Goal Drift | Restricts FS scope | Limits capabilities | Contains scope | Detects out-of-scope changes | Limits reach | Limits resources |
| T4: Credential Exfiltration | Blocks credential paths | Blocks credential files | N/A | N/A | Blocks outbound data | N/A |
| T5: Resource Exhaustion | N/A | Limits process count | Branch quotas | N/A | Egress limits | CPU/memory/IO limits |
| T6: Colluding Agents | Per-process irrevocable | Per-agent policy | Separate branches | Independent evaluation | Per-agent network NS | Per-agent cgroup |
| T7: Supply Chain Injection | Exec allowlisting | Per-cgroup exec control | Contains poisoned tool | Content scanning | Domain filtering | N/A |

---

## 5. Userspace Components

### 5.1 puzzled -- Governance Daemon

**Location:** `crates/puzzled/`

Central governance daemon managing OverlayFS branching, policy evaluation, and audit. Runs as root (system instance) or as a regular user (user instance for rootless mode).

**Process architecture:**

```
puzzled (runs as root or user)
+-- Main thread: D-Bus listener + agent registration
+-- Seccomp listener: Unix socket for crun notif fd (Podman-native)
+-- Seccomp thread: Per-branch seccomp notification fd polling (epoll)
+-- Fanotify thread: Per-branch fanotify fd polling (epoll); behavioral triggers
+-- Policy thread: OPA evaluation engine (pooled)
+-- Watchdog thread: Heartbeat monitoring + timeout enforcement
+-- Cleanup thread: Branch garbage collection + journal recovery
+-- Audit thread: Event serialization + signing
```

**Configuration:**

- System instance: `/etc/puzzled/puzzled.conf`
- User instance (rootless): `~/.config/puzzled/puzzled.conf` (or `$XDG_CONFIG_HOME/puzzled/puzzled.conf`)
- CLI override: `puzzled --config <path>`
- Auto-detection: `DaemonConfig::load_or_default()` checks system path first, then user config for non-root users, then falls back to defaults

**Hardening:** Minimal capabilities, SELinux-confined (`puzzlepod_t`), seccomp-BPF (configurable per-profile), no external network access.

**Fail-closed behavior:** If puzzled crashes during governance evaluation, pending commits are rolled back on restart. Landlock restrictions on agent processes survive (kernel-enforced, independent). systemd restarts puzzled; it re-discovers active branches from `/var/lib/puzzled/branches/`.

**Rootless degradation:** When running as a user instance without root, BPF LSM is disabled (requires `CAP_BPF`), fanotify is partial (path-based only), XFS project quotas are unavailable (use `podman --storage-opt size=` instead), and kernel OverlayFS is replaced by fuse-overlayfs (~15-20% I/O overhead). Landlock, seccomp (static deny + USER_NOTIF), OPA policy, and the audit chain work fully.

**fanotify behavioral monitoring:**

puzzled uses fanotify (`FAN_REPORT_FID | FAN_REPORT_NAME`) for real-time filesystem event monitoring:

| Counter | Trigger | Used For |
|---|---|---|
| `files_opened` | `FAN_OPEN` | Behavioral monitoring; rate limiting |
| `files_created` | `FAN_CREATE` | Quota enforcement; anomaly detection |
| `files_modified` | `FAN_CLOSE_WRITE` | Changeset pre-computation |
| `files_deleted` | `FAN_DELETE` | Destructive action detection |
| `files_renamed` | `FAN_MOVED_FROM`/`FAN_MOVED_TO` | Changeset tracking |

Behavioral triggers per-profile:

```yaml
behavioral_policy:
  triggers:
    - name: mass_deletion
      condition: "files_deleted > 50 within 10 seconds"
      action: freeze_branch

    - name: credential_access
      condition: "file_opened matches **/.*secret* or **/.env*"
      action: log_and_alert

    - name: excessive_reads
      condition: "files_opened > 5000"
      action: warn_and_throttle
```

### 5.2 puzzlectl -- CLI Tool

**Location:** `crates/puzzlectl/`

```
puzzlectl -- Agent Guardrail Management Tool

WORKFLOW:
  puzzlectl run --profile=<name> [--base=<dir>] [--auto-commit|--auto-rollback] [--no-diff] -- <command...>

BRANCH MANAGEMENT:
  puzzlectl branch list [--state=active|reviewing|all]
  puzzlectl branch inspect <branch_id>
  puzzlectl branch approve <branch_id>
  puzzlectl branch reject <branch_id> [--reason="..."]
  puzzlectl branch rollback <branch_id> [--reason="..."]
  puzzlectl branch create <branch_id>
  puzzlectl branch diff <branch_id>

AGENT MANAGEMENT:
  puzzlectl agent list
  puzzlectl agent info <agent_id>
  puzzlectl agent kill <agent_id>

PROFILE MANAGEMENT:
  puzzlectl profile list
  puzzlectl profile show <profile_name>
  puzzlectl profile validate <profile_file>
  puzzlectl profile test <profile_name> --changeset=<file>
  puzzlectl profile init [--name <name>] [--extends <parent>] [--network-mode <mode>] [--out <file>] [--non-interactive]

POLICY MANAGEMENT:
  puzzlectl policy reload
  puzzlectl policy test <policy_file> --input=<json_file>
  puzzlectl policy add-rule [--deny-path <glob>] [--max-file-size <bytes>] [--deny-extension <exts>] [--max-files <n>] [--severity <level>] [--dry-run]

AUDIT:
  puzzlectl audit list [--agent=<id>] [--since=<timestamp>]
  puzzlectl audit export [--format=json|csv]
  puzzlectl audit verify <changeset_hash>

ATTESTATION:
  puzzlectl attestation export <branch_id> --output bundle.json
  puzzlectl attestation verify bundle.json [--pubkey key.pub]
  puzzlectl attestation inclusion <seq>
  puzzlectl attestation consistency --from <old_size> --to <new_size>
  puzzlectl attestation pubkey

COMPLIANCE:
  puzzlectl compliance report --framework eu-ai-act --period 30d
  puzzlectl compliance status --framework soc2
  puzzlectl compliance gaps --framework eu-ai-act
  puzzlectl compliance frameworks

TRUST:
  puzzlectl trust score <uid>
  puzzlectl trust baseline <uid>
  puzzlectl trust history <uid>
  puzzlectl trust reset <uid> --reason "..."
  puzzlectl trust override <uid> --level <level> --hours <hours>

CREDENTIALS:
  puzzlectl credential add <name>
  puzzlectl credential add <name> --from-env=VAR
  puzzlectl credential add <name> --from-file=path
  puzzlectl credential add <name> --passphrase
  puzzlectl credential list
  puzzlectl credential unlock <name>

AGENT SIMULATOR:
  puzzlectl sim [--run|--run-all|--interactive]

SYSTEM:
  puzzlectl status
  puzzlectl version
  puzzlectl tui
```

**Optional features (Cargo):**

| Feature | Default | Description |
|---|---|---|
| `tui` | yes | Interactive terminal UI (`puzzlectl tui`) |
| `sim` | yes | Agent simulator subcommand and `puzzle-sim-worker` binary |

### 5.3 Podman Integration

**Location:** `podman/` (wrapper), proposed `crates/puzzle-hook/` and `crates/puzzle-init/`

Zero Podman source code changes. All integration via documented, stable extension points:

| Extension Point | How PuzzlePod Uses It | Status |
|---|---|---|
| OCI runtime hooks | Hook fires for containers with branch annotation | Implemented (bash); proposed Rust replacement |
| Container annotations (`--annotation`) | `org.lobstertrap.puzzlepod.branch=ID` carries branch identity | Implemented |
| Bind mounts (`--mount type=bind`) | Branch merged dir at `/workspace` | Implemented |
| Custom seccomp profile (`--security-opt seccomp=`) | OCI profile with `SCMP_ACT_NOTIFY` + `listenerPath` | **Proposed** |
| SELinux labels (`--security-opt label=type:puzzlepod_agent_t`) | SELinux type enforcement | **Proposed** |
| crun `listenerPath` | crun sends seccomp notification fd to puzzled via Unix socket | **Proposed** |

**puzzle-init (proposed):** Static binary bind-mounted into every governed container, running as PID 1 before the agent process. It applies Landlock rules, sets up nftables DNAT for transparent proxy, stacks a second seccomp filter (blocking AF_NETLINK), drops all capabilities, updates CA trust store, then execs the real command. ~500 lines, ~15 KB additional binary size.

### 5.4 systemd Integration

**Location:** `systemd/`

```ini
# /usr/lib/systemd/system/puzzled.service
[Unit]
Description=Agent Governance Daemon
After=dbus.service
Requires=dbus.service

[Service]
Type=notify
ExecStart=/usr/sbin/puzzled
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/lib/puzzled /run/puzzled
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_AUDIT_WRITE CAP_DAC_OVERRIDE
                      CAP_SETUID CAP_SETGID CAP_NET_ADMIN
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

```ini
# /usr/lib/systemd/system/puzzle@.service
[Unit]
Description=Agent Runtime %i
After=puzzled.service
Requires=puzzled.service

[Service]
Type=exec
ExecStartPre=/usr/bin/puzzlectl branch create %i
ExecStart=/usr/libexec/agent-runner --id=%i
ExecStopPost=/usr/bin/puzzlectl branch rollback %i --reason="service-stopped"
Slice=puzzle.slice
Delegate=yes
MemoryMax=2G
CPUQuota=100%
TasksMax=64

[Install]
WantedBy=puzzled.service
```

```ini
# /usr/lib/systemd/system/puzzle.slice
[Unit]
Description=Agent Workload Slice
Before=slices.target

[Slice]
MemoryMax=80%
CPUQuota=400%
TasksMax=1024
IOWeight=50
```

### 5.5 SELinux Policy Module

```
# puzzlepod.te -- SELinux Type Enforcement

policy_module(puzzlepod, 1.0.0)

# Type declarations
type puzzlepod_t;              # Daemon domain
type puzzled_exec_t;           # Daemon executable type
type puzzlepod_agent_t;        # Agent sandbox domain
type puzzlepod_exec_t;         # Agent executable type
type puzzlepod_branch_t;       # Branch filesystem type
type puzzled_var_lib_t;        # Governance data type
type puzzled_policy_t;         # Policy file type
type puzzled_log_t;            # Log file type

# Daemon policy
allow puzzlepod_t self:capability { sys_admin dac_override audit_write
                                    setuid setgid net_admin };
allow puzzlepod_t puzzlepod_agent_t:process { transition signal sigkill };
type_transition puzzlepod_t puzzlepod_exec_t:process puzzlepod_agent_t;

# Agent policy
allow puzzlepod_agent_t puzzlepod_branch_t:dir { read write search add_name remove_name };
allow puzzlepod_agent_t puzzlepod_branch_t:file { read write create unlink rename };

# Neverallow rules (agent sandbox restrictions)
neverallow puzzlepod_agent_t puzzled_var_lib_t:file *;
neverallow puzzlepod_agent_t puzzled_policy_t:file *;
neverallow puzzlepod_agent_t etc_t:file { write append };
neverallow puzzlepod_agent_t usr_t:file { write append };
neverallow puzzlepod_agent_t domain:process ptrace;
neverallow puzzlepod_agent_t self:capability sys_module;
neverallow puzzlepod_agent_t security_t:security *;

# File contexts
# /var/lib/puzzled(/.*)?              puzzled_var_lib_t
# /var/lib/puzzled/branches(/.*)?     puzzlepod_branch_t
# /etc/puzzled(/.*)?                  puzzled_policy_t
# /var/log/puzzled(/.*)?              puzzled_log_t
# /usr/sbin/puzzled                   puzzled_exec_t
```

---

## 6. Tier 1: Regulatory and Liability Capabilities

### 6.1 Cryptographic Attestation of Governance

Every governance-significant event produces a signed attestation record, extending the existing `StoredAuditEvent`:

```rust
pub struct StoredAuditEvent {
    pub seq: u64,                          // Monotonic sequence number
    pub timestamp: String,                 // RFC 3339
    pub event: AuditEventRecord,           // { event_type, branch_id, details }
    pub hmac: Option<String>,              // HMAC-SHA256 chain (backward compat)

    // Attestation fields
    pub record_id: Option<String>,         // UUID v7 (time-ordered)
    pub agent_identity: Option<AgentIdentity>,
    pub policy_version: Option<String>,    // SHA-256 of active policy set
    pub changeset_hash: Option<String>,    // SHA-256 of changeset (commit events)
    pub governance_decision: Option<String>,
    pub parent_record_id: Option<String>,  // Links to preceding record in branch chain
    pub signature: Option<String>,         // Ed25519 (hex) over canonical form
    pub merkle_leaf_index: Option<u64>,    // Position in global Merkle tree
}

pub struct AgentIdentity {
    pub uid: u32,
    pub profile: String,
    pub selinux_context: Option<String>,
    pub framework: Option<String>,
}
```

**Merkle tree audit log:** All attestation records are inserted into a global append-only Merkle tree providing:

1. **Inclusion proof** -- prove a specific record exists without revealing others
2. **Consistency proof** -- prove the log at time T2 is an append-only extension of T1

Tree structure: leaf nodes SHA-256(`0x00` || record_bytes), internal nodes SHA-256(`0x01` || left || right), domain-separated per RFC 6962.

**Signing infrastructure:** Reuses existing Ed25519 via `ed25519_dalek` from `ima.rs`. Both HMAC (internal integrity) and Ed25519 (external verifiability) are present. Key management: `signing_key_path` in config, `check_key_rotation()`, CSPRNG generation via `getrandom`.

**Attestation bundle format:** Self-contained JSON including records, signatures, commit manifest, Merkle inclusion proofs, and public key for offline verification.

### 6.2 Compliance Evidence Generation

Compliance runs entirely in puzzlectl (client-side). Supported frameworks:

| Framework | Key Controls Mapped |
|---|---|
| **EU AI Act** (2024/1689) | Art. 9 risk management, Art. 12 record-keeping, Art. 14 human oversight, Art. 15 cybersecurity |
| **SOC 2 Type II** | CC6.1 logical access, CC6.6 system boundaries, CC7.1-7.3 monitoring, CC8.1 change management |
| **ISO 27001:2022** | A.5.1 policies, A.8.2 privileged access, A.8.16 monitoring, A.8.24 cryptography |
| **NIST AI RMF 1.0** | GOVERN 1, MAP 3, MEASURE 2, MANAGE 1, MANAGE 4 |

Evidence packages are signed with Ed25519 and include raw audit events, profile/policy copies, branch statistics, and attestation chains.

### 6.3 Data Residency and Exfiltration Prevention

DLP content inspection integrates into the existing proxy handler pipeline:

| Inspection Layer | What It Detects |
|---|---|
| URL/domain classification + GeoIP | Unauthorized destinations, out-of-region endpoints |
| Request body inspection | Secrets, API keys, private keys, high-entropy strings |
| PII detection | Email addresses, SSNs, credit cards |
| Code exfiltration | Source code fragments via TLSH similarity hashing |
| Document fingerprinting | Exfiltration of specific protected files |
| Response inspection | Prompt injection payloads in API responses |

DLP rules defined in YAML with actions: `BlockAndAlert`, `BlockAndReview`, `LogAndAllow`, `RedactAndAllow`, `Quarantine`.

GeoIP enforcement via MaxMind GeoLite2 database with configurable `allowed_regions`, `dns_verification`, and domain-level `exceptions`.

### 6.4 Credential Isolation via Phantom Tokens

**Core principle:** Real credentials never enter agent memory. The agent sees only opaque phantom tokens (`pt_puzzled_<16 hex chars>`). The proxy swaps phantom tokens for real credentials on outbound requests.

**Architecture:**

```
+-- Container (rootless Podman, user namespace) --+
|                                                 |
|  Agent process (after puzzle-init hardening)    |
|    - Sees GITHUB_TOKEN=pt_puzzled_f7a3b2        |
|    - No CAP_NET_ADMIN (dropped by puzzle-init)  |
|    - AF_NETLINK blocked by stacked seccomp      |
|    - Cannot modify nftables rules               |
|                                                 |
|  nftables DNAT rewrites all HTTP/HTTPS to proxy |
|                                                 |
+----------------------------+--------------------+
                             | All HTTP/HTTPS traffic
                             v
+-- Host (puzzled process) ---------------------------+
|                                                     |
|  puzzle-proxy with credential resolution            |
|    1. Accept TLS connection (DNAT'd)                |
|    2. TLS handshake to upstream (verify server cert)|
|    3. Present branch ephemeral CA cert to agent     |
|    4. Read plaintext HTTP request from agent        |
|    5. Scan headers for phantom tokens               |
|    6. Resolve phantom -> real from encrypted store  |
|    7. Forward request with real credential          |
|    8. Scan response for credential leakage; redact  |
|    9. Return response to agent                      |
|                                                     |
|  Credential store (mlock'd secure memory):          |
|    pt_puzzled_f7a3b2 -> ghp_real_abc123             |
|                                                     |
+-----------------------------------------------------+
```

**Five credential backends:**

| Backend | Description | Phase |
|---|---|---|
| `encrypted-file` | AES-256-GCM encrypted files, `systemd-creds` or Argon2id KDF | Phase 1 |
| `systemd-creds` | TPM-sealed or machine-id-sealed via systemd | Phase 1 |
| `env-passthrough` | Read from puzzled's environment (dev/CI only) | Phase 1 |
| `vault` / `openbao` | HashiCorp Vault or OpenBao KV v2 | Phase 2 |
| `aws-sts` | AWS Security Token Service via AssumeRole | Phase 2 |

**Secure memory:** Pre-allocated `mmap(MAP_ANONYMOUS | MAP_PRIVATE)` + `mlock()` + `MADV_DONTDUMP` + `PROT_NONE` guard pages. `write_volatile` zeroing on drop. `RwLock` for concurrent access during rotation.

**Four independent barriers preventing proxy bypass:**

| Barrier | Mechanism | Bypass Requires |
|---|---|---|
| seccomp filter | `socket(AF_NETLINK, ...)` returns `KILL_PROCESS` | Kernel seccomp vulnerability |
| Capability sets | `CAP_NET_ADMIN` dropped from all 5 sets | Kernel capability vulnerability |
| Landlock | `/usr/sbin/nft` not in execute allowlist | Kernel Landlock vulnerability |
| seccomp USER_NOTIF | `execve("/usr/sbin/nft")` denied by puzzled | puzzled compromise |

**Response scanning:** Direct byte comparison from mlock'd secure region (no Aho-Corasick to avoid credential copies). Checks raw, Base64, URL-encoded, and HTML-entity-encoded variants. Sliding window across segment boundaries.

---

## 7. Tier 2: Technical Moat Capabilities

### 7.1 Graduated Trust with Behavioral Learning

Dynamic trust scores (0-100) per agent UID, with five trust levels:

| Score | Level | Description |
|---|---|---|
| 0-19 | `Untrusted` | Maximum restrictions. All operations gated. |
| 20-39 | `Restricted` | Narrow filesystem access, no network. |
| 40-59 | `Standard` | Project-scoped access, gated network. |
| 60-79 | `Elevated` | Broad access, monitored network. |
| 80-100 | `Trusted` | Near-full access, audited but minimally gated. |

Score changes are deterministic (no ML) based on audit events. Upward transitions take effect on the next branch creation (Landlock is irrevocable). Downward transitions are immediate via `cgroup.freeze` -> adjust restrictions -> thaw.

Behavioral baseline: rolling window (7 days) of per-metric observations with sigma-based anomaly detection.

### 7.2 Multi-Agent Governance and Delegation Chains

- `parent_id` field on `BranchInfo` for parent-child relationship tracking
- Capability attenuation: child permissions = intersection of parent and requested profile
- Nested OverlayFS: child uses parent's `merged/` as its `lower_dir`
- Delegation tokens: Ed25519-signed JSON with attenuated permissions
- Maximum delegation depth: configurable (default: 4)
- Child commits to parent upper layer; parent commits to base

### 7.3 Full Provenance Chain

Links every filesystem change to the complete decision chain:

```
Human Request -> LLM Inference -> Tool Invocation -> Filesystem Change -> Governance Decision
    (who)          (why)            (how)              (what)              (outcome)
    [SDK]          [SDK]         [SDK + seccomp]      [diff engine]       [OPA/Rego]
```

Two modes: transparent (syscall-level via seccomp, no agent cooperation) and SDK (full causal chains via Unix socket).

### 7.4 Agent Tool Supply Chain Security

Signed tool manifests declaring identity, integrity (SHA-256 binary hash), and required permissions. Per-tool Landlock sub-sandboxing at exec time. Binary hash verified via the existing SECCOMP_ADDFD TOCTOU-safe flow. Optional Sigstore integration.

### 7.5 Agent Workload Identity (SPIFFE/SVID)

SPIFFE-compatible identity for governed agents:

```
spiffe://<trust_domain>/agent/<branch_id>
```

JWT-SVID with governance claims (enforcement layers, policy version, trust level, attestation chain hash). X.509-SVID for outbound mTLS. Short-lived tokens (default: 1 hour), audience-scoped. JWKS endpoint for offline verification.

---

## 8. Tier 3: Ecosystem Capabilities

### 8.1 Framework Ecosystem Integration

SDKs for Rust (`puzzled-client` crate), Python (`puzzlepod` PyPI), and TypeScript (`@puzzlepod/sdk` npm). Framework-specific integrations: LangChain callback handler, CrewAI agent wrapper, AutoGen runtime hook. REST API gateway via Unix domain socket for non-D-Bus clients.

### 8.2 Real-Time Governance Dashboard

Embedded web dashboard (React + WebSocket) served by puzzled on localhost:9090. WebSocket bridges D-Bus signals to browser for real-time events. REST endpoints map 1:1 to existing BranchManager methods. Disabled by default; enabled via `dashboard.enabled = true`.

### 8.3 Federated Multi-Host Governance

Separate `puzzled-controller` binary for centralized policy management, aggregated observability, and consistent trust scores across hosts. gRPC (mTLS) communication. Local enforcement never depends on controller availability -- kernel-enforced primitives operate independently. Offline-capable with local policy cache.

### 8.4 MCP-Aware Governance

MCP message parsing in proxy (HTTP/SSE transport) and standalone governance shim (stdio transport). Per-tool-name OPA policy evaluation at call time. Tool description integrity verification (SAFE-M-2). DLP inspection on tool results. ~200 us per-message overhead.

---

## 9. Security Model

### 9.1 Threat Mitigation

| Threat Actor | Description | Primary Mitigation |
|---|---|---|
| T1: Hallucinating Agent | Executes valid but wrong commands | OverlayFS branching + governance gate |
| T2: Prompt-Injected Agent | Executes attacker-chosen commands | Landlock + network gating + governance gate |
| T3: Goal-Drifting Agent | Pursues emergent sub-goals | Governance gate + cgroup limits + behavioral monitoring |
| T4: Credential-Exfiltrating Agent | Reads and transmits sensitive data | Landlock read_deny + network gating + phantom tokens |
| T5: Resource-Exhausting Agent | Fork bombs, infinite loops | cgroups v2 hard limits |
| T6: Colluding Agents | Coordinate to bypass individual containment | Separate branches + scope partitioning |
| T7: Supply-Chain Injector | Plants prompt injection in packages | Package allowlists + tool manifests + content scanning |

### 9.2 Resilience to Component Failure

| Failure | Detection | Recovery |
|---|---|---|
| puzzled crashes | systemd watchdog (WatchdogSec=30) | Restart; re-discover active branches; fail-closed rollback of pending commits |
| puzzled hangs | systemd watchdog (no `sd_notify`) | SIGABRT -> SIGKILL -> restart |
| Base filesystem full | Commit I/O returns ENOSPC | Rollback branch; alert admin |
| Branch storage quota exceeded | `write()` returns ENOSPC | Agent can commit or be rolled back |
| OOM in agent cgroup | cgroup OOM handler | Branch auto-rolled back |
| Branch lifetime expired | puzzled timer | Branch auto-rolled back |
| Power loss during commit | fsync not completed | WAL recovery on boot; incomplete commits rolled back |
| seccomp notification fd closed | Agent syscalls return ENOSYS | Agent crashes; branch rolled back |
| fanotify queue overflow | Events lost | Falls back to upper-dir walk at commit time |

### 9.3 Fail-Closed Behavior

- If governance cannot be determined: rollback, not commit
- If puzzled is down when a governed container starts (Podman-native): OCI hook fails, crun aborts container start -- container never runs ungoverned
- Landlock restrictions survive puzzled crash (kernel-enforced, independent)
- Configurable fail modes: `FailClosed`, `FailSilent`, `FailOperational`, `FailSafeState`

---

## 10. Performance Analysis

### 10.1 Performance Targets

| Operation | x86_64 Target | aarch64 Target |
|---|---|---|
| Branch creation (OverlayFS upper layer) | < 50ms | < 100ms |
| Container start (Podman-native, additional) | ~100-200ms | ~100-200ms |
| File I/O overhead (kernel OverlayFS) | < 10% | < 10% |
| File I/O overhead (fuse-overlayfs, rootless) | ~15-20% | ~15-20% |
| Branch commit (1K files, WAL) | < 2s | < 3s |
| Branch rollback | < 10ms | < 10ms |
| Landlock check | < 1 us | < 1 us |
| BPF LSM check | < 1 us | < 1 us |
| seccomp USER_NOTIF (per call) | ~50-100 us | ~50-100 us |
| Concurrent branches | 64 | 8 (edge) |
| puzzled memory | < 50MB + 5MB/branch | < 30MB + 3MB/branch |

### 10.2 Structural Penalties of Userspace Composition

| Penalty | Severity | Typical Agent Impact | When It Matters |
|---|---|---|---|
| seccomp USER_NOTIF latency (50-100x vs in-kernel) | Low | < 10ms per session | Per-`openat()` gating needed |
| Upper-dir walk at commit (O(n) vs O(1) tracker) | Low-Medium | < 500ms for typical changesets | Changesets > 10,000 files |
| Branch creation multi-call setup | Low | 40ms one-time per session | Branch creation rate > 25/sec |
| Commit write amplification (2x I/O vs rename) | Medium | 2x I/O during commit | Edge devices, slow storage |
| TLS proxy overhead (double termination) | Low-Medium | < 50ms per session total | Hundreds of large HTTPS downloads |

For the vast majority of AI agent workloads (modify hundreds of files, run for minutes, make a dozen network requests), the performance penalties are measured in tens of milliseconds -- well within the noise of LLM inference latency (1-30 seconds per call).

### 10.3 Resource Footprint

| Resource | Server | Edge |
|---|---|---|
| puzzled baseline | ~50MB | ~30MB |
| Per branch | ~5MB | ~3MB |
| Policy engine (regorus) | ~8MB per pool thread | ~8MB (single thread) |
| Metrics server | ~2MB | ~1MB |
| **Total (8 branches)** | **~100MB** | **~52MB** |

---

## 11. Functional Safety

### 11.1 Actuator Gating and Real-Time Profile

For deployment in safety-critical physical systems, the containment framework extends the network gating pattern to physical actuators:

```
AI Agent --> Containment Framework (puzzled) --> Safety Controller --> Physical Actuators
```

The **real-time profile** uses only in-kernel primitives with guaranteed bounded WCET:

| Feature | Standard Profile | Real-Time Profile |
|---|---|---|
| Access control | Landlock + seccomp USER_NOTIF | Landlock only (< 1 us) |
| Syscall gating | seccomp USER_NOTIF (daemon-mediated) | seccomp KILL_PROCESS (in-kernel) |
| Network gating | Transparent proxy | nftables only (no proxy) |
| Governance gate | OPA/Rego at commit time | Pre-computed allowlists (no runtime evaluation) |

### 11.2 Configurable Fail Modes

| Fail Mode | Behavior | Appropriate For |
|---|---|---|
| **Fail-closed** | Halt all agent activity; rollback branch | Default. Safe when stopping is acceptable. |
| **Fail-silent** | Agent ceases output; actuators hold last safe state | Robotic systems where sudden stop is acceptable. |
| **Fail-operational** | Switch to pre-loaded fallback behavior | Vehicles, aircraft where ceasing control is hazardous. |
| **Fail-safe-state** | Command system to known safe state, then halt | Drones (return to home), robots (park position). |

### 11.3 Certification Mapping

| Standard Requirement | How Addressed | Evidence |
|---|---|---|
| Freedom from interference (ISO 26262) | Namespace isolation + cgroup limits | Kernel namespace analysis |
| Deterministic WCET (IEC 61508 SIL-2) | Real-time profile: in-kernel only, < 1 us | Landlock, seccomp, cgroup check bounds |
| Fault detection (IEC 61508) | fanotify + cgroup events + watchdog | Kernel event mechanisms |
| Fault reaction (IEC 61508) | Configurable fail modes | Per-profile configuration |
| Diagnostic coverage (IEC 61508) | Full audit trail via Linux Audit + IMA | Audit subsystem |
| Single point of failure | Daemon mitigated by systemd watchdog + fail-mode fallback | Crash triggers configured fail mode |
| Independence of safety function | Safety controller architecturally independent | Three-layer architecture |

---

## 12. Testing Strategy

| Category | Framework | Scope |
|---|---|---|
| `tests/unit/` | Rust `#[test]` | Component-level: diff engine, WAL, sandbox setup, policy evaluation |
| `tests/integration/` | Rust `#[test]` + `testcontainers-rs` | Full fork-explore-commit cycle, concurrent branches, crash recovery |
| `tests/security/` | Custom | Escape testing, privilege escalation, policy bypass, namespace escape |
| `tests/performance/` | fio + Criterion | I/O overhead, branch creation latency, commit throughput |

**Key test suites:**

| Test | Description |
|---|---|
| `branch_lifecycle` | Full fork-explore-commit cycle; verify base filesystem state |
| `branch_rollback_cleanup` | Verify zero residue after rollback |
| `concurrent_branches` | 64 simultaneous branches; verify isolation |
| `branch_conflict_resolution` | Two branches modify same file; verify conflict detection |
| `quota_enforcement` | Write beyond quota; verify ENOSPC |
| `oom_rollback` | Agent exceeds memory limit; verify branch rollback |
| `crash_recovery` | Kill puzzled during commit; verify WAL recovery |
| `landlock_deny` | Agent accesses denied path; verify EACCES |
| `network_gating` | Agent makes HTTP POST; verify gating |
| `branch_storm` | Create and destroy 1,000 branches in rapid succession |
| `large_changeset` | Branch with 100,000 modified files; measure commit time |
| `sustained_load` | 24-hour continuous agent workload |

---

## Appendix A: D-Bus API Specification

```
Interface: org.lobstertrap.PuzzlePod1.Manager
Object path: /org/lobstertrap/PuzzlePod1/Manager

Methods (16 core + 5 attestation + 4 trust + 4 delegation + 2 identity + 2 provenance + 2 MCP):
  CreateBranch(profile: s, base_path: s, command_json: s) -> branch_id: s
  CommitBranch(branch_id: s) -> result_json: s
  RollbackBranch(branch_id: s, reason: s) -> success: b
  InspectBranch(branch_id: s) -> info_json: s
  DiffBranch(branch_id: s) -> diff_json: s
  ListBranches() -> branches_json: s
  ListAgents() -> agents_json: s
  KillAgent(branch_id: s) -> success: b
  ApproveBranch(branch_id: s) -> result_json: s
  RejectBranch(branch_id: s, reason: s) -> success: b
  UnregisterAgent(branch_id: s) -> success: b
  AgentInfo(branch_id: s) -> agent_info_json: s
  ReloadPolicy() -> (success: b, detail_message: s)
  QueryAuditEvents(filter_json: s) -> events_json: s
  ExportAuditEvents(format: s) -> export_data: s

  -- Attestation --
  VerifyAttestationChain(branch_id: s) -> json: s
  GetInclusionProof(leaf_index: t) -> json: s
  GetConsistencyProof(old_size: t, new_size: t) -> json: s
  ExportAttestationBundle(branch_id: s) -> json: s
  GetAttestationPublicKey() -> str: s

  -- Trust --
  GetTrustScore(uid: u) -> json: s
  GetBaseline(uid: u) -> json: s
  ResetTrustScore(uid: u, reason: s) -> success: b
  SetTrustOverride(uid: u, level: s, duration_hours: u) -> success: b

  -- Delegation --
  Delegate(parent_branch_id: s, child_profile: s, permissions_json: s, command_json: s) -> json: s
  ListDelegations(branch_id: s) -> json: s
  RevokeDelegation(child_branch_id: s) -> success: b
  GetDelegationChain(branch_id: s) -> json: s

  -- Identity --
  GetIdentityToken(branch_id: s, audience_json: s) -> jwt: s
  GetIdentityJwks() -> json: s

  -- Provenance --
  ReportProvenance(branch_id: s, record_json: s) -> id: s
  GetProvenance(branch_id: s) -> ndjson: s

  -- MCP --
  ReportMcpToolCall(branch_id: s, tool_call_json: s) -> id: s
  GetMcpStats(branch_id: s) -> json: s

Signals (8 core + 3 advanced):
  BranchCreated(branch_id: s, profile: s)
  BranchCommitted(branch_id: s, changeset_hash: s, profile: s)
  BranchRolledBack(branch_id: s, reason: s)
  PolicyViolation(branch_id: s, violations_json: s, changeset_hash: s, reason: s, profile: s)
  BehavioralTrigger(branch_id: s, trigger_json: s)
  AgentTimeout(branch_id: s, timeout_duration_secs: t)
  GovernanceReviewPending(branch_id: s, diff_summary: s)
  BranchEvent(branch_id: s, event_type: s, details_json: s)

  -- Advanced --
  TrustTransition(uid: u, old_level: s, new_level: s, score: u, trigger_event: s)
  DelegationEvent(parent_branch_id: s, child_branch_id: s, event_type: s)
  McpToolDenied(branch_id: s, tool_name: s, server_name: s, reason: s)
```

---

## Appendix B: Configuration Schema

**Primary config:** `/etc/puzzled/puzzled.conf` (system), `~/.config/puzzled/puzzled.conf` (user)

```yaml
[daemon]
socket_path = /run/puzzled/puzzled.sock
pid_file = /run/puzzled/puzzled.pid
log_level = info
log_target = journal

[branches]
storage_path = /var/lib/puzzled/branches
max_concurrent_branches = 64
default_storage_quota_mb = 1024
default_lifetime_minutes = 60
cleanup_interval_seconds = 30

[policy]
engine = opa
policy_dir = /etc/puzzled/policies/
profile_dir = /etc/puzzled/profiles/
default_profile = restricted
hot_reload = true

[governance]
default_action = rollback
commit_timeout_seconds = 30
require_human_approval = false
human_approval_timeout_minutes = 30

[watchdog]
heartbeat_interval_seconds = 10
heartbeat_timeout_seconds = 30
max_restart_attempts = 3

[audit]
enable_changeset_signing = true
signing_key_path = /etc/puzzled/signing-key.pem
ima_integration = true

[network]
default_mode = gated
pending_ops_max_per_branch = 100

[attestation]
enabled = false
attestation_dir = /var/lib/puzzled/attestation
checkpoint_interval = 100
checkpoint_time_interval_secs = 60

[dlp]
enabled = false
default_rules_path = /etc/puzzled/dlp/rules.yaml
geo_database_path = /usr/share/GeoIP/GeoLite2-Country.mmdb
max_inspection_body_size = 10485760
oversized_body_action = block_and_alert

[credential_proxy]
listen_address = 127.0.0.1
port_range = 18000-18499
max_concurrent_connections_per_branch = 64
max_concurrent_connections_total = 512

[credential_store]
mlock_required = true
keyring_cache_enabled = true
keyring_cache_timeout = 86400

[trust]
graduated = false

[dashboard]
enabled = false
socket_path = /run/puzzled/dashboard.sock

[federation]
enabled = false

[identity]
enabled = false
trust_domain = ""
svid_lifetime_secs = 3600
injection_mode = disabled

[telemetry]
otel_enabled = false
otel_exporter = otlp
otel_service_name = puzzled
```

**Profile YAML JSON Schema:**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PuzzlePod Agent Profile",
  "type": "object",
  "required": ["name", "description", "filesystem", "exec_allowlist", "resource_limits", "network", "behavioral"],
  "properties": {
    "name": { "type": "string", "pattern": "^[a-zA-Z][a-zA-Z0-9_-]{0,62}$" },
    "description": { "type": "string" },
    "extends": { "type": "string", "pattern": "^[a-zA-Z][a-zA-Z0-9_-]{0,62}$", "description": "Parent profile name for inheritance (max depth 3, cycle detection enforced)" },
    "filesystem": {
      "type": "object",
      "properties": {
        "read_allowlist": { "type": "array", "items": { "type": "string" } },
        "write_allowlist": { "type": "array", "items": { "type": "string" } },
        "denylist": { "type": "array", "items": { "type": "string" } },
        "read_denylist": { "type": "array", "items": { "type": "string" } },
        "write_denylist": { "type": "array", "items": { "type": "string" } }
      }
    },
    "exec_allowlist": { "type": "array", "items": { "type": "string" } },
    "exec_denylist": { "type": "array", "items": { "type": "string" } },
    "resource_limits": {
      "type": "object",
      "required": ["memory_bytes", "cpu_shares", "io_weight", "max_pids", "storage_quota_mb", "inode_quota"],
      "properties": {
        "memory_bytes": { "type": "integer" },
        "cpu_shares": { "type": "integer" },
        "io_weight": { "type": "integer" },
        "max_pids": { "type": "integer" },
        "storage_quota_mb": { "type": "integer" },
        "inode_quota": { "type": "integer" }
      }
    },
    "network": {
      "type": "object",
      "properties": {
        "mode": { "type": "string", "enum": ["Blocked", "Gated", "Monitored", "Unrestricted"] },
        "allowed_domains": { "type": "array", "items": { "type": "string" } }
      }
    },
    "behavioral": {
      "type": "object",
      "properties": {
        "max_deletions": { "type": "integer" },
        "max_reads_per_minute": { "type": "integer" },
        "credential_access_alert": { "type": "boolean" }
      }
    },
    "fail_mode": { "type": "string", "enum": ["FailClosed", "FailSilent", "FailOperational", "FailSafeState"] },
    "seccomp_mode": { "type": "string", "enum": ["Permissive", "Strict"] },
    "allow_symlinks": { "type": "boolean" },
    "allow_exec_overlay": { "type": "boolean" },
    "credentials": {
      "type": "object",
      "properties": {
        "secrets": { "type": "array" },
        "proxy": { "type": "object" }
      }
    }
  }
}
```

---

## Appendix C: Original Kernel Extension Designs (Historical Reference)

The following kernel-extension proposals from the original PuzzlePod PRD v1.2 are preserved here for historical reference. Under the userspace-first architecture adopted in v2.0, these kernel extensions are **not being implemented**. They are retained for:

1. **Historical record** -- documenting the design evolution
2. **Phase 3 reference** -- if empirical evidence justifies kernel optimizations
3. **Academic contribution** -- the designs may inform future Linux kernel development

### C.1 AgentFS Kernel Module

The original design proposed a kernel module extending OverlayFS with:

- Custom syscalls (`agent_branch_create`, `agent_branch_commit`, `agent_branch_rollback`, `agent_branch_inspect`)
- In-kernel change tracker (`struct agentfs_change` linked list per branch, 64 bytes per entry, cache-line aligned)
- Kernel-enforced quotas at VFS layer (storage bytes, inode count, branch lifetime)
- Atomic commit via `renameat2(RENAME_EXCHANGE)`
- Conflict detection via inode change list comparison

**Why not implemented:** OverlayFS + userspace diff + WAL-based commit achieves equivalent functionality. The ~5-15% copy-up false positive rate is acceptable for governance review. WAL provides crash safety without kernel atomic commit.

### C.2 AgentGuard LSM

The original design proposed a new Linux Security Module providing:

- Agent-aware path-based access control (vs. SELinux's label-based)
- Per-agent-instance policies (vs. per-type policies)
- Quantitative limits (file count, byte count, rate limiting)
- BPF-accelerated glob cache for fast path lookups
- LSM stacking with SELinux

**Why not implemented:** Landlock (unprivileged, irrevocable, kernel 5.13+) + BPF LSM (programmable per-cgroup hooks, kernel 5.7+) + SELinux provides equivalent or stronger security. A new LSM has very low upstream acceptance probability.

### C.3 Agent cgroup v2 Controller

The original design proposed a new cgroup v2 controller providing:

- Branch-specific resource accounting (storage, inode, lifetime, exec count, network egress)
- Branch-scoped OOM handling
- Agent lifecycle state tracking

**Why not implemented:** Existing cgroup v2 controllers + XFS project quotas + BPF LSM for exec counting provides equivalent resource management. A new cgroup controller has low upstream acceptance probability.

### C.4 Branch Context Syscall

The original design proposed `branch_context_create()` returning a single kernel file descriptor atomically binding PID namespace, mount namespace, network namespace, cgroup scope, seccomp-BPF filter, LSM context, and AgentFS branch.

**Why not implemented:** `clone3()` with namespace flags + `pidfd` provides equivalent lifecycle management. The "single fd" convenience is achievable in userspace via puzzled tracking the association.

### C.5 Original Syscall Specifications (Historical)

```c
long agent_branch_create(const char __user *base_path,
                         const struct agentfs_branch_config __user *config,
                         uuid_t __user *branch_id_out);

long agent_branch_commit(const uuid_t __user *branch_id,
                         __u32 flags,
                         struct agentfs_commit_result __user *result_out);

long agent_branch_rollback(const uuid_t __user *branch_id, __u32 flags);

long agent_branch_inspect(const uuid_t __user *branch_id,
                          void __user *manifest_out,
                          __u64 __user *manifest_len);

long branch_context_create(
    const struct branch_context_config __user *config,
    int __user *context_fd);
```

These syscalls are **not implemented** under the userspace-first architecture. The current architecture uses `clone3()`, `pidfd_open()`, `mount()`, `landlock_create_ruleset()`, and other existing APIs instead.

---

*End of document.*
