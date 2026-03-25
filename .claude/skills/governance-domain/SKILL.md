---
name: PuzzlePod Governance Domain
description: "Auto-activates when working in crates/puzzled/. Provides domain context for the Fork-Explore-Commit governance model, sandbox layers, and design principles."
---

# PuzzlePod Governance Domain

## Core Concept: Fork, Explore, Commit

1. **Fork**: Create an isolated OverlayFS branch for the agent workload
2. **Explore**: Agent executes in the sandboxed branch, all filesystem changes tracked
3. **Commit**: Changes evaluated by OPA/Rego policy; approved changes committed, rejected changes rolled back

## Sandbox Layers (Defense in Depth)

Each layer is independent and irrevocable once applied:

- **Namespaces**: mount, PID, network, user, UTS, IPC isolation
- **cgroups v2**: Resource limits (CPU, memory, I/O)
- **Landlock**: Filesystem access control (read/write/execute per path)
- **seccomp**: System call filtering (allowlist model)
- **BPF LSM**: Dynamic security policy hooks
- **SELinux**: Type enforcement via `puzzlepod_t` domain (`selinux/puzzlepod.te`)
- **OverlayFS**: Copy-on-write filesystem branching

## Key Design Principles

1. **Zero kernel modifications** -- compose existing upstream primitives only
2. **Kernel enforces, userspace decides** -- puzzled configures sandbox; kernel enforces irrevocably
3. **Fail closed** -- if governance cannot be determined, rollback (not commit)
4. **Deterministic** -- no ML, heuristics, or probabilistic decisions in governance path
5. **Composable** -- SELinux, audit, Podman, systemd continue unchanged
6. **Defense in depth** -- all sandbox layers are independent; compromise of one does not defeat others

## D-Bus API

- Bus name: `org.lobstertrap.PuzzlePod1.Manager`
- 16 methods, 8 signals
- Key methods: `CreateBranch`, `CommitBranch`, `RollbackBranch`, `ListBranches`, `GetBranchStatus`
- All methods are idempotent
- Implementation: `crates/puzzled/src/dbus.rs`

## Key Types (puzzled-types)

- `Branch`: Represents an OverlayFS branch with lifecycle state
- `Change`: A tracked filesystem modification within a branch
- `CommitResult`: Outcome of policy evaluation (commit or rollback)

## Agent Profiles

Three tiers in `policies/profiles/`:
- `restricted.yaml`: Minimal permissions (default)
- `standard.yaml`: Typical agent workload
- `privileged.yaml`: Extended permissions (requires explicit approval)
