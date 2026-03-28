# Profile Authoring Guide

This guide explains how to create and test agent profiles for PuzzlePod.
Agent profiles define per-agent access control, resource limits, and
behavioral monitoring configuration used by the `puzzled` governance daemon
to set up kernel-enforced sandboxes.

## Profile Location

Profile files are YAML documents stored in the profiles directory
(default: `/etc/puzzled/profiles/`). The filename (without the `.yaml`
extension) is used as the profile name when creating branches:

```bash
puzzlectl branch create --profile my-agent --base-path /home/user/project
```

## YAML Structure

Every profile has the following top-level sections:

```yaml
name: my-agent
description: >
  Human-readable description of what this profile is for.

fail_mode: fail-closed   # optional, default: fail-closed

filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []

exec_allowlist: []

resource_limits:
  memory_bytes: 268435456
  cpu_shares: 100
  io_weight: 100
  max_pids: 32
  storage_quota_mb: 512
  inode_quota: 5000

network:
  mode: Blocked
  allowed_domains: []

behavioral:
  max_deletions: 50
  max_reads_per_minute: 500
  credential_access_alert: true
```

### Required Fields

- `name` -- Must match the filename (e.g., `my-agent.yaml` must have
  `name: my-agent`).
- `filesystem` -- At least `read_allowlist` and `denylist` must be present.
- `exec_allowlist` -- List of permitted executables.
- `resource_limits` -- All six sub-fields are required.
- `network` -- Both `mode` and `allowed_domains` are required.
- `behavioral` -- All three sub-fields are required.

### Optional Fields

- `description` -- Recommended but not required.
- `fail_mode` -- Defaults to `fail-closed` if omitted.

### Profile Inheritance

Profiles can inherit from a parent profile using the `extends` field:

```yaml
# Partial example — fields not shown here are required in the full profile.
# Omitted Vec fields (e.g., read_allowlist) inherit from the parent when empty.
# Omitted scalar fields use serde defaults, NOT the parent's values (see warning below).
name: my-custom-agent
description: Custom agent extending standard
extends: standard

filesystem:
  write_allowlist:
    - /workspace
  # read_allowlist, denylist inherited from standard (empty lists inherit)

resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 100
  io_weight: 100
  max_pids: 128
  storage_quota_mb: 1024
  inode_quota: 10000
```

**Merge rules:**
- **Vec fields** (exec_allowlist, exec_denylist, capabilities, all filesystem lists): if the child's list is empty, the parent's list is inherited; if non-empty, the child's list replaces the parent's entirely
- **Scalar/struct fields** (resource_limits, network, behavioral, fail_mode, seccomp_mode, etc.): always use the child's values
- **credentials**: child's if present, else parent's

> **Security warning:** Scalar fields like `fail_mode`, `seccomp_mode`,
> `allow_symlinks`, and `allow_exec_overlay` do NOT inherit from the parent.
> When omitted in a child profile, they receive serde defaults (e.g.,
> `SeccompMode::Permissive`), which may be less restrictive than the parent.
> Always explicitly set security-relevant scalar fields in child profiles.

**Constraints:**
- Maximum inheritance depth: 3 levels (e.g., grandchild extends child extends parent)
- Circular inheritance is detected and rejected
- The parent profile must exist in the same profiles directory
- The merged profile is validated after resolution

## Filesystem Rules

Filesystem access is enforced by Landlock LSM, an in-kernel mechanism
that is irrevocable once applied. Rules are evaluated on every file
access with less than 1 microsecond overhead.

### read_allowlist

Paths the agent can read. These are recursive -- granting read access to
`/usr/share` permits reading any file under that directory tree.

```yaml
filesystem:
  read_allowlist:
    - /usr/share
    - /usr/lib
    - /usr/lib64
    - /usr/include
```

### write_allowlist

Paths the agent can write to directly (outside the OverlayFS branch).
In most profiles this should be empty, because all writes are captured
by the OverlayFS upper layer and reviewed at commit time.

```yaml
filesystem:
  write_allowlist: []
```

Only set write paths when the agent needs to write to locations outside
the branch (e.g., `/tmp` for temporary files in the privileged profile).

### denylist

Paths that are always denied, regardless of allowlist rules. Denylists
take precedence over allowlists. Use this for sensitive system files:

```yaml
filesystem:
  denylist:
    - /etc/shadow
    - /etc/gshadow
    - /etc/ssh
    - /root/.ssh
    - /home
```

**Best practice:** Always deny `/etc/shadow`, `/etc/ssh`, and
`/root/.ssh` at minimum.

## Executable Allowlist

Every `execve()` call is intercepted by seccomp USER_NOTIF and validated
by `puzzled` against this list before the exec is permitted. Glob patterns
are supported.

```yaml
exec_allowlist:
  - /usr/bin/python3
  - /usr/bin/gcc
  - /usr/bin/make
  - /usr/bin/git
  - /usr/bin/curl
```

For profiles that need broad exec access, use glob patterns:

```yaml
exec_allowlist:
  - /usr/bin/*
  - /usr/sbin/*
```

**Security note:** Broad glob patterns reduce containment. Prefer explicit
lists of required executables.

## Network Modes

Network access is controlled by network namespace isolation and nftables
rules. Four modes are available:

### Blocked

No network access. The agent runs in an isolated network namespace with
no external interfaces. This is the most restrictive and recommended
default for untrusted agents.

```yaml
network:
  mode: Blocked
  allowed_domains: []
```

### Gated

Network access is permitted only to explicitly listed domains. DNS
resolution is performed by `puzzled`, and nftables rules are configured
for the resolved IP addresses. Connection attempts to unlisted
destinations are blocked by seccomp USER_NOTIF interception of
`connect()`.

```yaml
network:
  mode: Gated
  allowed_domains:
    - pypi.org
    - files.pythonhosted.org
    - github.com
    - api.github.com
    - crates.io
```

### Monitored

All network access is permitted but every connection attempt is logged
to the audit trail. Use this for trusted agents where you need visibility
but not enforcement.

```yaml
network:
  mode: Monitored
  allowed_domains: []  # ignored in Monitored mode
```

### Unrestricted

All network access is permitted without logging. Use only for fully
trusted agents in controlled environments.

```yaml
network:
  mode: Unrestricted
  allowed_domains: []  # ignored in Unrestricted mode
```

## Resource Limits

Resource limits are enforced by cgroups v2 and XFS project quotas. These
are hard limits -- the kernel enforces them regardless of the agent's
behavior.

```yaml
resource_limits:
  memory_bytes: 536870912      # 512 MiB
  cpu_shares: 100              # relative weight (1-10000)
  io_weight: 100               # relative weight (1-10000)
  max_pids: 64                 # maximum processes
  storage_quota_mb: 1024       # OverlayFS upper layer storage limit
  inode_quota: 10000           # OverlayFS upper layer file count limit
```

### Field Reference

| Field | Enforcement | Description |
|---|---|---|
| `memory_bytes` | cgroup v2 `memory.max` | Hard memory limit. OOM killer terminates agent on exceed. |
| `cpu_shares` | cgroup v2 `cpu.weight` | Relative CPU share (1-10000). Higher = more CPU time. |
| `io_weight` | cgroup v2 `io.weight` | Relative I/O priority (1-10000). Higher = more I/O bandwidth. |
| `max_pids` | cgroup v2 `pids.max` | Maximum process count. Fork bomb protection. |
| `storage_quota_mb` | XFS project quota | Maximum storage for branch filesystem in megabytes. |
| `inode_quota` | XFS project quota | Maximum file count for branch filesystem. |

### Sizing Guidelines

| Workload | Memory | PIDs | Storage | Inodes |
|---|---|---|---|---|
| Simple script | 256 MiB | 16 | 256 MB | 1,000 |
| Development agent | 512 MiB | 64 | 1 GB | 10,000 |
| Build agent | 2 GiB | 256 | 4 GB | 100,000 |
| Edge device | 128 MiB | 8 | 64 MB | 500 |

## Behavioral Triggers

Behavioral monitoring uses fanotify to observe file access patterns in
real time with zero agent overhead (asynchronous monitoring). When a
trigger fires, `puzzled` emits a `BehavioralTrigger` D-Bus signal and
records an audit event.

```yaml
behavioral:
  max_deletions: 50            # mass deletion detection
  max_reads_per_minute: 1000   # data exfiltration detection
  credential_access_alert: true # credential sniffing detection
```

### max_deletions

Maximum number of file deletions before triggering an alert. Protects
against a hallucinating agent that attempts to delete large numbers of
files. Set lower for safety-critical deployments.

### max_reads_per_minute

Maximum file read operations per minute. Detects data exfiltration
patterns where an agent rapidly reads many files. Reads within the
agent's own branch do not count toward this limit.

### credential_access_alert

When `true`, generates an alert when the agent attempts to access files
matching known credential patterns (SSH keys, AWS credentials, GPG
keyrings, `.env` files), even if the access is denied by Landlock. This
provides early warning of potentially malicious agent behavior.

## Fail Modes

The `fail_mode` field controls behavior when the governance daemon
cannot evaluate policy (daemon crash, resource exhaustion, timeout).

| Mode | Behavior | Use Case |
|---|---|---|
| `fail-closed` | Deny the operation, roll back | Default. Production servers. |
| `fail-silent` | Hold last known safe state | Edge devices with intermittent connectivity. |
| `fail-operational` | Continue with reduced capabilities | High-availability environments. |
| `fail-safe-state` | Controlled stop, return to safe state | Safety-critical (IEC 61508, ISO 26262). |

```yaml
fail_mode: fail-closed
```

**Important:** For safety-critical deployments (vehicles, robots, drones,
industrial controllers), always use `fail-safe-state` and ensure a
certified safety controller sits between the agent and physical actuators.

## Creating Profiles

Use `puzzlectl profile init` to generate a new profile YAML:

```bash
# Generate a new profile interactively
puzzlectl profile init --out /etc/puzzled/profiles/my-agent.yaml

# Generate non-interactively with inheritance
puzzlectl profile init --non-interactive --name my-agent --extends standard
```

## Testing Profiles

### Validate Syntax and Schema

Before deploying a profile, validate it against the JSON schema:

```bash
puzzlectl profile validate /etc/puzzled/profiles/my-agent.yaml
```

This checks:
- YAML syntax is valid
- All required fields are present
- Field values are within allowed ranges
- `name` matches filename
- No unknown fields

### Simulate Against Test Scenarios

Test a profile against simulated agent behavior:

```bash
puzzlectl profile test my-agent --simulate read-write-test
```

The `--simulate` flag accepts a scenario name or path to a scenario file.
The command reports which operations would be allowed or denied under the
profile's rules:

```
Simulating profile 'my-agent' against scenario 'read-write-test':
  READ  /usr/share/doc/README    -> ALLOWED (read_allowlist match)
  READ  /etc/shadow              -> DENIED  (denylist match)
  WRITE /tmp/output.txt          -> DENIED  (not in write_allowlist)
  EXEC  /usr/bin/python3         -> ALLOWED (exec_allowlist match)
  EXEC  /usr/bin/rm              -> DENIED  (not in exec_allowlist)
  NET   connect pypi.org:443     -> DENIED  (network mode: Blocked)

Result: 3 allowed, 3 denied
```

### Live Testing

Create a test branch with the profile and run a test workload:

```bash
# Create a branch with the new profile
puzzlectl branch create --profile my-agent --base-path /tmp/test-project \
  --command '["python3", "-c", "print(\"hello\")"]'

# Inspect the branch to verify sandbox configuration
puzzlectl branch list
puzzlectl branch inspect <branch-id>

# Check the diff
puzzlectl branch diff <branch-id>

# Roll back (discard) the test branch
puzzlectl branch rollback <branch-id>
```

## Example Profiles for Common Use Cases

### Code Review Agent

An agent that reads source code and produces review comments:

```yaml
name: code-reviewer
description: Read-only access to source code for automated review.

filesystem:
  read_allowlist:
    - /usr/share
    - /usr/lib
    - /usr/lib64
  write_allowlist: []
  denylist:
    - /etc/shadow
    - /etc/ssh
    - /root
    - /home

exec_allowlist:
  - /usr/bin/python3
  - /usr/bin/git
  - /usr/bin/grep
  - /usr/bin/cat

resource_limits:
  memory_bytes: 268435456
  cpu_shares: 50
  io_weight: 50
  max_pids: 16
  storage_quota_mb: 128
  inode_quota: 1000

network:
  mode: Blocked
  allowed_domains: []

behavioral:
  max_deletions: 0
  max_reads_per_minute: 500
  credential_access_alert: true
```

### CI Runner Agent

An agent that builds and tests code:

```yaml
name: ci-runner
description: Build and test agent with network access to package registries.

filesystem:
  read_allowlist:
    - /usr/share
    - /usr/lib
    - /usr/lib64
    - /usr/include
    - /usr/bin
  write_allowlist: []
  denylist:
    - /etc/shadow
    - /etc/ssh
    - /root/.ssh

exec_allowlist:
  - /usr/bin/python3
  - /usr/bin/gcc
  - /usr/bin/g++
  - /usr/bin/make
  - /usr/bin/cmake
  - /usr/bin/cargo
  - /usr/bin/rustc
  - /usr/bin/npm
  - /usr/bin/node
  - /usr/bin/git
  - /usr/bin/curl

resource_limits:
  memory_bytes: 2147483648
  cpu_shares: 200
  io_weight: 200
  max_pids: 256
  storage_quota_mb: 4096
  inode_quota: 100000

network:
  mode: Gated
  allowed_domains:
    - pypi.org
    - files.pythonhosted.org
    - registry.npmjs.org
    - crates.io
    - static.crates.io
    - github.com

behavioral:
  max_deletions: 100
  max_reads_per_minute: 2000
  credential_access_alert: true
```

### Edge Device Agent

A minimal agent for resource-constrained edge devices:

```yaml
name: edge-minimal
description: Minimal profile for edge devices with 4GB RAM.

fail_mode: fail-safe-state

filesystem:
  read_allowlist:
    - /usr/share
    - /usr/lib
  write_allowlist: []
  denylist:
    - /etc
    - /root
    - /home
    - /boot

exec_allowlist:
  - /usr/bin/python3

resource_limits:
  memory_bytes: 134217728
  cpu_shares: 25
  io_weight: 25
  max_pids: 8
  storage_quota_mb: 64
  inode_quota: 500

network:
  mode: Blocked
  allowed_domains: []

behavioral:
  max_deletions: 5
  max_reads_per_minute: 50
  credential_access_alert: true
```

## Troubleshooting

### Profile validation fails with "unknown field"

Ensure you are using the exact field names documented above. Common
mistakes:
- `read_allow` instead of `read_allowlist`
- `memory` instead of `memory_bytes`
- `cpu` instead of `cpu_shares`

### Agent cannot read expected files

Check that the paths in `read_allowlist` are correct and that no parent
path is in the `denylist`. Denylists take precedence over allowlists.

### Agent exec is denied

Verify the executable path is in `exec_allowlist`. Use the full absolute
path. Check that the binary exists at that path on the system (not a
symlink to a different location).

### Network connections fail in Gated mode

Ensure the exact domain is listed in `allowed_domains`. Subdomains are
not automatically included -- `github.com` does not grant access to
`api.github.com`. List each domain explicitly.

## Enforcement Requirements (Optional)

Profiles can declare enforcement requirements that `puzzled` verifies at
branch creation time. If the host does not meet the requirements, branch
creation fails with an error rather than silently degrading.

```yaml
enforcement_requirements:
  landlock_abi: 4          # Minimum Landlock ABI version
  seccomp_user_notif: true # Require seccomp USER_NOTIF support
  bpf_lsm: true           # Require BPF LSM
  selinux: true            # Require SELinux in enforcing mode
  xfs_quotas: true         # Require XFS project quotas
  fanotify_fid: true       # Require fanotify FAN_REPORT_FID support
```

All fields are optional. Omitted fields are not checked. This is useful
for safety-critical profiles that must not run with degraded enforcement.

## Trust Tier Interaction

Profiles operate independently of trust tiers. A profile defines the
**maximum** access an agent can have; trust tiers may restrict access
further in the future. Currently:

- Trust tier transitions emit D-Bus signals and update JWT-SVID claims
- Dynamic Landlock/seccomp tightening based on trust tier is planned
- Operators can subscribe to `TrustTransition` signals and manually
  switch an agent to a more restrictive profile on demotion

## See Also

- `puzzled(8)` -- Governance daemon
- `puzzlectl(1)` -- CLI management tool
- `puzzled.conf(5)` -- Daemon configuration
- `puzzlepod-profile(5)` -- Profile YAML format reference (man page)
- `docs/security-guide.md` -- Trust scoring and attestation chain details
- `docs/admin-guide.md` -- Trust management and workload identity
