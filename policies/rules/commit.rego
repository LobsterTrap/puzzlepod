package puzzlepod.commit

import future.keywords.if
import future.keywords.in

# Commit governance rules — evaluated by puzzled before committing a branch.
# Input: { "changes": [{ "path": "...", "kind": "...", "size": ..., "checksum": "..." }] }

default allow := false

allow if {
    not any_violation
}

any_violation if {
    count(violations) > 0
}

# --- Rule: No empty paths ---

violations[v] if {
    some change in input.changes
    change.path == ""
    v := {
        "rule": "no_empty_paths",
        "message": "changeset contains a change with an empty path",
        "severity": "critical",
    }
}

# --- K62: Reject paths containing null bytes ---
# Null bytes in paths can be used for injection attacks (C-style string truncation).

violations[v] if {
    some change in input.changes
    contains(change.path, "\u0000")
    v := {
        "rule": "deny_null_in_path",
        "message": sprintf("K62: path contains null byte: %s", [change.path]),
        "severity": "critical",
    }
}

# --- Rule: No sensitive files ---
# U33: .dockerignore negation patterns are not checked — this is a documentation concern, not a security boundary

# L17: Use regex patterns for flexible matching of sensitive file paths.
# M13: Generic substring patterns for "credentials" and "secret" catch files like
# credentials.txt, secret_keys.yml, etc. — not just credentials.json and secrets.yaml.
sensitive_regex_patterns := [
    "\\.env$",
    "\\.env\\.",
    "\\.ssh/",
    "(^|/)id_rsa$",
    "(^|/)id_ed25519$",
    "(^|/)id_ecdsa$",
    "(^|/)id_dsa$",
    "(^|/)id_ecdsa_sk$",
    "(^|/)id_ed25519_sk$",
    # H83: More specific patterns to avoid false positives on helper scripts
    "(^|/)credentials(\\.json|\\.yaml|\\.toml|\\.xml)?$",
    "(^|/)secrets?(\\.json|\\.yaml|\\.toml|\\.xml|\\.env)?$",
    "\\.aws/credentials",
    "\\.gnupg/",
    "(^|/)shadow$",
    "(^|/)gshadow$",
    "\\.docker/config\\.json$",
    "\\.config/gcloud/",
    "\\.kube/config$",
    "\\.npmrc$",
    "\\.pypirc$",
    "\\.netrc$",
    "\\.pgpass$",
    "\\.pem$",
    "\\.key$",
    "\\.p12$",
    "\\.pfx$",
    "\\.jks$",
    "(^|/)\\.token$",
    "(^|/)\\.[a-zA-Z_]*token[a-zA-Z_]*$",
    "(^|/)\\.secret$",
    "(^|/)api[_-]?key",
    "(^|/)private[_-]?key",
    # S15: Cloud provider credentials
    "\\.azure/",
    "\\.boto$",
    "(^|/)service[_-]?account.*\\.json$",
    # S15: CI/CD secrets
    "\\.vault[_-]?pass",
    # S29: Shell history (may contain passwords/API keys)
    "\\.bash_history$",
    "\\.zsh_history$",
    "\\.sh_history$",
    "\\.mysql_history$",
    "\\.psql_history$",
    # S29: Build tool credentials
    "\\.cargo/credentials",
    "\\.gem/credentials$",
    "\\.gradle/gradle\\.properties$",
    "\\.m2/settings\\.xml$",
    # S29: Container registry credentials
    "\\.podman/auth\\.json$",
    "\\.config/containers/auth\\.json$",
    "(^|/)cosign\\.key$",
    # S15: Infrastructure credentials
    "\\.terraform/",
    "\\.terraformrc$",
    "\\.config/gh/",
    "(^|/)kubeconfig$",
    # S38: Shell rc/profile files (persistence/env manipulation)
    "(^|/)\\.(bashrc|bash_profile|bash_logout|zshrc|zprofile|profile)$",
    # S39: Kerberos keytab files
    "\\.keytab$",
    # S40: GPG secret keyring
    "secring\\.gpg$",
]

# G5: Normalize path to lowercase before matching to catch CREDENTIALS.json, .ENV, Secrets.yaml etc.
violations[v] if {
    some change in input.changes
    some pattern in sensitive_regex_patterns
    trimmed := trim_left(change.path, "/")
    re_match(pattern, lower(trimmed))
    v := {
        "rule": "no_sensitive_files",
        "message": sprintf("sensitive file in changeset: %s", [change.path]),
        "severity": "critical",
    }
}

# --- Rule: No persistence mechanisms ---

persistence_paths := [
    "etc/cron",
    "var/spool/cron",
    "etc/systemd/system/",
    "usr/lib/systemd/system/",
    "etc/init.d/",
    # R19: at daemon scheduling persistence
    "etc/at.allow",
    "etc/at.deny",
    # K63: at job spool directory persistence
    "var/spool/at/",
    # S41: udev rules and kernel module autoload persistence
    "etc/udev/rules.d/",
    "etc/modules-load.d/",
    # F22: Additional persistence paths
    "etc/xdg/autostart/",
    "etc/environment.d/",
    "etc/profile.d/",
    "etc/pam.d/",
    "etc/NetworkManager/dispatcher.d/",
    "var/spool/anacron/",
]

# F22: Exact-match persistence files (not directories)
persistence_exact_files := [
    "etc/ld.so.preload",
    "etc/anacrontab",
]

# H13: User-directory persistence paths (matched as path suffixes to catch any home directory)
persistence_suffixes := [
    ".config/autostart/",
    ".bashrc",
    ".profile",
    ".local/share/systemd/",
    # S30: User-level systemd services persistence
    ".config/systemd/user/",
    # S37: D-Bus session services persistence
    ".local/share/dbus-1/services/",
]

violations[v] if {
    some change in input.changes
    some pattern in persistence_paths
    # Match both relative and absolute paths
    path := trim_left(change.path, "/")
    # H84: Lowercase path before matching to catch mixed-case evasion (e.g. Etc/Cron.d/)
    startswith(lower(path), pattern)
    v := {
        "rule": "no_persistence",
        "message": sprintf("persistence mechanism in changeset: %s", [change.path]),
        "severity": "critical",
    }
}

# F22: Exact-match persistence files (not prefix-matched directories)
violations[v] if {
    some change in input.changes
    some exact in persistence_exact_files
    path := trim_left(change.path, "/")
    # J60: Case-normalize exact-match persistence files to catch evasion (e.g. Etc/Ld.So.Preload)
    lower(path) == exact
    v := {
        "rule": "no_persistence",
        "message": sprintf("persistence mechanism in changeset: %s", [change.path]),
        "severity": "critical",
    }
}

# T21: Match directory suffixes with contains(), file suffixes with endswith()
_matches_suffix(path, suffix) if {
    endswith(suffix, "/")
    contains(path, suffix)
}
_matches_suffix(path, suffix) if {
    not endswith(suffix, "/")
    endswith(path, suffix)
}

# T21: Use endswith() for file entries and contains() for directory entries
# to avoid false positives (e.g., "docs/.bashrc_backup/" matching ".bashrc")
violations[v] if {
    some change in input.changes
    some suffix in persistence_suffixes
    path_lower := lower(change.path)
    _matches_suffix(path_lower, suffix)
    v := {
        "rule": "no_persistence",
        "message": sprintf("user-directory persistence mechanism in changeset: %s", [change.path]),
        "severity": "critical",
    }
}

# --- Rule: No executable permission changes ---
# U34: setuid/setgid detection is handled by the overlay mount's MS_NOSUID flag (kernel-enforced)
# M22: Flag any file with metadata changes (potential executable permission changes),
# not just .sh files. Any file where permissions are altered could be made executable.
# L17: Use re_match for pattern matching instead of string suffix checks.

violations[v] if {
    some change in input.changes
    change.kind == "MetadataChanged"
    v := {
        "rule": "no_exec_permission_changes",
        "message": sprintf("executable permission change: %s", [change.path]),
        "severity": "error",
    }
}

# --- Rule: Total changeset size limit (100 MiB) ---

max_total_bytes := 104857600

# V11: Guard total_bytes sum with is_number to reject string/null size values
total_bytes := sum([change.size | some change in input.changes; is_number(change.size)])

violations[v] if {
    total_bytes > max_total_bytes
    v := {
        "rule": "max_changeset_size",
        "message": sprintf("total changeset size %d exceeds limit %d", [total_bytes, max_total_bytes]),
        "severity": "error",
    }
}

# --- G18: Reject changes missing required size field ---
# Without a size field, the total_bytes sum silently skips the change,
# allowing unlimited data commit.

violations[v] if {
    some change in input.changes
    not change.size
    v := {
        "rule": "missing_change_size",
        # R1: Use lowercase "critical" to match case-sensitive parser in policy.rs
        "severity": "critical",
        "message": sprintf("G18: change '%s' missing required size field", [change.path]),
    }
}

# --- Rule: No system file modifications ---

system_prefixes := [
    "usr/bin/",
    "usr/sbin/",
    "usr/lib/systemd/",
    "usr/lib/",
    "usr/local/",
    "usr/share/",
    "etc/",
    "boot/",
    "lib/modules/",
    "sys/",
    "dev/",
    "run/",
    "proc/",
    "sbin/",
    "bin/", # Q5: Cover top-level /bin (not just /usr/bin)
    "var/lib/systemd/",
    "tmp/", # R1: Flag /tmp content at commit time
]

violations[v] if {
    some change in input.changes
    some prefix in system_prefixes
    # Match both relative paths (usr/bin/...) and absolute (/usr/bin/...)
    path := trim_left(change.path, "/")
    # H85: Lowercase path before matching to catch mixed-case evasion (e.g. Usr/Bin/)
    startswith(lower(path), prefix)
    v := {
        "rule": "no_system_modifications",
        "message": sprintf("system file modification: %s", [change.path]),
        "severity": "critical",
    }
}

# --- Rule: Maximum number of files ---
# N13: max_files is overridable from profile via input.profile.max_files,
# falling back to the default of 10000.

default_max_files := 10000

# S15: input.max_files is not set by policy.rs — use default_max_files only.
# Profile-specific file count limits should be added to evaluate_full() if needed.
max_files := default_max_files

violations[v] if {
    count(input.changes) > max_files
    v := {
        "rule": "max_file_count",
        "message": sprintf("changeset contains %d files, limit is %d", [count(input.changes), max_files]),
        "severity": "error",
    }
}

# --- Rule: Profile-aware storage quota ---
#
# Q7: These hard-coded profile limits are legacy fallbacks only. At commit time,
# puzzled passes input.storage_quota_bytes from the actual profile YAML, which is
# used by the dynamic_storage_quota rule (~line 361). The hard-coded rules below
# only apply if input.storage_quota_bytes is not provided in the input.
#
# If input.profile is provided, enforce profile-specific total changeset size limits.
# Profiles: restricted = 10 MiB, standard = 100 MiB (default), privileged = 500 MiB.

profile_storage_limit_bytes := limit if {
    input.profile == "restricted"
    limit := 10485760
}

profile_storage_limit_bytes := limit if {
    input.profile == "standard"
    limit := 104857600
}

profile_storage_limit_bytes := limit if {
    input.profile == "privileged"
    limit := 524288000
}

# V39: Only restricted/standard/privileged have explicit limits here.
# Other profiles use dynamic_storage_quota (K67) via input.storage_quota_bytes
# which puzzled always provides from the profile's resource_limits.storage_quota_mb.

# Fallback: if profile is not recognized or not provided, use the default max_total_bytes
profile_storage_limit_bytes := max_total_bytes if {
    not input.profile
}

profile_storage_limit_bytes := max_total_bytes if {
    input.profile
    not input.profile == "restricted"
    not input.profile == "standard"
    not input.profile == "privileged"
}

violations[v] if {
    input.profile
    total_bytes > profile_storage_limit_bytes
    v := {
        "rule": "profile_storage_quota",
        "message": sprintf("total changeset size %d exceeds profile '%s' limit %d", [total_bytes, input.profile, profile_storage_limit_bytes]),
        "severity": "error",
    }
}

# --- K67: Dynamic storage quota from profile metadata ---
# When input.storage_quota_bytes is provided (from profile YAML), use it as the
# authoritative limit instead of the hard-coded profile_storage_limit_bytes above.
# This ensures Rego enforcement matches the actual profile configuration.

# S13: Use is_number + > 0 to prevent falsy 0 from disabling the limit
violations[v] if {
    is_number(input.storage_quota_bytes)
    input.storage_quota_bytes > 0
    total_bytes > input.storage_quota_bytes
    v := {
        "rule": "dynamic_storage_quota",
        "message": sprintf("K67: total changeset size %d exceeds dynamic storage quota %d bytes", [total_bytes, input.storage_quota_bytes]),
        "severity": "error",
    }
}

# --- N11: No hardlinks ---
# Hardlinks can be used for privilege escalation and data exfiltration
# (e.g., hardlinking a setuid binary or sensitive file to gain access after commit).

violations[v] if {
    some change in input.changes
    change.kind == "Hardlink"
    v := {
        "rule": "deny_hardlinks",
        "message": sprintf("N11: hardlink not allowed in changeset: %s", [change.path]),
        "severity": "critical",
    }
}

# --- N12: No device special files ---
# Device files (block, char, FIFO) should never appear in agent changesets.
# They can be used to access raw devices or create covert IPC channels.

violations[v] if {
    some change in input.changes
    change.kind in {"BlockDevice", "CharDevice", "Fifo"}
    v := {
        "rule": "deny_device_files",
        "message": sprintf("N12: device/special file not allowed in changeset: %s (kind: %s)", [change.path, change.kind]),
        "severity": "critical",
    }
}

# --- Cross-file combination rules ---
# These require multiple changes in input.changes; paths are normalized like other rules
# (trim leading "/", lowercase) so relative and absolute paths match consistently.

# Reject changesets that add or touch both a shared library (.so) and ld.so configuration
# (preload / ld.so.conf.d) — possible LD_PRELOAD persistence attack.

violations[v] if {
    some lib_change in input.changes
    endswith(lower(lib_change.path), ".so")
    some preload_change in input.changes
    p := trim_left(preload_change.path, "/")
    startswith(lower(p), "etc/ld.so")
    v := {
        "rule": "deny_preload_with_library",
        "message": sprintf("changeset contains both a shared library (%s) and an ld.so configuration (%s) — possible LD_PRELOAD persistence attack", [lib_change.path, preload_change.path]),
        "severity": "error",
        "file": preload_change.path,
    }
}

# Reject changesets with an executable file (any owner/group/other execute bit) and a
# cron or systemd unit path — possible persistence attack.
# Requires new_mode on the executable change (from diff / FileChange); if absent, this rule does not apply.

cron_or_systemd_path(path) if {
    p := trim_left(path, "/")
    startswith(lower(p), "etc/cron")
}

cron_or_systemd_path(path) if {
    p := trim_left(path, "/")
    startswith(lower(p), "etc/systemd/system/")
}

violations[v] if {
    some exec_change in input.changes
    exec_change.new_mode != null
    bits.and(to_number(exec_change.new_mode), 73) > 0 # 0o111 = any execute bit
    some sched_change in input.changes
    cron_or_systemd_path(sched_change.path)
    v := {
        "rule": "deny_script_with_cron",
        "message": sprintf("changeset contains both an executable (%s) and a scheduler entry (%s) — possible persistence attack", [exec_change.path, sched_change.path]),
        "severity": "error",
        "file": sched_change.path,
    }
}

# --- R1: No setuid/setgid bits on new files ---
# Reject any change where new_mode has setuid (0o4000 = 2048) or setgid (0o2000 = 1024) set.
# Combined mask: 0o6000 = 3072 (2048 + 1024). Use to_number so string or numeric JSON modes work.
# Note: 6144 would not cover setgid-only (1024); 3072 is the correct S_ISUID|S_ISGID mask.

violations[v] if {
    some change in input.changes
    change.new_mode != null
    bits.and(to_number(change.new_mode), 3072) > 0
    v := {
        "rule": "deny_suid_binary",
        "message": sprintf("file %s has setuid/setgid bits (mode: %v) — elevated privileges not allowed", [change.path, change.new_mode]),
        "severity": "error",
        "file": change.path,
    }
}

# --- H11: No symlinks unless profile allows ---
# V40: Use input.allow_symlinks (boolean from profile YAML) instead of
# hardcoding the "privileged" profile name. puzzled passes this field
# from AgentProfile.allow_symlinks in the Rego input.

violations[v] if {
    some change in input.changes
    change.kind == "Symlink"
    not input.allow_symlinks
    v := {
        "rule": "deny_symlink",
        "message": sprintf("symlink not allowed: %s", [change.path]),
        "severity": "critical",
    }
}

# --- Symlink target validation when symlinks are allowed ---
# Even when the profile allows symlinks, reject any symlink whose
# target points outside the workspace root (prevents symlink-based escape).

violations[v] if {
    some change in input.changes
    change.kind == "Symlink"
    input.allow_symlinks
    input.workspace_root
    change.target
    startswith(change.target, "/")
    # G17: Append trailing "/" to workspace_root to prevent prefix confusion
    # (e.g., "/workspace" matching "/workspacevil/")
    not startswith(change.target, concat("", [input.workspace_root, "/"]))
    not change.target == input.workspace_root
    v := {
        "rule": "deny_symlink_outside_workspace",
        "message": sprintf("symlink target outside workspace: %s -> %s", [change.path, change.target]),
        "severity": "critical",
    }
}

# R8: Relative symlink targets with parent traversal can escape workspace
# F9: Uses change.kind == "Symlink" (matching Rust serde serialization of FileChangeKind)
violations[v] if {
    some change in input.changes
    change.kind == "Symlink"
    change.target
    contains(change.target, "..")
    v := {
        "rule": "deny_symlink_parent_traversal",
        "message": sprintf("relative symlink with parent traversal: %s -> %s", [change.path, change.target]),
        "severity": "critical",
    }
}

# --- M6: Workspace boundary enforcement ---
# All changed paths must be under the workspace root. Reject any absolute path
# that does not start with input.workspace_root.

# G17: Append trailing "/" to workspace_root to prevent prefix confusion
# (e.g., "/workspace" matching "/workspacevil/file")
violations[v] if {
    some change in input.changes
    startswith(change.path, "/")
    input.workspace_root
    not startswith(change.path, concat("", [input.workspace_root, "/"]))
    not change.path == input.workspace_root
    v := {
        "rule": "deny_outside_workspace",
        "message": sprintf("change outside workspace boundary: %s", [change.path]),
        "severity": "critical",
    }
}

# --- J61: Reject paths with ".." traversal components ---
# Path traversal via ".." in change.path can escape workspace boundaries
# even when the path is relative (e.g., "workspace/../etc/shadow").

violations[v] if {
    some change in input.changes
    contains(change.path, "..")
    v := {
        "rule": "deny_path_traversal_in_changeset",
        "message": sprintf("J61: path traversal detected in changeset: %s", [change.path]),
        "severity": "critical",
    }
}

# --- J68: Reject symlinks with empty or missing targets ---
# A symlink with no target or an empty target string is suspicious —
# it may indicate an attempt to create a dangling symlink for later exploitation.

violations[v] if {
    some change in input.changes
    change.kind == "Symlink"
    not change.target
    v := {
        "rule": "deny_symlink_missing_target",
        "message": sprintf("J68: symlink with missing target: %s", [change.path]),
        "severity": "critical",
    }
}

violations[v] if {
    some change in input.changes
    change.kind == "Symlink"
    change.target == ""
    v := {
        "rule": "deny_symlink_empty_target",
        "message": sprintf("J68: symlink with empty target: %s", [change.path]),
        "severity": "critical",
    }
}

# F10: Reject absolute paths when workspace_root is not provided.
# Without workspace_root, boundary enforcement cannot be applied, so
# absolute paths must be rejected to prevent silent bypass.
violations[v] if {
    some change in input.changes
    startswith(change.path, "/")
    not input.workspace_root
    v := {
        "rule": "deny_missing_workspace_root",
        "message": sprintf("F10: absolute path '%s' requires workspace_root to be set", [change.path]),
        "severity": "critical",
    }
}

# --- Content inspection: high-entropy file detection (opt-in) ---
# Gated behind input.profile_config.content_inspection_enabled.

deny_high_entropy contains violation if {
    input.profile_config.content_inspection_enabled == true
    some change in input.changes
    change.entropy != null
    change.entropy > 4.5
    not endswith(change.path, ".bin")
    not endswith(change.path, ".gz")
    not endswith(change.path, ".zip")
    not endswith(change.path, ".png")
    not endswith(change.path, ".jpg")
    violation := {
        "rule": "deny_high_entropy",
        "message": sprintf("file %s has high entropy (%.2f > 4.5) — possible encoded/encrypted content", [change.path, change.entropy]),
        "severity": "warning",
        "file": change.path,
    }
}

violations[v] if {
    some v in deny_high_entropy
}

# --- Content inspection: base64 block detection (opt-in) ---

deny_base64_blocks contains violation if {
    input.profile_config.content_inspection_enabled == true
    some change in input.changes
    change.has_base64_blocks == true
    not endswith(change.path, ".bin")
    violation := {
        "rule": "deny_base64_blocks",
        "message": sprintf("file %s contains base64 blocks > 64 chars — possible encoded data exfiltration", [change.path]),
        "severity": "warning",
        "file": change.path,
    }
}

violations[v] if {
    some v in deny_base64_blocks
}

# --- §3.4 G27: Reject phantom tokens in commit changeset ---
# Files flagged by fanotify as containing phantom token patterns
# are passed in input.phantom_token_flagged_files. Any file in the
# changeset that was flagged must be rejected to prevent credential
# proxy tokens from being persisted.
violations[v] if {
    some change in input.changes
    some flagged_path in input.phantom_token_flagged_files
    change.path == flagged_path
    v := {
        "rule": "deny_phantom_token_in_changeset",
        "message": sprintf("§3.4 G27: phantom token detected in file '%s' — credential proxy tokens must not be committed", [change.path]),
        "severity": "critical",
    }
}
