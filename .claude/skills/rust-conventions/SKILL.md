---
name: PuzzlePod Rust Conventions
description: "Auto-activates when editing .rs files. Provides PuzzlePod-specific Rust conventions for async runtime, D-Bus, CLI, policy engine, error handling, and comment tags."
---

# PuzzlePod Rust Conventions

Apply these conventions when editing Rust code in this project.

## Async Runtime
- Use `tokio` for all async code
- Prefer `tokio::spawn` for concurrent tasks
- Use `tokio::select!` for multiplexing
- Blocking calls in async context must use `tokio::task::spawn_blocking`

## D-Bus (zbus)
- All D-Bus methods MUST be idempotent
- Bus name: `org.lobstertrap.PuzzlePod1.Manager`
- Use async zbus API (pure Rust, no libdbus)
- System bus for root mode, session bus for rootless mode
- Implementation: `crates/puzzled/src/dbus.rs` (16 methods, 8 signals)

## CLI (clap)
- Use clap derive macros for argument parsing
- All output must be machine-parseable with `--output=json`
- Follow GNU CLI conventions for flag naming
- Exit codes: 0 = success, 1 = error, 2 = usage error

## Policy Engine
- Use `regorus` (pure-Rust OPA/Rego evaluator)
- Policy files: `.rego` in `policies/rules/`
- Agent profiles: YAML in `policies/profiles/`, validated against JSON schema
- Policy evaluation must be deterministic (no ML, heuristics, or probabilistic decisions)

## Error Handling
- Use `thiserror` for library errors, `anyhow` sparingly in binaries
- Fail closed: if governance cannot be determined, rollback (not commit)
- Error messages must state what failed, why, and what to try next

## Config Auto-detection
- `DaemonConfig::load_or_default()` for config loading
- Check order: `/etc/puzzled/puzzled.conf` -> user config -> defaults

## Comment Tags
Use prefixed tags to categorize design decisions:
- `H`: Hardening measure (e.g., H8: Policy evaluation timeout)
- `M`: Mitigation for specific threat (e.g., M10: Rate limiting branch creation)
- `SC`: Seccomp design (e.g., SC1: TOCTOU-safe execve via ADDFD)
- `DC`: Design choice/trade-off (e.g., DC2: Idempotency cache for D-Bus)
- `PM`: Phase 2 feature placeholder
- `L`: Lifecycle constraint
- `A`/`B`/`C`: v6 audit fix categories
