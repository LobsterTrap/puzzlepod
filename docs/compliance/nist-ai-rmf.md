# PuzzlePod — NIST AI Risk Management Framework (AI RMF 1.0) Mapping

This document maps the NIST **AI RMF 1.0** core functions (**GOVERN**, **MAP**, **MEASURE**, **MANAGE**) to PuzzlePod capabilities. Organizational governance processes are only noted where the product supplies evidence or enforcement hooks.

---

## Core function mapping

| Function | RMF expectation (summary) | PuzzlePod Control | Evidence |
|---|---|---|---|
| **GOVERN** | Policies, accountability, and oversight structures for AI risk | **OPA/Rego** governance engine (`crates/puzzled/src/policy.rs`, `regorus`); **profile-based containment** (YAML + `policies/schemas/profile.schema.json`, `crates/puzzled/src/profile.rs`); **administrative API** on system/session D-Bus (`crates/puzzled/src/dbus.rs` — branch lifecycle, policy reload `ReloadPolicy`, trust/attestation) | `policies/rules/`; `puzzlectl profile` / `policy test`; four-phase rollout (Monitor → Full) per design docs |
| **MAP** | Context, categorization, and understanding of AI-related risks | **Threat model T1–T7** and risk matrix in product security architecture; **agent profiling** (restricted / standard / privileged templates under `policies/profiles/`) mapping workload class to filesystem, network, exec, and fail-mode posture | `docs/PRD.md`, `docs/security-guide.md`; profile loader in `puzzled` |
| **MEASURE** | Test, evaluate, and monitor AI system behavior and impacts | **fanotify** behavioral monitoring (`crates/puzzled/src/sandbox/fanotify.rs`); **per-UID trust scores** (`GetTrustScore`, `SetTrustOverride`, `ResetTrustScore` in `dbus.rs`, config `trust` in `config.rs`); **audit + attestation metrics** via audit store and Prometheus instrumentation in `puzzled` (`main.rs` metrics init, branch metrics) | Prometheus scrape of `puzzled`; D-Bus trust methods; `puzzlectl audit list` / export patterns in `puzzlectl` |
| **MANAGE** | Prioritize and respond to risks; incident handling and recovery | **Configurable fail modes** (`FailClosed`, `FailSilent`, `FailOperational`, `FailSafeState` — `puzzled_types`, applied in `branch/commit_flow.rs`); **incident-style response**: rollback, cgroup freeze/quarantine hooks for DLP, `puzzlectl agent kill`, PID namespace teardown; **policy hot-reload** without daemon restart (`ReloadPolicy` on D-Bus); **trust lifecycle** (overrides, reset, signals on transition) | `commit_flow.rs` `apply_fail_mode`; `dbus.rs` reload + rollback paths; integration/security tests under `tests/` |

---

## Summary

PuzzlePod primarily supports AI RMF **GOVERN** and **MANAGE** through **declarative policies and kernel-enforced containment**, and **MAP** / **MEASURE** through **documented threats, profiles, telemetry, and trust scoring**. Teams should pair these controls with organizational AI RMF playbooks (accountability, vendor management, red-teaming) that the daemon does not implement.
