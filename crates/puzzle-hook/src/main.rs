// SPDX-License-Identifier: Apache-2.0
//! puzzle-hook — OCI runtime hook for PuzzlePod governance integration.
//!
//! This binary is invoked by the container runtime (crun) at two OCI lifecycle
//! stages:
//!
//! - `createRuntime`: after the container namespaces are created but before the
//!   user process starts. The hook calls puzzled's `AttachGovernance` D-Bus method
//!   to attach BPF LSM programs, start fanotify monitoring, and register the
//!   container PID.
//!
//! - `poststop`: after the container process has exited. The hook calls puzzled's
//!   `TriggerGovernance` D-Bus method to run governance evaluation (freeze, diff,
//!   OPA policy, commit/rollback).
//!
//! The hook reads OCI container state from stdin as JSON per the OCI runtime
//! spec. It is fail-closed: any error results in a non-zero exit code, which
//! causes crun to abort the container start. This ensures containers never run
//! ungoverned.
//!
//! The hook is registered via an OCI hook configuration file that matches on the
//! `run.oci.handler=puzzlepod` annotation. Containers without this annotation are
//! never invoked.

use std::collections::HashMap;
use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Maximum time to wait for a D-Bus method call before failing.
/// Prevents the hook from stalling the container runtime indefinitely.
const DBUS_CALL_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// OCI container state (read from stdin)
// ---------------------------------------------------------------------------

/// OCI runtime container state, as defined by the OCI Runtime Specification.
///
/// Reference: <https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciState {
    /// OCI specification version (e.g. "1.0.2").
    #[allow(dead_code)]
    oci_version: String,

    /// Container ID.
    id: String,

    /// Container lifecycle status: "creating", "created", "running", "stopped".
    status: String,

    /// PID of the container init process in the runtime namespace.
    /// May be absent for the `poststop` stage (process already exited).
    pid: Option<u32>,

    /// Absolute path to the container bundle directory.
    #[allow(dead_code)]
    bundle: String,

    /// Container annotations (key-value pairs).
    #[serde(default)]
    annotations: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Hook stage determination
// ---------------------------------------------------------------------------

/// The OCI lifecycle stage at which this hook is executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookStage {
    /// createRuntime: namespaces created, user process not yet started.
    CreateRuntime,
    /// poststop: container process has exited.
    Poststop,
}

/// Annotation key indicating this container is governed by PuzzlePod.
const ANNOTATION_HANDLER: &str = "run.oci.handler";

/// Expected annotation value for PuzzlePod governed containers.
const ANNOTATION_HANDLER_VALUE: &str = "puzzlepod";

/// Annotation key carrying the branch ID for this container.
const ANNOTATION_BRANCH: &str = "org.lobstertrap.puzzlepod.branch";

/// D-Bus well-known name for puzzled.
const DBUS_SERVICE: &str = "org.lobstertrap.PuzzlePod1";

/// D-Bus object path for the puzzled Manager interface.
const DBUS_PATH: &str = "/org/lobstertrap/PuzzlePod1/Manager";

/// D-Bus interface name for puzzled Manager.
const DBUS_INTERFACE: &str = "org.lobstertrap.PuzzlePod1.Manager";

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

/// Parse OCI container state from a JSON byte slice.
fn parse_oci_state(input: &[u8]) -> Result<OciState> {
    serde_json::from_slice(input).context("failed to parse OCI state JSON from stdin")
}

/// Check whether this container is an PuzzlePod governed container.
/// Returns `true` if the `run.oci.handler` annotation is set to `puzzlepod`.
fn is_puzzlepod_container(state: &OciState) -> bool {
    state
        .annotations
        .get(ANNOTATION_HANDLER)
        .map(|v| v == ANNOTATION_HANDLER_VALUE)
        .unwrap_or(false)
}

/// G19: Validate a branch ID — reject path traversal, control characters, and excessive length.
fn validate_branch_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && !id.contains('/')
        && !id.contains("..")
        && !id.contains('\0')
        && !id.chars().any(|c| c.is_control())
}

/// Extract the branch ID from annotations.
/// G19: Validates the branch ID to reject path traversal and injection attacks.
fn extract_branch_id(state: &OciState) -> Result<&str> {
    let id = state
        .annotations
        .get(ANNOTATION_BRANCH)
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .context("missing or empty 'org.lobstertrap.puzzlepod.branch' annotation")?;

    if !validate_branch_id(id) {
        bail!(
            "G19: invalid branch ID '{}': must be <= 256 chars, no '/', '..', null, or control characters",
            id
        );
    }

    Ok(id)
}

/// Determine the hook stage from the OCI state `status` field.
///
/// Per the OCI runtime spec:
/// - `createRuntime` hooks fire when status is "creating" or "created"
/// - `poststop` hooks fire when status is "stopped"
fn determine_stage(status: &str) -> Result<HookStage> {
    match status {
        "creating" | "created" => Ok(HookStage::CreateRuntime),
        "stopped" => Ok(HookStage::Poststop),
        other => bail!(
            "unexpected OCI state status '{}'; expected 'creating', 'created', or 'stopped'",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// D-Bus calls to puzzled
// ---------------------------------------------------------------------------

/// Call puzzled's `AttachGovernance` method via D-Bus.
///
/// Parameters:
/// - `branch_id`: the branch ID from the container annotation
/// - `pid`: the container init process PID
/// - `container_id`: the OCI container ID
async fn call_attach_governance(branch_id: &str, pid: u32, container_id: &str) -> Result<()> {
    let connection = connect_dbus().await?;

    // Call AttachGovernance(branch_id: s, pid: u, container_id: s) -> b
    // Wrapped in a timeout to prevent stalling the container runtime indefinitely.
    let reply: bool = tokio::time::timeout(
        DBUS_CALL_TIMEOUT,
        connection.call_method(
            Some(DBUS_SERVICE),
            DBUS_PATH,
            Some(DBUS_INTERFACE),
            "AttachGovernance",
            &(branch_id, pid, container_id),
        ),
    )
    .await
    .context("D-Bus call to AttachGovernance timed out (30s limit)")?
    .context("D-Bus call to AttachGovernance failed")?
    .body()
    .deserialize()
    .context("failed to deserialize AttachGovernance response")?;

    if !reply {
        bail!("AttachGovernance returned false for branch '{}'", branch_id);
    }

    Ok(())
}

/// Call puzzled's `TriggerGovernance` method via D-Bus.
///
/// Parameters:
/// - `branch_id`: the branch ID from the container annotation
async fn call_trigger_governance(branch_id: &str) -> Result<()> {
    let connection = connect_dbus().await?;

    // Call TriggerGovernance(branch_id: s) -> s (JSON result)
    // Wrapped in a timeout to prevent stalling the container runtime indefinitely.
    let reply: String = tokio::time::timeout(
        DBUS_CALL_TIMEOUT,
        connection.call_method(
            Some(DBUS_SERVICE),
            DBUS_PATH,
            Some(DBUS_INTERFACE),
            "TriggerGovernance",
            &(branch_id,),
        ),
    )
    .await
    .context("D-Bus call to TriggerGovernance timed out (30s limit)")?
    .context("D-Bus call to TriggerGovernance failed")?
    .body()
    .deserialize()
    .context("failed to deserialize TriggerGovernance response")?;

    // Print the governance result so it's visible in the terminal
    eprintln!(
        "puzzle-hook: governance result for branch '{}': {}",
        branch_id, reply
    );

    Ok(())
}

/// Establish a D-Bus connection.
///
/// Uses the system bus in production builds. In debug/test builds, the
/// `PUZZLEPOD_DBUS_SESSION` environment variable can override to the session bus
/// for development convenience.
///
/// H93: The session bus fallback is gated behind `#[cfg(debug_assertions)]`
/// to prevent an attacker from controlling bus selection via environment
/// variable in production.
async fn connect_dbus() -> Result<zbus::Connection> {
    #[cfg(debug_assertions)]
    {
        // Debug-only: allow session bus override for testing
        if std::env::var("PUZZLEPOD_DBUS_SESSION").is_ok() {
            return zbus::Connection::session()
                .await
                .context("failed to connect to D-Bus session bus");
        }
    }
    zbus::Connection::system()
        .await
        .context("failed to connect to D-Bus system bus")
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    // H86: Read OCI state from stdin with a 1 MiB limit to prevent unbounded allocation
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().take(1_048_576).read_to_end(&mut input) {
        eprintln!("puzzle-hook: failed to read stdin: {e}");
        return ExitCode::FAILURE;
    }

    // Parse OCI state
    let state = match parse_oci_state(&input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("puzzle-hook: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Check if this is an PuzzlePod governed container
    if !is_puzzlepod_container(&state) {
        // Not our container — exit successfully without action
        return ExitCode::SUCCESS;
    }

    // Extract branch ID
    let branch_id = match extract_branch_id(&state) {
        Ok(id) => id.to_string(),
        Err(e) => {
            eprintln!("puzzle-hook: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Determine lifecycle stage
    let stage = match determine_stage(&state.status) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("puzzle-hook: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Build a single-threaded tokio runtime for the async D-Bus call.
    // OCI hooks should be lightweight and short-lived.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("puzzle-hook: failed to create tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = rt.block_on(async {
        match stage {
            HookStage::CreateRuntime => {
                let pid = state.pid.context(
                    "container PID is required at createRuntime stage but was not provided",
                )?;
                eprintln!(
                    "puzzle-hook: createRuntime — attaching governance for branch '{}' \
                     (container={}, pid={})",
                    branch_id, state.id, pid
                );
                call_attach_governance(&branch_id, pid, &state.id).await
            }
            HookStage::Poststop => {
                eprintln!(
                    "puzzle-hook: poststop — triggering governance for branch '{}' \
                     (container={})",
                    branch_id, state.id
                );
                call_trigger_governance(&branch_id).await
            }
        }
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Fail-closed: any error causes non-zero exit, which makes crun
            // abort the container start (at createRuntime) or report an error
            // (at poststop).
            eprintln!("puzzle-hook: FATAL: {e:#}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid OCI state JSON for a creating container with puzzlepod handler.
    fn make_oci_state_json(
        status: &str,
        pid: Option<u32>,
        handler: Option<&str>,
        branch: Option<&str>,
    ) -> String {
        let mut annotations = serde_json::Map::new();
        if let Some(h) = handler {
            annotations.insert(
                "run.oci.handler".to_string(),
                serde_json::Value::String(h.to_string()),
            );
        }
        if let Some(b) = branch {
            annotations.insert(
                "org.lobstertrap.puzzlepod.branch".to_string(),
                serde_json::Value::String(b.to_string()),
            );
        }

        let mut obj = serde_json::json!({
            "ociVersion": "1.0.2",
            "id": "test-container-abc123",
            "status": status,
            "bundle": "/run/containers/storage/overlay-containers/abc123/userdata",
            "annotations": annotations,
        });

        if let Some(p) = pid {
            obj["pid"] = serde_json::Value::Number(serde_json::Number::from(p));
        }

        serde_json::to_string(&obj).unwrap()
    }

    #[test]
    fn test_parse_oci_state_creating() {
        let json = make_oci_state_json("creating", Some(12345), Some("puzzlepod"), Some("br-001"));
        let state = parse_oci_state(json.as_bytes()).unwrap();

        assert_eq!(state.id, "test-container-abc123");
        assert_eq!(state.status, "creating");
        assert_eq!(state.pid, Some(12345));
        assert_eq!(state.oci_version, "1.0.2");
        assert!(state.annotations.contains_key("run.oci.handler"));
        assert_eq!(
            state
                .annotations
                .get("org.lobstertrap.puzzlepod.branch")
                .unwrap(),
            "br-001"
        );
    }

    #[test]
    fn test_parse_oci_state_stopped_no_pid() {
        let json = make_oci_state_json("stopped", None, Some("puzzlepod"), Some("br-002"));
        let state = parse_oci_state(json.as_bytes()).unwrap();

        assert_eq!(state.status, "stopped");
        assert_eq!(state.pid, None);
    }

    #[test]
    fn test_parse_oci_state_no_annotations() {
        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "id": "test-container-def456",
            "status": "creating",
            "pid": 99,
            "bundle": "/some/path"
        });
        let state = parse_oci_state(json.to_string().as_bytes()).unwrap();
        assert!(state.annotations.is_empty());
    }

    #[test]
    fn test_parse_oci_state_invalid_json() {
        let result = parse_oci_state(b"not valid json {{{");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to parse OCI state JSON"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_oci_state_missing_required_fields() {
        // Missing 'id' field
        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "status": "creating",
            "bundle": "/some/path"
        });
        let result = parse_oci_state(json.to_string().as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_is_puzzlepod_container_true() {
        let json = make_oci_state_json("creating", Some(1), Some("puzzlepod"), Some("br-1"));
        let state = parse_oci_state(json.as_bytes()).unwrap();
        assert!(is_puzzlepod_container(&state));
    }

    #[test]
    fn test_is_puzzlepod_container_false_wrong_value() {
        let json = make_oci_state_json("creating", Some(1), Some("other-handler"), Some("br-1"));
        let state = parse_oci_state(json.as_bytes()).unwrap();
        assert!(!is_puzzlepod_container(&state));
    }

    #[test]
    fn test_is_puzzlepod_container_false_no_annotation() {
        let json = make_oci_state_json("creating", Some(1), None, Some("br-1"));
        let state = parse_oci_state(json.as_bytes()).unwrap();
        assert!(!is_puzzlepod_container(&state));
    }

    #[test]
    fn test_is_puzzlepod_container_false_no_annotations_at_all() {
        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "id": "ctr-1",
            "status": "creating",
            "pid": 1,
            "bundle": "/b"
        });
        let state = parse_oci_state(json.to_string().as_bytes()).unwrap();
        assert!(!is_puzzlepod_container(&state));
    }

    #[test]
    fn test_extract_branch_id_present() {
        let json =
            make_oci_state_json("creating", Some(1), Some("puzzlepod"), Some("my-branch-42"));
        let state = parse_oci_state(json.as_bytes()).unwrap();
        assert_eq!(extract_branch_id(&state).unwrap(), "my-branch-42");
    }

    #[test]
    fn test_extract_branch_id_missing() {
        let json = make_oci_state_json("creating", Some(1), Some("puzzlepod"), None);
        let state = parse_oci_state(json.as_bytes()).unwrap();
        let result = extract_branch_id(&state);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing or empty"));
    }

    #[test]
    fn test_extract_branch_id_empty() {
        let json = make_oci_state_json("creating", Some(1), Some("puzzlepod"), Some(""));
        let state = parse_oci_state(json.as_bytes()).unwrap();
        let result = extract_branch_id(&state);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing or empty"));
    }

    #[test]
    fn test_determine_stage_creating() {
        assert_eq!(
            determine_stage("creating").unwrap(),
            HookStage::CreateRuntime
        );
    }

    #[test]
    fn test_determine_stage_stopped() {
        assert_eq!(determine_stage("stopped").unwrap(), HookStage::Poststop);
    }

    #[test]
    fn test_determine_stage_running() {
        let result = determine_stage("running");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("running"), "unexpected error: {err}");
        assert!(
            err.contains("unexpected OCI state status"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_determine_stage_created() {
        let result = determine_stage("created");
        assert!(result.is_ok(), "created should map to CreateRuntime");
        assert!(matches!(result.unwrap(), HookStage::CreateRuntime));
    }

    #[test]
    fn test_determine_stage_empty() {
        let result = determine_stage("");
        assert!(result.is_err());
    }

    /// Integration-style test: full parse + annotation check + stage detection
    /// for a createRuntime scenario.
    #[test]
    fn test_full_flow_create_runtime() {
        let json = make_oci_state_json("creating", Some(54321), Some("puzzlepod"), Some("br-xyz"));
        let state = parse_oci_state(json.as_bytes()).unwrap();

        assert!(is_puzzlepod_container(&state));
        assert_eq!(extract_branch_id(&state).unwrap(), "br-xyz");
        assert_eq!(
            determine_stage(&state.status).unwrap(),
            HookStage::CreateRuntime
        );
        assert_eq!(state.pid, Some(54321));
    }

    /// Integration-style test: full parse + annotation check + stage detection
    /// for a poststop scenario.
    #[test]
    fn test_full_flow_poststop() {
        let json = make_oci_state_json("stopped", None, Some("puzzlepod"), Some("br-final"));
        let state = parse_oci_state(json.as_bytes()).unwrap();

        assert!(is_puzzlepod_container(&state));
        assert_eq!(extract_branch_id(&state).unwrap(), "br-final");
        assert_eq!(determine_stage(&state.status).unwrap(), HookStage::Poststop);
        assert_eq!(state.pid, None);
    }

    /// Test that a non-puzzlepod container is correctly skipped.
    #[test]
    fn test_skip_non_puzzlepod_container() {
        let json = make_oci_state_json("creating", Some(100), Some("something-else"), Some("br"));
        let state = parse_oci_state(json.as_bytes()).unwrap();

        // Should not be identified as an puzzlepod container
        assert!(!is_puzzlepod_container(&state));
    }

    // G19: Branch ID validation tests
    #[test]
    fn test_g19_validate_branch_id_valid() {
        assert!(validate_branch_id("my-branch-42"));
        assert!(validate_branch_id("br_001"));
        assert!(validate_branch_id("a"));
    }

    #[test]
    fn test_g19_validate_branch_id_empty() {
        assert!(!validate_branch_id(""));
    }

    #[test]
    fn test_g19_validate_branch_id_slash() {
        assert!(!validate_branch_id("path/traversal"));
    }

    #[test]
    fn test_g19_validate_branch_id_dotdot() {
        assert!(!validate_branch_id(".."));
        assert!(!validate_branch_id("foo..bar"));
    }

    #[test]
    fn test_g19_validate_branch_id_null() {
        assert!(!validate_branch_id("abc\0def"));
    }

    #[test]
    fn test_g19_validate_branch_id_control_char() {
        assert!(!validate_branch_id("abc\x01def"));
        assert!(!validate_branch_id("abc\ndef"));
    }

    #[test]
    fn test_g19_validate_branch_id_too_long() {
        let long_id = "a".repeat(257);
        assert!(!validate_branch_id(&long_id));
        let exact_id = "a".repeat(256);
        assert!(validate_branch_id(&exact_id));
    }

    #[test]
    fn test_g19_extract_branch_id_rejects_invalid() {
        let json = make_oci_state_json("creating", Some(1), Some("puzzlepod"), Some("../escape"));
        let state = parse_oci_state(json.as_bytes()).unwrap();
        let result = extract_branch_id(&state);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("G19"),
            "error should mention G19 validation"
        );
    }

    /// Test that annotations with extra keys do not interfere.
    #[test]
    fn test_extra_annotations_ignored() {
        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "id": "ctr-extra",
            "status": "creating",
            "pid": 42,
            "bundle": "/b",
            "annotations": {
                "run.oci.handler": "puzzlepod",
                "org.lobstertrap.puzzlepod.branch": "br-extra",
                "org.lobstertrap.puzzlepod.profile": "standard",
                "io.kubernetes.pod.name": "my-pod",
                "some.other.annotation": "value"
            }
        });
        let state = parse_oci_state(json.to_string().as_bytes()).unwrap();

        assert!(is_puzzlepod_container(&state));
        assert_eq!(extract_branch_id(&state).unwrap(), "br-extra");
        assert_eq!(state.annotations.len(), 5);
    }
}
