// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

/// Top-level error type for the puzzled daemon.
///
/// Variants that wrap `String` are legacy — prefer the typed source-preserving
/// variants (e.g., `SerdeJson`, `SerdeYaml`) where possible.  Existing
/// `PuzzledError::Foo(format!(...))` call sites remain valid and can be migrated
/// incrementally.
#[derive(Debug, Error)]
pub enum PuzzledError {
    #[error("branch error: {0}")]
    Branch(String),

    #[error("sandbox setup error: {0}")]
    Sandbox(String),

    #[error("policy evaluation error: {0}")]
    Policy(String),

    #[error("commit error: {0}")]
    Commit(String),

    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("WAL error: {0}")]
    Wal(String),

    #[error("diff error: {0}")]
    Diff(String),

    #[error("profile error: {0}")]
    Profile(String),

    #[error("IMA error: {0}")]
    Ima(String),

    #[error("BPF LSM error: {0}")]
    BpfLsm(String),

    #[error("seccomp notification error: {0}")]
    SeccompNotif(String),

    #[error("fanotify error: {0}")]
    Fanotify(String),

    #[error("conflict error: {0}")]
    Conflict(String),

    #[error("budget error: {0}")]
    Budget(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("audit store error: {0}")]
    AuditStore(String),

    #[error("attestation error: {0}")]
    Attestation(String),

    #[error("trust error: {0}")]
    Trust(String),

    #[error("provenance error: {0}")]
    Provenance(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("YAML parsing error: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),

    #[error("directory walk error: {0}")]
    WalkDir(#[from] walkdir::Error),
}

pub type Result<T> = std::result::Result<T, PuzzledError>;

#[cfg(test)]
mod tests {
    use super::*;

    // --- Each error variant can be created ---

    #[test]
    fn create_branch_error() {
        let _e = PuzzledError::Branch("test".into());
    }

    #[test]
    fn create_sandbox_error() {
        let _e = PuzzledError::Sandbox("test".into());
    }

    #[test]
    fn create_policy_error() {
        let _e = PuzzledError::Policy("test".into());
    }

    #[test]
    fn create_commit_error() {
        let _e = PuzzledError::Commit("test".into());
    }

    #[test]
    fn create_config_error() {
        let _e = PuzzledError::Config("test".into());
    }

    #[test]
    fn create_wal_error() {
        let _e = PuzzledError::Wal("test".into());
    }

    #[test]
    fn create_diff_error() {
        let _e = PuzzledError::Diff("test".into());
    }

    #[test]
    fn create_profile_error() {
        let _e = PuzzledError::Profile("test".into());
    }

    #[test]
    fn create_ima_error() {
        let _e = PuzzledError::Ima("test".into());
    }

    #[test]
    fn create_bpf_lsm_error() {
        let _e = PuzzledError::BpfLsm("test".into());
    }

    #[test]
    fn create_seccomp_notif_error() {
        let _e = PuzzledError::SeccompNotif("test".into());
    }

    #[test]
    fn create_fanotify_error() {
        let _e = PuzzledError::Fanotify("test".into());
    }

    #[test]
    fn create_conflict_error() {
        let _e = PuzzledError::Conflict("test".into());
    }

    #[test]
    fn create_budget_error() {
        let _e = PuzzledError::Budget("test".into());
    }

    #[test]
    fn create_network_error() {
        let _e = PuzzledError::Network("test".into());
    }

    #[test]
    fn create_audit_error() {
        let _e = PuzzledError::Audit("test".into());
    }

    #[test]
    fn create_audit_store_error() {
        let _e = PuzzledError::AuditStore("test".into());
    }

    #[test]
    fn create_attestation_error() {
        let _e = PuzzledError::Attestation("test".into());
    }

    #[test]
    fn create_not_found_error() {
        let _e = PuzzledError::NotFound("test".into());
    }

    #[test]
    fn create_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let _e = PuzzledError::Io(io_err);
    }

    // --- Display formatting ---

    #[test]
    fn display_branch() {
        let e = PuzzledError::Branch("bad branch".into());
        assert_eq!(e.to_string(), "branch error: bad branch");
    }

    #[test]
    fn display_sandbox() {
        let e = PuzzledError::Sandbox("ns failed".into());
        assert_eq!(e.to_string(), "sandbox setup error: ns failed");
    }

    #[test]
    fn display_policy() {
        let e = PuzzledError::Policy("denied".into());
        assert_eq!(e.to_string(), "policy evaluation error: denied");
    }

    #[test]
    fn display_commit() {
        let e = PuzzledError::Commit("wal fail".into());
        assert_eq!(e.to_string(), "commit error: wal fail");
    }

    #[test]
    fn display_config() {
        let e = PuzzledError::Config("missing key".into());
        assert_eq!(e.to_string(), "configuration error: missing key");
    }

    #[test]
    fn display_wal() {
        let e = PuzzledError::Wal("corrupt".into());
        assert_eq!(e.to_string(), "WAL error: corrupt");
    }

    #[test]
    fn display_diff() {
        let e = PuzzledError::Diff("empty".into());
        assert_eq!(e.to_string(), "diff error: empty");
    }

    #[test]
    fn display_profile() {
        let e = PuzzledError::Profile("invalid".into());
        assert_eq!(e.to_string(), "profile error: invalid");
    }

    #[test]
    fn display_ima() {
        let e = PuzzledError::Ima("no key".into());
        assert_eq!(e.to_string(), "IMA error: no key");
    }

    #[test]
    fn display_bpf_lsm() {
        let e = PuzzledError::BpfLsm("load failed".into());
        assert_eq!(e.to_string(), "BPF LSM error: load failed");
    }

    #[test]
    fn display_seccomp_notif() {
        let e = PuzzledError::SeccompNotif("fd closed".into());
        assert_eq!(e.to_string(), "seccomp notification error: fd closed");
    }

    #[test]
    fn display_fanotify() {
        let e = PuzzledError::Fanotify("mark fail".into());
        assert_eq!(e.to_string(), "fanotify error: mark fail");
    }

    #[test]
    fn display_conflict() {
        let e = PuzzledError::Conflict("merge conflict".into());
        assert_eq!(e.to_string(), "conflict error: merge conflict");
    }

    #[test]
    fn display_budget() {
        let e = PuzzledError::Budget("exceeded".into());
        assert_eq!(e.to_string(), "budget error: exceeded");
    }

    #[test]
    fn display_network() {
        let e = PuzzledError::Network("timeout".into());
        assert_eq!(e.to_string(), "network error: timeout");
    }

    #[test]
    fn display_audit() {
        let e = PuzzledError::Audit("write fail".into());
        assert_eq!(e.to_string(), "audit error: write fail");
    }

    #[test]
    fn display_audit_store() {
        let e = PuzzledError::AuditStore("full".into());
        assert_eq!(e.to_string(), "audit store error: full");
    }

    #[test]
    fn display_attestation() {
        let e = PuzzledError::Attestation("merkle error".into());
        assert_eq!(e.to_string(), "attestation error: merkle error");
    }

    #[test]
    fn display_not_found() {
        let e = PuzzledError::NotFound("branch-42".into());
        assert_eq!(e.to_string(), "not found: branch-42");
    }

    #[test]
    fn display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope");
        let e = PuzzledError::Io(io_err);
        assert_eq!(e.to_string(), "I/O error: nope");
    }

    // --- Debug formatting ---

    #[test]
    fn debug_format_works() {
        let e = PuzzledError::Branch("x".into());
        let debug = format!("{:?}", e);
        assert!(debug.contains("Branch"));
    }

    #[test]
    fn debug_format_io() {
        let io_err = std::io::Error::other("oops");
        let e = PuzzledError::Io(io_err);
        let debug = format!("{:?}", e);
        assert!(debug.contains("Io"));
    }

    // --- From conversions ---

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let e: PuzzledError = io_err.into();
        assert!(matches!(e, PuzzledError::Io(_)));
        assert!(e.to_string().contains("broken"));
    }

    #[test]
    fn from_zbus_error() {
        // zbus::Error::Address is a simple variant we can construct without a live bus
        let zbus_err = zbus::Error::Address("bad address".into());
        let e: PuzzledError = zbus_err.into();
        assert!(matches!(e, PuzzledError::Dbus(_)));
        assert!(e.to_string().contains("D-Bus error"));
    }

    // --- Result type alias ---

    #[test]
    fn result_ok() {
        let r: Result<i32> = Ok(42);
        match r {
            Ok(val) => assert_eq!(val, 42),
            Err(e) => panic!("expected Ok, got Err: {}", e),
        }
    }

    #[test]
    fn result_err() {
        let r: Result<i32> = Err(PuzzledError::NotFound("nope".into()));
        assert!(r.is_err());
    }

    #[test]
    fn result_with_question_mark() {
        fn inner() -> Result<String> {
            let _ = Ok::<_, PuzzledError>("hello".to_string())?;
            Err(PuzzledError::Config("test".into()))
        }
        assert!(inner().is_err());
    }

    // --- Error is Send + Sync (required for async contexts) ---

    #[test]
    fn error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PuzzledError>();
    }

    #[test]
    fn error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<PuzzledError>();
    }

    // --- std::error::Error trait ---

    #[test]
    fn implements_std_error() {
        let e = PuzzledError::Branch("test".into());
        let _dyn_err: &dyn std::error::Error = &e;
    }

    #[test]
    fn source_for_io_error() {
        let io_err = std::io::Error::other("inner");
        let e = PuzzledError::Io(io_err);
        // thiserror #[from] sets up source() delegation
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn source_for_string_variant_is_none() {
        let e = PuzzledError::Branch("no source".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    // --- New typed error variants ---

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{bad}}").unwrap_err();
        let e: PuzzledError = json_err.into();
        assert!(matches!(e, PuzzledError::SerdeJson(_)));
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn from_serde_yaml_error() {
        let yaml_err = serde_yaml::from_str::<serde_json::Value>(":\n  :\n    :").unwrap_err();
        let e: PuzzledError = yaml_err.into();
        assert!(matches!(e, PuzzledError::SerdeYaml(_)));
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn from_walkdir_error() {
        // walkdir::Error cannot be constructed directly, but we can test the variant exists
        fn accepts_walkdir_err(e: walkdir::Error) -> PuzzledError {
            e.into()
        }
        let _ = accepts_walkdir_err; // compile-time check
    }
}
