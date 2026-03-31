// SPDX-License-Identifier: Apache-2.0
//! Integration test: IMA sign/verify roundtrip.
//!
//! Tests that ImaIntegration::sign_commit() and ImaIntegration::verify_manifest()
//! roundtrip correctly for valid changesets, and that tampered manifests are
//! detected.

use std::path::PathBuf;

use puzzled_types::{BranchId, FileChange, FileChangeKind};

/// Helper to create an ImaIntegration instance in a temp directory.
fn make_ima(dir: &std::path::Path) -> puzzled::ima::ImaIntegration {
    let manifest_dir = dir.join("manifests");
    let key_path = dir.join("signing_key");
    puzzled::ima::ImaIntegration::new(manifest_dir, &key_path).unwrap()
}

/// Helper to create a sample changeset.
fn sample_changes() -> Vec<FileChange> {
    vec![
        FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 2048,
            checksum: "abc123def456".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
        FileChange {
            path: PathBuf::from("README.md"),
            kind: FileChangeKind::Added,
            size: 512,
            checksum: "789abc012def".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
        FileChange {
            path: PathBuf::from("old_config.yaml"),
            kind: FileChangeKind::Deleted,
            size: 0,
            checksum: "".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// T1: Sign and verify roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_sign_verify_roundtrip_basic() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("roundtrip-basic".to_string());
    let changes = sample_changes();

    let manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Verify the manifest content
    assert_eq!(manifest.branch_id, "roundtrip-basic");
    assert_eq!(manifest.files.len(), 3);
    assert!(!manifest.signature.is_empty());
    assert!(!manifest.timestamp.is_empty());

    // Verify the signature
    ima.verify_manifest(&manifest).unwrap();
}

#[test]
fn test_sign_verify_roundtrip_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("single-file".to_string());
    let changes = vec![FileChange {
        path: PathBuf::from("hello.txt"),
        kind: FileChangeKind::Added,
        size: 13,
        checksum: "d41d8cd98f00".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
        entropy: None,
        has_base64_blocks: None,
    }];

    let manifest = ima.sign_commit(&branch_id, &changes).unwrap();
    assert_eq!(manifest.files.len(), 1);
    ima.verify_manifest(&manifest).unwrap();
}

#[test]
fn test_sign_verify_roundtrip_empty_changeset() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("empty-changeset".to_string());
    let changes: Vec<FileChange> = vec![];

    let manifest = ima.sign_commit(&branch_id, &changes).unwrap();
    assert_eq!(manifest.files.len(), 0);
    ima.verify_manifest(&manifest).unwrap();
}

#[test]
fn test_sign_verify_roundtrip_all_change_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("all-kinds".to_string());
    let changes = vec![
        FileChange {
            path: PathBuf::from("added.txt"),
            kind: FileChangeKind::Added,
            size: 100,
            checksum: "aaa".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
        FileChange {
            path: PathBuf::from("modified.txt"),
            kind: FileChangeKind::Modified,
            size: 200,
            checksum: "bbb".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
        FileChange {
            path: PathBuf::from("deleted.txt"),
            kind: FileChangeKind::Deleted,
            size: 0,
            checksum: "".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
        FileChange {
            path: PathBuf::from("metadata.txt"),
            kind: FileChangeKind::MetadataChanged,
            size: 300,
            checksum: "ccc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
        FileChange {
            path: PathBuf::from("renamed.txt"),
            kind: FileChangeKind::Renamed,
            size: 400,
            checksum: "ddd".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        },
    ];

    let manifest = ima.sign_commit(&branch_id, &changes).unwrap();
    assert_eq!(manifest.files.len(), 5);
    ima.verify_manifest(&manifest).unwrap();
}

// ---------------------------------------------------------------------------
// T1: Tampered manifest detection
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_manifest_file_size() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("tamper-size".to_string());
    let changes = sample_changes();

    let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Tamper with file size
    manifest.files[0].size = 999999;
    assert!(
        ima.verify_manifest(&manifest).is_err(),
        "tampered file size should fail verification"
    );
}

#[test]
fn test_tampered_manifest_file_path() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("tamper-path".to_string());
    let changes = sample_changes();

    let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Tamper with file path
    manifest.files[0].path = "/etc/shadow".to_string();
    assert!(
        ima.verify_manifest(&manifest).is_err(),
        "tampered file path should fail verification"
    );
}

#[test]
fn test_tampered_manifest_checksum() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("tamper-checksum".to_string());
    let changes = sample_changes();

    let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Tamper with checksum
    manifest.files[0].checksum = "tampered_checksum".to_string();
    assert!(
        ima.verify_manifest(&manifest).is_err(),
        "tampered checksum should fail verification"
    );
}

#[test]
fn test_tampered_manifest_branch_id() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("tamper-branch".to_string());
    let changes = sample_changes();

    let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Tamper with branch ID
    manifest.branch_id = "different-branch".to_string();
    assert!(
        ima.verify_manifest(&manifest).is_err(),
        "tampered branch_id should fail verification"
    );
}

#[test]
fn test_tampered_manifest_timestamp() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("tamper-timestamp".to_string());
    let changes = sample_changes();

    let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Tamper with timestamp
    manifest.timestamp = "2000-01-01T00:00:00Z".to_string();
    assert!(
        ima.verify_manifest(&manifest).is_err(),
        "tampered timestamp should fail verification"
    );
}

#[test]
fn test_tampered_manifest_added_file() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("tamper-add-file".to_string());
    let changes = sample_changes();

    let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Add an extra file to the manifest
    manifest.files.push(puzzled::ima::ManifestEntry {
        path: "injected.txt".to_string(),
        kind: "added".to_string(),
        size: 1,
        checksum: "xxx".to_string(),
    });

    assert!(
        ima.verify_manifest(&manifest).is_err(),
        "manifest with injected file should fail verification"
    );
}

#[test]
fn test_tampered_manifest_removed_file() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("tamper-remove-file".to_string());
    let changes = sample_changes();

    let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Remove a file from the manifest
    manifest.files.pop();

    assert!(
        ima.verify_manifest(&manifest).is_err(),
        "manifest with removed file should fail verification"
    );
}

// ---------------------------------------------------------------------------
// T1: Key persistence and cross-instance verification
// ---------------------------------------------------------------------------

#[test]
fn test_key_persistence_cross_instance_verify() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_dir = dir.path().join("manifests");
    let key_path = dir.path().join("signing_key");

    // First instance signs
    let ima1 = puzzled::ima::ImaIntegration::new(manifest_dir.clone(), &key_path).unwrap();
    let branch_id = BranchId::from("cross-instance".to_string());
    let changes = sample_changes();
    let manifest = ima1.sign_commit(&branch_id, &changes).unwrap();

    // Second instance (same key file) verifies
    let ima2 = puzzled::ima::ImaIntegration::new(manifest_dir, &key_path).unwrap();
    ima2.verify_manifest(&manifest).unwrap();
}

#[test]
fn test_different_key_fails_verification() {
    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();

    // Sign with key from dir1
    let ima1 = make_ima(dir1.path());
    let branch_id = BranchId::from("diff-key".to_string());
    let changes = sample_changes();
    let manifest = ima1.sign_commit(&branch_id, &changes).unwrap();

    // Verify with a different key from dir2
    let ima2 = make_ima(dir2.path());
    assert!(
        ima2.verify_manifest(&manifest).is_err(),
        "verification with a different key should fail"
    );
}

#[test]
fn test_manifest_saved_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());

    let branch_id = BranchId::from("disk-test".to_string());
    let changes = sample_changes();

    ima.sign_commit(&branch_id, &changes).unwrap();

    // Verify the manifest YAML file was written
    let manifest_path = dir.path().join("manifests").join("disk-test.manifest.yaml");
    assert!(
        manifest_path.exists(),
        "manifest file should be written to disk"
    );

    // Verify it can be deserialized
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let loaded: puzzled::ima::CommitManifest = serde_yaml::from_str(&content).unwrap();
    assert_eq!(loaded.branch_id, "disk-test");
    assert_eq!(loaded.files.len(), 3);
}

#[test]
fn test_verify_manifest_with_pubkey() {
    let dir = tempfile::tempdir().unwrap();
    let ima = make_ima(dir.path());
    let pubkey_hex = ima.public_key_hex();

    let branch_id = BranchId::from("pubkey-verify".to_string());
    let changes = sample_changes();
    let manifest = ima.sign_commit(&branch_id, &changes).unwrap();

    // Verify using static public key hex
    puzzled::ima::ImaIntegration::verify_manifest_with_pubkey(&manifest, &pubkey_hex).unwrap();

    // Tamper and verify it fails
    let mut tampered = manifest;
    tampered.files[0].size = 0;
    assert!(
        puzzled::ima::ImaIntegration::verify_manifest_with_pubkey(&tampered, &pubkey_hex).is_err()
    );
}
