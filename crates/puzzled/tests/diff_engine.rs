// SPDX-License-Identifier: Apache-2.0
//! Integration test: DiffEngine complex scenarios.
//!
//! Tests nested directories, binary files, special characters in filenames,
//! and large changesets.

use std::fs;
use std::path::{Path, PathBuf};

use puzzled_types::FileChangeKind;

#[test]
fn test_nested_directory_changes() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Create deeply nested structure
    let deep = upper.path().join("a").join("b").join("c").join("d");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("deep_file.txt"), "deep content").unwrap();

    // Also create a file at the top level
    fs::write(upper.path().join("top.txt"), "top content").unwrap();

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert_eq!(changes.len(), 2);
    assert!(changes.iter().all(|c| c.kind == FileChangeKind::Added));

    let paths: Vec<String> = changes
        .iter()
        .map(|c| c.path.display().to_string())
        .collect();
    assert!(paths.iter().any(|p| p.contains("deep_file.txt")));
    assert!(paths.iter().any(|p| p == "top.txt"));
}

#[test]
fn test_binary_file_detection() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Write binary content
    let binary_content: Vec<u8> = (0..256).map(|i| i as u8).collect();
    fs::write(upper.path().join("binary.bin"), &binary_content).unwrap();

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, FileChangeKind::Added);
    assert_eq!(changes[0].size, 256);
    assert!(!changes[0].checksum.is_empty());
}

#[test]
fn test_special_characters_in_filenames() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Files with special characters (avoiding OS-restricted chars)
    let special_names = vec![
        "file with spaces.txt",
        "file-with-dashes.txt",
        "file_with_underscores.txt",
        "file.multiple.dots.txt",
        "UPPERCASE.TXT",
    ];

    for name in &special_names {
        fs::write(upper.path().join(name), format!("content of {}", name)).unwrap();
    }

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert_eq!(changes.len(), special_names.len());
    assert!(changes.iter().all(|c| c.kind == FileChangeKind::Added));
}

#[test]
fn test_empty_file() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    fs::write(upper.path().join("empty.txt"), "").unwrap();

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, FileChangeKind::Added);
    assert_eq!(changes[0].size, 0);
}

#[test]
fn test_mixed_operations() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Setup lower (base) layer
    fs::write(lower.path().join("existing.txt"), "original").unwrap();
    fs::write(lower.path().join("to_delete.txt"), "will be deleted").unwrap();

    // Setup upper layer
    fs::write(upper.path().join("new_file.txt"), "brand new").unwrap(); // Added
    fs::write(upper.path().join("existing.txt"), "modified content").unwrap(); // Modified
    fs::write(upper.path().join(".wh.to_delete.txt"), "").unwrap(); // Deleted (whiteout)

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert_eq!(changes.len(), 3);

    let added = changes
        .iter()
        .find(|c| c.kind == FileChangeKind::Added)
        .unwrap();
    assert_eq!(added.path, PathBuf::from("new_file.txt"));

    let modified = changes
        .iter()
        .find(|c| c.kind == FileChangeKind::Modified)
        .unwrap();
    assert_eq!(modified.path, PathBuf::from("existing.txt"));

    let deleted = changes
        .iter()
        .find(|c| c.kind == FileChangeKind::Deleted)
        .unwrap();
    assert_eq!(deleted.path, PathBuf::from("to_delete.txt"));
}

#[test]
fn test_large_changeset() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Create 100 files
    for i in 0..100 {
        fs::write(
            upper.path().join(format!("file_{:03}.txt", i)),
            format!("content {}", i),
        )
        .unwrap();
    }

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert_eq!(changes.len(), 100);
    assert!(changes.iter().all(|c| c.kind == FileChangeKind::Added));
}

#[test]
fn test_symlink_in_upper() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Create a regular file and a symlink to it
    let target = upper.path().join("target.txt");
    fs::write(&target, "target content").unwrap();

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, upper.path().join("link.txt")).unwrap();
    }

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    // Should include the target file at minimum
    assert!(!changes.is_empty());
    assert!(changes.iter().any(|c| c.path == Path::new("target.txt")));
}

#[test]
fn test_whiteout_in_subdirectory() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Delete a file that was in a subdirectory
    let subdir = upper.path().join("subdir");
    fs::create_dir_all(&subdir).unwrap();
    fs::write(subdir.join(".wh.deleted_in_subdir.txt"), "").unwrap();

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, FileChangeKind::Deleted);
    assert_eq!(
        changes[0].path,
        PathBuf::from("subdir").join("deleted_in_subdir.txt")
    );
}
