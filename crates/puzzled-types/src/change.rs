// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zbus::zvariant::Type;

// ---------------------------------------------------------------------------
// Filesystem diff
// ---------------------------------------------------------------------------

/// Kind of change detected in the OverlayFS upper layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum FileChangeKind {
    /// m4: PRD canonical name is "Created"; "Added" kept as primary for backward compat.
    #[serde(alias = "Created")]
    Added,
    Modified,
    Deleted,
    /// m5: PRD canonical name is "PermissionChanged"; "MetadataChanged" kept as primary.
    #[serde(alias = "PermissionChanged")]
    MetadataChanged,
    /// File was renamed (OverlayFS redirect xattr).
    Renamed,
    /// H9: Symbolic link detected in changeset. Rejected by default unless
    /// the agent profile sets `allow_symlinks: true`.
    Symlink,
    /// Q6: Hard link (nlink > 1) detected in changeset.
    Hardlink,
    /// Q6: Block device special file detected in changeset.
    BlockDevice,
    /// Q6: Character device special file detected in changeset.
    CharDevice,
    /// Q6: Named pipe (FIFO) detected in changeset.
    Fifo,
}

/// A single file change in a branch diff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileChange {
    /// Path relative to the branch root.
    pub path: PathBuf,
    pub kind: FileChangeKind,
    /// Size in bytes (0 for deletions).
    pub size: u64,
    /// Size of the file in the base layer (for Modified changes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_size: Option<u64>,
    /// File mode in the base layer (for Modified/MetadataChanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_mode: Option<u32>,
    /// File mode in the upper layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_mode: Option<u32>,
    /// SHA-256 checksum of file contents (empty for deletions).
    pub checksum: String,
    /// RFC 3339 timestamp of the file modification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// K60: Symlink target path (only populated for Symlink changes).
    /// Included in Rego input so policies can validate symlink destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Shannon entropy of file content (0.0-8.0). Only set for Added/Modified text files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// Whether the file contains base64 blocks longer than 64 chars.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_base64_blocks: Option<bool>,
}

impl Default for FileChange {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            kind: FileChangeKind::Added,
            size: 0,
            old_size: None,
            old_mode: None,
            new_mode: None,
            checksum: String::new(),
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        }
    }
}

impl FileChange {
    /// Create a `FileChange` with the given path, kind, and size.
    ///
    /// All optional fields default to `None` and checksum defaults to empty.
    /// Use struct update syntax to override additional fields:
    /// ```
    /// # use puzzled_types::{FileChange, FileChangeKind};
    /// let change = FileChange::new("/app/main.py", FileChangeKind::Modified, 1024);
    /// ```
    pub fn new(path: impl Into<PathBuf>, kind: FileChangeKind, size: u64) -> Self {
        Self {
            path: path.into(),
            kind,
            size,
            ..Default::default()
        }
    }
}
