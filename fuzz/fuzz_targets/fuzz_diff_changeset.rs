// SPDX-License-Identifier: Apache-2.0
//! Fuzz target: Diff engine changeset parsing.
//!
//! Feeds arbitrary file paths and metadata to the FileChange struct
//! to find edge cases in path handling (null bytes, traversal, unicode).
//!
//! Run: cargo +nightly fuzz run fuzz_diff_changeset

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Test FileChange deserialization with arbitrary JSON
        let _ = serde_json::from_str::<puzzled_types::FileChange>(s);

        // Test path construction with arbitrary strings
        let _ = std::path::PathBuf::from(s);
    }
});
