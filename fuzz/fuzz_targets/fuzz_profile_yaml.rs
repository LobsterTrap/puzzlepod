// SPDX-License-Identifier: Apache-2.0
//! Fuzz target: YAML profile deserialization.
//!
//! Feeds arbitrary bytes to the YAML profile parser to find panics,
//! infinite loops, or excessive memory allocation in serde_yaml.
//!
//! Run: cargo +nightly fuzz run fuzz_profile_yaml

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to parse as an AgentProfile YAML
        let _ = serde_yaml::from_str::<puzzled_types::AgentProfile>(s);
    }
});
