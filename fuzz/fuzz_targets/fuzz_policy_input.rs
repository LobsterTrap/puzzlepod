// SPDX-License-Identifier: Apache-2.0
//! Fuzz target: OPA/Rego policy evaluation input.
//!
//! Feeds arbitrary JSON as policy input to find panics or unexpected
//! behavior in the policy engine (regorus).
//!
//! Run: cargo +nightly fuzz run fuzz_policy_input

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to parse as a JSON changeset and evaluate policy
        if let Ok(changes) = serde_json::from_str::<Vec<puzzled_types::FileChange>>(s) {
            let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("policies/rules");
            if policy_dir.exists() {
                let engine = puzzled::policy::PolicyEngine::new(&policy_dir);
                if let Ok(engine) = engine {
                    let _ = engine.evaluate(&changes, None);
                }
            }
        }
    }
});
