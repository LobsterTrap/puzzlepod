// SPDX-License-Identifier: Apache-2.0
//! Integration tests: Fanotify behavioral monitoring (Linux-only, requires root).
//!
//! Tests that fanotify-based behavioral monitoring correctly detects
//! mass file deletion and fires BehavioralTrigger signals. All tests
//! are #[ignore] because they require root privileges and real fanotify
//! kernel infrastructure.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use puzzled_types::{BehavioralConfig, BehavioralTrigger, BranchId};

use puzzled::sandbox::fanotify::FanotifyMonitor;

/// Drop guard that sets the shutdown flag on drop (including panic unwind).
struct ShutdownGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// T3: Fanotify mass deletion trigger
// ---------------------------------------------------------------------------

/// Test that mass file deletion triggers a BehavioralTrigger::MassDeletion signal.
///
/// Creates a fanotify monitor on a temp directory, deletes files beyond the
/// threshold, and verifies that the MassDeletion trigger is fired.
#[tokio::test]
#[ignore] // Requires root + Linux with fanotify support
async fn test_mass_deletion_trigger() {
    let dir = tempfile::tempdir().unwrap();
    let merged_dir = dir.path().join("merged");
    std::fs::create_dir_all(&merged_dir).unwrap();

    // Create files to delete
    let threshold = 5u32;
    for i in 0..(threshold + 5) {
        let path = merged_dir.join(format!("file_{}.txt", i));
        std::fs::write(&path, format!("content {}", i)).unwrap();
    }

    let config = BehavioralConfig {
        max_deletions: threshold,
        max_reads_per_minute: 10000,
        credential_access_alert: true,
        phantom_token_prefixes: Vec::new(),
    };

    let branch_id = BranchId::from("mass-delete-test".to_string());

    let monitor = FanotifyMonitor::init(branch_id, merged_dir.clone(), config)
        .expect("fanotify init should succeed with root");

    let (mut rx, counters, _touched, _needs_full_diff, shutdown) = monitor.start();
    let _guard = ShutdownGuard(shutdown.clone());

    // T7: Poll for monitor readiness instead of hard-coded sleep.
    // The monitor is ready once it starts processing events.
    // We give it up to 5 seconds to start.
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(5) {
        // Create and delete a probe file to check if monitoring is active
        let probe = merged_dir.join(".probe_ready");
        let _ = std::fs::write(&probe, "probe");
        let _ = std::fs::remove_file(&probe);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if counters.deletions.load(Ordering::Relaxed) > 0 {
            // Reset the probe deletion count
            counters.deletions.store(0, Ordering::Relaxed);
            break;
        }
    }

    // Delete files beyond the threshold
    for i in 0..(threshold + 5) {
        let path = merged_dir.join(format!("file_{}.txt", i));
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
    }

    // T7: Poll for deletion count instead of hard-coded sleep
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let deletion_count = counters.deletions.load(Ordering::Relaxed);
        if deletion_count >= threshold {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Check that deletions were counted
    let deletion_count = counters.deletions.load(Ordering::Relaxed);
    assert!(
        deletion_count >= threshold,
        "expected at least {} deletions, got {}",
        threshold,
        deletion_count
    );

    // Check that a MassDeletion trigger was sent
    let mut found_trigger = false;
    while let Ok(trigger) = rx.try_recv() {
        if let BehavioralTrigger::MassDeletion {
            count,
            threshold: t,
        } = trigger
        {
            assert!(count >= threshold);
            assert_eq!(t, threshold);
            found_trigger = true;
            break;
        }
    }

    assert!(
        found_trigger,
        "expected MassDeletion behavioral trigger to be fired"
    );
}

/// Test that reads below threshold do not trigger ExcessiveReads.
#[tokio::test]
#[ignore] // Requires root + Linux with fanotify support
async fn test_reads_below_threshold_no_trigger() {
    let dir = tempfile::tempdir().unwrap();
    let merged_dir = dir.path().join("merged");
    std::fs::create_dir_all(&merged_dir).unwrap();

    let test_file = merged_dir.join("test.txt");
    std::fs::write(&test_file, "content").unwrap();

    let config = BehavioralConfig {
        max_deletions: 100,
        max_reads_per_minute: 1000, // high threshold
        credential_access_alert: false,
        phantom_token_prefixes: Vec::new(),
    };

    let branch_id = BranchId::from("reads-below".to_string());

    let monitor =
        FanotifyMonitor::init(branch_id, merged_dir, config).expect("fanotify init should succeed");

    let (mut rx, counters, _touched, _needs_full_diff, shutdown) = monitor.start();
    let _guard = ShutdownGuard(shutdown.clone());

    // T7: Poll for monitor readiness instead of hard-coded sleep
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let _ = std::fs::read_to_string(&test_file);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if counters.reads_this_minute.load(Ordering::Relaxed) > 0 {
            break;
        }
    }

    // Read a few more files (below threshold)
    for _ in 0..5 {
        let _ = std::fs::read_to_string(&test_file);
    }

    // T7: Poll for read count to stabilize
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let read_count = counters.reads_this_minute.load(Ordering::Relaxed);
        if read_count > 0 {
            break;
        }
    }

    // Reads should be counted
    let read_count = counters.reads_this_minute.load(Ordering::Relaxed);
    assert!(read_count > 0, "reads should be counted");
    assert!(read_count < 1000, "reads should be below threshold");

    // No ExcessiveReads trigger expected
    let mut found_excessive = false;
    while let Ok(trigger) = rx.try_recv() {
        if matches!(trigger, BehavioralTrigger::ExcessiveReads { .. }) {
            found_excessive = true;
        }
    }
    assert!(
        !found_excessive,
        "should not trigger ExcessiveReads below threshold"
    );
}

/// Test that credential file access triggers CredentialAccess alert.
#[tokio::test]
#[ignore] // Requires root + Linux with fanotify support
async fn test_credential_access_trigger() {
    let dir = tempfile::tempdir().unwrap();
    let merged_dir = dir.path().join("merged");
    let ssh_dir = merged_dir.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();

    // Create a credential-like file
    let cred_file = ssh_dir.join("id_rsa");
    std::fs::write(&cred_file, "fake ssh key").unwrap();

    let config = BehavioralConfig {
        max_deletions: 100,
        max_reads_per_minute: 10000,
        credential_access_alert: true,
        phantom_token_prefixes: Vec::new(),
    };

    let branch_id = BranchId::from("cred-access-test".to_string());

    let monitor =
        FanotifyMonitor::init(branch_id, merged_dir, config).expect("fanotify init should succeed");

    let (mut rx, counters, _touched, _needs_full_diff, shutdown) = monitor.start();
    let _guard = ShutdownGuard(shutdown.clone());

    // T7: Poll for monitor readiness instead of hard-coded sleep
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Touch a non-credential file to check if monitoring is active
        let probe = dir.path().join("merged").join("probe.txt");
        let _ = std::fs::write(&probe, "x");
        let _ = std::fs::read_to_string(&probe);
        if counters.reads_this_minute.load(Ordering::Relaxed) > 0 {
            break;
        }
    }

    // Read the credential file
    let _ = std::fs::read_to_string(&cred_file);

    // T7: Poll for credential access detection with timeout
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if counters.credential_accesses.load(Ordering::Relaxed) > 0 {
            break;
        }
    }

    let cred_count = counters.credential_accesses.load(Ordering::Relaxed);

    // T7: Remove conditional assertion — either detection works or it fails.
    // fanotify with FAN_REPORT_FID may not resolve the path to include the
    // credential pattern on all kernels, so we assert on the counter and
    // the trigger channel independently.
    assert!(
        cred_count > 0,
        "credential access counter should be > 0 after reading id_rsa"
    );

    // Check for CredentialAccess trigger
    let mut found_cred = false;
    while let Ok(trigger) = rx.try_recv() {
        if matches!(trigger, BehavioralTrigger::CredentialAccess { .. }) {
            found_cred = true;
        }
    }

    assert!(
        found_cred,
        "credential access should trigger CredentialAccess alert"
    );
}

/// Test that behavioral counters reset correctly.
#[test]
fn test_behavioral_counters_reset() {
    use puzzled::sandbox::fanotify::BehavioralCounters;

    let counters = BehavioralCounters::new();

    // Increment reads
    counters.reads_this_minute.fetch_add(500, Ordering::Relaxed);
    assert_eq!(counters.reads_this_minute.load(Ordering::Relaxed), 500);

    // Increment deletions
    counters.deletions.fetch_add(10, Ordering::Relaxed);

    // Reset reads
    counters.reset_reads();
    assert_eq!(
        counters.reads_this_minute.load(Ordering::Relaxed),
        0,
        "reads should be reset to 0"
    );

    // Deletions should NOT be reset
    assert_eq!(
        counters.deletions.load(Ordering::Relaxed),
        10,
        "deletions should not be affected by reset_reads"
    );
}

/// Test touched files tracking.
#[test]
fn test_touched_files_tracking() {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    let touched = Arc::new(Mutex::new(HashSet::new()));

    {
        let mut set = touched.lock().unwrap();
        set.insert(PathBuf::from("/merged/file1.txt"));
        set.insert(PathBuf::from("/merged/file2.txt"));
        set.insert(PathBuf::from("/merged/file1.txt")); // duplicate
    }

    let set = touched.lock().unwrap();
    assert_eq!(set.len(), 2, "duplicates should be deduplicated");
    assert!(set.contains(&PathBuf::from("/merged/file1.txt")));
    assert!(set.contains(&PathBuf::from("/merged/file2.txt")));
}
