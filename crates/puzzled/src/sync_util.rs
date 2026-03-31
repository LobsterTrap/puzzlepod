// SPDX-License-Identifier: Apache-2.0
//! Concurrency utilities for the PuzzlePod daemon.

/// Recover from a poisoned mutex by extracting the inner guard.
///
/// S10: All PuzzlePod mutexes use this pattern to survive panics in other
/// threads. The poisoned state is expected and safe because we replace the
/// protected value (not read stale data) or the value is append-only.
pub(crate) fn unlock_poisoned<T>(result: std::sync::LockResult<T>) -> T {
    result.unwrap_or_else(|e| e.into_inner())
}
