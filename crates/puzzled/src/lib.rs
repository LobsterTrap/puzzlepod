// SPDX-License-Identifier: Apache-2.0
//! PuzzlePod governance daemon — library interface.
//!
//! Re-exports internal modules for integration testing.
//! The binary entry point is in `main.rs`.

pub mod attestation;
pub mod audit;
pub mod audit_store;
pub mod branch;
pub mod budget;
pub mod commit;
pub mod config;
pub mod conflict;
pub mod dbus;
pub mod diff;
pub mod error;
pub mod identity;
pub mod ima;
pub mod landlock_rules;
pub mod metrics;
pub mod policy;
pub mod profile;
pub mod provenance;
pub mod sandbox;
pub mod seccomp_handler;
pub mod seccomp_profile;
pub(crate) mod sync_util;
pub mod trust;
pub mod wal;

#[cfg(test)]
pub mod test_helpers;
