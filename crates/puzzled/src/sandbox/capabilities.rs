// SPDX-License-Identifier: Apache-2.0
//! Capability dropping and credential switching for agent sandboxes.
//!
//! After clone3(), Landlock, and seccomp are applied, the child process
//! must drop all unnecessary capabilities and switch to the agent's
//! non-root UID/GID. Without this, the agent runs as root with full
//! capabilities, which undermines all other sandbox layers.

use crate::error::{PuzzledError, Result};

/// Drop all capabilities from the bounding set except those in `keep`.
///
/// Uses `prctl(PR_CAPBSET_DROP)` to remove each capability from the
/// bounding set. This is irreversible — once dropped, the capability
/// cannot be re-acquired by the process or its children.
///
/// Typical `keep` for restricted agents: empty (no capabilities retained).
/// Standard agents may retain `CAP_NET_BIND_SERVICE` if needed.
#[cfg(target_os = "linux")]
pub fn drop_capabilities(keep: &[u32]) -> Result<()> {
    // CAP_LAST_CAP is typically 40-41 on modern kernels; iterate to 63 for safety
    const MAX_CAP: u32 = 63;

    // Step 1: Drop capabilities from the bounding set.
    // CRITICAL: PR_CAPBSET_DROP requires CAP_SETPCAP (cap 8) in the effective
    // set. This function must be called BEFORE setuid() (which clears
    // effective/permitted) — see drop_bounding_set() for the pre-setuid path.
    // If called after setuid, bounding set drops will silently fail.
    // This is irreversible — once dropped, the capability cannot be
    // re-acquired by the process or its children.
    let mut dropped = 0u32;
    for cap in 0..=MAX_CAP {
        if keep.contains(&cap) {
            continue;
        }

        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret == 0 {
            dropped += 1;
        }
        // EINVAL means the capability doesn't exist on this kernel — skip
    }

    // Step 2: Clear the effective and permitted capability sets.
    clear_effective_and_permitted_sets(keep)?;

    // Step 3: Clear the ambient capability set (prevents re-acquisition via execve)
    let ret = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL on older kernels that don't support ambient caps — non-fatal
        if err.raw_os_error() != Some(libc::EINVAL) {
            tracing::warn!(error = %err, "failed to clear ambient capabilities");
        }
    }

    // Step 4: Set NO_NEW_PRIVS to prevent privilege escalation via setuid binaries
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        return Err(PuzzledError::Sandbox(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Verify the bounding set is empty (except for kept caps) by checking
    // each capability with PR_CAPBSET_READ. This belt-and-suspenders check
    // catches cases where a capability was not successfully dropped.
    let mut remaining = Vec::new();
    for cap in 0..=MAX_CAP {
        if keep.contains(&cap) {
            continue;
        }
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if ret > 0 {
            remaining.push(cap);
        }
    }
    if !remaining.is_empty() {
        tracing::warn!(
            remaining = ?remaining,
            "capabilities still present in bounding set after drop"
        );
    }

    tracing::info!(
        dropped,
        kept = keep.len(),
        remaining_caps = remaining.len(),
        "capabilities dropped — effective, permitted, and bounding sets cleared"
    );

    Ok(())
}

/// Drop all capabilities from the bounding set except those in `keep`.
///
/// MUST be called BEFORE setuid() / switch_credentials(), because
/// PR_CAPBSET_DROP requires CAP_SETPCAP (cap 8) in the effective set.
/// setuid() to a non-root user clears effective/permitted, making
/// subsequent PR_CAPBSET_DROP calls fail with EPERM.
#[cfg(target_os = "linux")]
pub fn drop_bounding_set(keep: &[u32]) -> Result<()> {
    const MAX_CAP: u32 = 63;

    let mut dropped = 0u32;
    for cap in 0..=MAX_CAP {
        if keep.contains(&cap) {
            continue;
        }

        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret == 0 {
            dropped += 1;
        }
        // EINVAL means the capability doesn't exist on this kernel — skip
    }

    // Verify the bounding set is cleared
    let mut remaining = Vec::new();
    for cap in 0..=MAX_CAP {
        if keep.contains(&cap) {
            continue;
        }
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if ret > 0 {
            remaining.push(cap);
        }
    }
    if !remaining.is_empty() {
        return Err(PuzzledError::Sandbox(format!(
            "failed to drop {} capabilities from bounding set: {:?}",
            remaining.len(),
            remaining
        )));
    }

    tracing::info!(
        dropped,
        kept = keep.len(),
        "bounding set capabilities dropped"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_bounding_set(_keep: &[u32]) -> Result<()> {
    Err(PuzzledError::Sandbox(
        "capability dropping requires Linux".to_string(),
    ))
}

/// Clear the effective and permitted capability sets using capget/capset.
///
/// The correct order for full capability removal is:
///   1. Clear effective set (so no capabilities are active)
///   2. Clear permitted set (so no capabilities can be raised to effective)
///   3. Drop bounding set entries (handled by caller)
///
/// Capabilities in `keep` are retained in both effective and permitted sets
/// (needed if the agent profile requires them, e.g., CAP_NET_BIND_SERVICE).
#[cfg(target_os = "linux")]
fn clear_effective_and_permitted_sets(keep: &[u32]) -> Result<()> {
    // Linux capability data structures for capget/capset (v3, 64-bit)
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // _LINUX_CAPABILITY_VERSION_3 (0x20080522) — supports caps 0..63 via two data structs
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // current process
    };

    // capget/capset with v3 uses two CapUserData structs (caps 0-31 and 32-63)
    let mut data = [CapUserData::default(); 2];

    // Get current capabilities so we know what the kernel reports
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapUserHeader,
            data.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(PuzzledError::Sandbox(format!(
            "capget failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    tracing::debug!(
        effective_lo = format!("{:#010x}", data[0].effective),
        effective_hi = format!("{:#010x}", data[1].effective),
        permitted_lo = format!("{:#010x}", data[0].permitted),
        permitted_hi = format!("{:#010x}", data[1].permitted),
        "current capability sets before clearing"
    );

    // Build bitmasks for capabilities to keep
    let mut keep_lo: u32 = 0;
    let mut keep_hi: u32 = 0;
    for &cap in keep {
        if cap < 32 {
            keep_lo |= 1 << cap;
        } else if cap < 64 {
            keep_hi |= 1 << (cap - 32);
        }
    }

    // Clear effective set (only retain kept caps that were already permitted)
    data[0].effective = keep_lo & data[0].permitted;
    data[1].effective = keep_hi & data[1].permitted;

    // Clear permitted set (only retain kept caps)
    data[0].permitted &= keep_lo;
    data[1].permitted &= keep_hi;

    // Clear inheritable set entirely (agents should not pass caps to children)
    data[0].inheritable = 0;
    data[1].inheritable = 0;

    // Apply the cleared capability sets
    header.version = LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapUserHeader,
            data.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(PuzzledError::Sandbox(format!(
            "capset failed (clearing effective/permitted): {}",
            std::io::Error::last_os_error()
        )));
    }

    tracing::debug!(
        effective_lo = format!("{:#010x}", data[0].effective),
        effective_hi = format!("{:#010x}", data[1].effective),
        permitted_lo = format!("{:#010x}", data[0].permitted),
        permitted_hi = format!("{:#010x}", data[1].permitted),
        "capability sets after clearing effective and permitted"
    );

    Ok(())
}

/// Switch the process to a non-root UID/GID.
///
/// Calls setgroups(0, NULL) -> setgid(gid) -> setuid(uid) in the
/// correct order (gid first, since setuid drops the ability to setgid).
///
/// After this call, the process runs as the specified non-root user
/// and cannot regain root privileges (due to NO_NEW_PRIVS + dropped caps).
///
/// If `reject_root` is true and uid=0, returns an error (for FailClosed profiles).
/// Otherwise, uid=0 is allowed with a warning.
#[cfg(target_os = "linux")]
pub fn switch_credentials(uid: u32, gid: u32, reject_root: bool) -> Result<()> {
    if uid == 0 {
        if reject_root {
            return Err(PuzzledError::Sandbox(
                "refusing to run agent as root (FailClosed profile requires non-root UID)"
                    .to_string(),
            ));
        }
        tracing::warn!("switch_credentials called with uid=0, agent will run as root");
        return Ok(());
    }

    // Clear supplementary groups
    let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
    if ret < 0 {
        return Err(PuzzledError::Sandbox(format!(
            "setgroups(0) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Set GID first (setuid drops ability to change GID)
    let ret = unsafe { libc::setgid(gid) };
    if ret < 0 {
        return Err(PuzzledError::Sandbox(format!(
            "setgid({}) failed: {}",
            gid,
            std::io::Error::last_os_error()
        )));
    }

    // Set UID last
    let ret = unsafe { libc::setuid(uid) };
    if ret < 0 {
        return Err(PuzzledError::Sandbox(format!(
            "setuid({}) failed: {}",
            uid,
            std::io::Error::last_os_error()
        )));
    }

    tracing::info!(uid, gid, "credentials switched to non-root");
    Ok(())
}

/// M8: Map a capability name string to its numeric value.
///
/// Accepts both "CAP_NET_BIND_SERVICE" and "NET_BIND_SERVICE" forms.
/// Returns None for unrecognized capability names.
pub fn cap_name_to_number(name: &str) -> Option<u32> {
    // Strip optional "CAP_" prefix for convenience
    let name = name.strip_prefix("CAP_").unwrap_or(name);
    match name {
        "CHOWN" => Some(0),
        "DAC_OVERRIDE" => Some(1),
        "DAC_READ_SEARCH" => Some(2),
        "FOWNER" => Some(3),
        "FSETID" => Some(4),
        "KILL" => Some(5),
        "SETGID" => Some(6),
        "SETUID" => Some(7),
        "SETPCAP" => Some(8),
        "LINUX_IMMUTABLE" => Some(9),
        "NET_BIND_SERVICE" => Some(10),
        "NET_BROADCAST" => Some(11),
        "NET_ADMIN" => Some(12),
        "NET_RAW" => Some(13),
        "IPC_LOCK" => Some(14),
        "IPC_OWNER" => Some(15),
        "SYS_MODULE" => Some(16),
        "SYS_RAWIO" => Some(17),
        "SYS_CHROOT" => Some(18),
        "SYS_PTRACE" => Some(19),
        "SYS_PACCT" => Some(20),
        "SYS_ADMIN" => Some(21),
        "SYS_BOOT" => Some(22),
        "SYS_NICE" => Some(23),
        "SYS_RESOURCE" => Some(24),
        "SYS_TIME" => Some(25),
        "SYS_TTY_CONFIG" => Some(26),
        "MKNOD" => Some(27),
        "LEASE" => Some(28),
        "AUDIT_WRITE" => Some(29),
        "AUDIT_CONTROL" => Some(30),
        "SETFCAP" => Some(31),
        "MAC_OVERRIDE" => Some(32),
        "MAC_ADMIN" => Some(33),
        "SYSLOG" => Some(34),
        "WAKE_ALARM" => Some(35),
        "BLOCK_SUSPEND" => Some(36),
        "AUDIT_READ" => Some(37),
        "PERFMON" => Some(38),
        "BPF" => Some(39),
        "CHECKPOINT_RESTORE" => Some(40),
        _ => {
            tracing::warn!(capability = name, "unrecognized capability name");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn drop_capabilities(_keep: &[u32]) -> Result<()> {
    Err(PuzzledError::Sandbox(
        "capability dropping requires Linux".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn switch_credentials(_uid: u32, _gid: u32, _reject_root: bool) -> Result<()> {
    Err(PuzzledError::Sandbox(
        "credential switching requires Linux".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_drop_capabilities_non_root() {
        // On non-Linux or non-root, drop_capabilities should fail gracefully
        // or succeed (prctl returns EINVAL for non-existent caps)
        #[cfg(not(target_os = "linux"))]
        {
            let result = super::drop_capabilities(&[]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_switch_credentials_uid_zero_noop() {
        #[cfg(target_os = "linux")]
        {
            // uid=0 with reject_root=false should be a no-op (with a warning)
            let result = super::switch_credentials(0, 0, false);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_switch_credentials_uid_zero_rejected() {
        #[cfg(target_os = "linux")]
        {
            // uid=0 with reject_root=true should fail (FailClosed mode)
            let result = super::switch_credentials(0, 0, true);
            assert!(result.is_err());
        }
    }

    /// M8: Test capability name to number mapping.
    #[test]
    fn test_cap_name_to_number() {
        // With CAP_ prefix
        assert_eq!(super::cap_name_to_number("CAP_CHOWN"), Some(0));
        assert_eq!(super::cap_name_to_number("CAP_NET_BIND_SERVICE"), Some(10));
        assert_eq!(super::cap_name_to_number("CAP_NET_RAW"), Some(13));
        assert_eq!(super::cap_name_to_number("CAP_SYS_CHROOT"), Some(18));
        assert_eq!(super::cap_name_to_number("CAP_SYS_PTRACE"), Some(19));
        assert_eq!(super::cap_name_to_number("CAP_SYS_ADMIN"), Some(21));
        assert_eq!(super::cap_name_to_number("CAP_SYS_RESOURCE"), Some(24));
        assert_eq!(super::cap_name_to_number("CAP_AUDIT_WRITE"), Some(29));
        assert_eq!(super::cap_name_to_number("CAP_AUDIT_READ"), Some(37));

        // Without CAP_ prefix
        assert_eq!(super::cap_name_to_number("DAC_OVERRIDE"), Some(1));
        assert_eq!(super::cap_name_to_number("FOWNER"), Some(3));
        assert_eq!(super::cap_name_to_number("SETUID"), Some(7));

        // Unknown
        assert_eq!(super::cap_name_to_number("NONEXISTENT"), None);
        assert_eq!(super::cap_name_to_number("CAP_NONEXISTENT"), None);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_drop_bounding_set_non_linux() {
        let result = super::drop_bounding_set(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("requires Linux"),
            "expected Linux error, got: {}",
            err
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_switch_credentials_non_linux() {
        let result = super::switch_credentials(1000, 1000, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("requires Linux"),
            "expected Linux error, got: {}",
            err
        );
    }

    #[test]
    fn test_cap_name_to_number_completeness() {
        // Verify all 41 capabilities (0..=40) are mapped
        let all_names = [
            "CHOWN",
            "DAC_OVERRIDE",
            "DAC_READ_SEARCH",
            "FOWNER",
            "FSETID",
            "KILL",
            "SETGID",
            "SETUID",
            "SETPCAP",
            "LINUX_IMMUTABLE",
            "NET_BIND_SERVICE",
            "NET_BROADCAST",
            "NET_ADMIN",
            "NET_RAW",
            "IPC_LOCK",
            "IPC_OWNER",
            "SYS_MODULE",
            "SYS_RAWIO",
            "SYS_CHROOT",
            "SYS_PTRACE",
            "SYS_PACCT",
            "SYS_ADMIN",
            "SYS_BOOT",
            "SYS_NICE",
            "SYS_RESOURCE",
            "SYS_TIME",
            "SYS_TTY_CONFIG",
            "MKNOD",
            "LEASE",
            "AUDIT_WRITE",
            "AUDIT_CONTROL",
            "SETFCAP",
            "MAC_OVERRIDE",
            "MAC_ADMIN",
            "SYSLOG",
            "WAKE_ALARM",
            "BLOCK_SUSPEND",
            "AUDIT_READ",
            "PERFMON",
            "BPF",
            "CHECKPOINT_RESTORE",
        ];

        for (expected_num, name) in all_names.iter().enumerate() {
            assert_eq!(
                super::cap_name_to_number(name),
                Some(expected_num as u32),
                "cap_name_to_number({}) should return {}",
                name,
                expected_num
            );
        }
    }

    #[test]
    fn test_cap_name_to_number_empty_string() {
        assert_eq!(super::cap_name_to_number(""), None);
    }

    #[test]
    fn test_cap_name_to_number_case_sensitive() {
        // Lowercase should not match
        assert_eq!(super::cap_name_to_number("chown"), None);
        assert_eq!(super::cap_name_to_number("cap_chown"), None);
        // Only uppercase works
        assert_eq!(super::cap_name_to_number("CAP_CHOWN"), Some(0));
    }

    #[test]
    fn test_cap_name_to_number_double_prefix() {
        // "CAP_CAP_CHOWN" should strip one CAP_ prefix, leaving "CAP_CHOWN" which won't match
        assert_eq!(super::cap_name_to_number("CAP_CAP_CHOWN"), None);
    }

    /// M8: Verify all documented capabilities from the fix specification.
    #[test]
    fn test_cap_name_to_number_all_specified() {
        let specified = [
            ("CAP_CHOWN", 0),
            ("CAP_DAC_OVERRIDE", 1),
            ("CAP_DAC_READ_SEARCH", 2),
            ("CAP_FOWNER", 3),
            ("CAP_FSETID", 4),
            ("CAP_KILL", 5),
            ("CAP_SETGID", 6),
            ("CAP_SETUID", 7),
            ("CAP_SETPCAP", 8),
            ("CAP_NET_BIND_SERVICE", 10),
            ("CAP_NET_RAW", 13),
            ("CAP_SYS_CHROOT", 18),
            ("CAP_SYS_PTRACE", 19),
            ("CAP_SYS_ADMIN", 21),
            ("CAP_SYS_RESOURCE", 24),
            ("CAP_AUDIT_WRITE", 29),
            ("CAP_AUDIT_READ", 37),
        ];

        for (name, expected) in &specified {
            assert_eq!(
                super::cap_name_to_number(name),
                Some(*expected),
                "cap_name_to_number({}) should return {}",
                name,
                expected
            );
        }
    }
}
