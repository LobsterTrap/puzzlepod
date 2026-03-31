// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use crate::error::Result;

/// Status of an enforcement mechanism setup attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// Mechanism was successfully configured.
    Active,
    /// Mechanism was not available but setup continued (best-effort).
    Unavailable(String),
}

/// XFS project quota manager — enforces per-branch storage and inode limits
/// on the OverlayFS upper layer directory.
///
/// Returns `EnforcementStatus` to let callers decide whether a failure
/// is fatal based on the profile's `EnforcementRequirements`.
pub struct QuotaManager;

impl QuotaManager {
    /// Set up XFS project quotas for a branch upper directory.
    ///
    /// 1. Assign a unique project ID to the upper dir via FS_IOC_FSSETXATTR
    /// 2. Set block limit (storage_quota_mb) via quotactl(Q_XSETPQLIM)
    /// 3. Set inode limit (inode_quota) via quotactl(Q_XSETPQLIM)
    ///
    /// Returns `EnforcementStatus::Active` on success, or
    /// `EnforcementStatus::Unavailable` with a reason if quotas are not available.
    /// Callers should check the profile's `require_quota` to decide if
    /// `Unavailable` is fatal.
    #[cfg(target_os = "linux")]
    pub fn setup(
        upper_dir: &Path,
        storage_quota_mb: u64,
        inode_quota: u64,
    ) -> Result<EnforcementStatus> {
        use std::ffi::CString;

        // Try to detect if we're on XFS with project quotas enabled
        let dir_str = upper_dir.to_string_lossy().to_string();
        let _c_path = match CString::new(dir_str.as_str()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    path = %upper_dir.display(),
                    error = %e,
                    "XFS quota setup skipped: invalid path"
                );
                return Ok(EnforcementStatus::Unavailable(format!("invalid path: {e}")));
            }
        };

        // Generate a deterministic project ID from the directory path (SHA-256).
        // SHA-256 is used instead of DefaultHasher because DefaultHasher (SipHash)
        // is seeded with per-process random bytes — hash values differ across runs
        // and Rust versions, breaking crash recovery.
        let project_id = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(upper_dir.to_string_lossy().as_bytes());
            u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
        };

        // Try to set the project ID via FS_IOC_FSSETXATTR ioctl
        // This requires the directory to be on XFS with prjquota mount option
        let fd = match std::fs::File::open(upper_dir) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    path = %upper_dir.display(),
                    error = %e,
                    "XFS quota setup skipped: cannot open directory"
                );
                return Ok(EnforcementStatus::Unavailable(format!(
                    "cannot open directory: {e}"
                )));
            }
        };

        // FS_IOC_FSSETXATTR = 0x40100020 (set extended attributes)
        const FS_IOC_FSSETXATTR: libc::c_ulong = 0x40100020;
        const FSX_PROJID: u32 = 0x04;

        #[repr(C)]
        struct FsxAttr {
            fsx_xflags: u32,
            fsx_extsize: u32,
            fsx_nextents: u32,
            fsx_projid: u32,
            fsx_cowextsize: u32,
            fsx_pad: [u8; 8],
        }

        let attr = FsxAttr {
            fsx_xflags: FSX_PROJID,
            fsx_extsize: 0,
            fsx_nextents: 0,
            fsx_projid: project_id,
            fsx_cowextsize: 0,
            fsx_pad: [0; 8],
        };

        use std::os::unix::io::AsRawFd;
        let ret =
            unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_FSSETXATTR, &attr as *const FsxAttr) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                path = %upper_dir.display(),
                project_id,
                error = %err,
                "XFS project ID assignment failed (best-effort, continuing)"
            );
            return Ok(EnforcementStatus::Unavailable(format!(
                "FS_IOC_FSSETXATTR failed: {err}"
            )));
        }

        // Set project quota limits via quotactl(Q_XSETPQLIM).
        // If this fails after FS_IOC_FSSETXATTR succeeded, the project ID is
        // assigned but limits are not enforced — report as Unavailable so the
        // caller can decide based on the profile's require_quota setting.
        if let Err(reason) =
            Self::set_project_quota(upper_dir, project_id, storage_quota_mb, inode_quota)
        {
            tracing::warn!(
                path = %upper_dir.display(),
                project_id,
                error = %reason,
                "XFS project ID assigned but quotactl failed"
            );
            return Ok(EnforcementStatus::Unavailable(format!(
                "project ID set but quota limits failed: {reason}"
            )));
        }

        tracing::info!(
            path = %upper_dir.display(),
            project_id,
            storage_quota_mb,
            inode_quota,
            "XFS project quota configured"
        );

        Ok(EnforcementStatus::Active)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn setup(
        upper_dir: &Path,
        _storage_quota_mb: u64,
        _inode_quota: u64,
    ) -> Result<EnforcementStatus> {
        tracing::warn!(
            path = %upper_dir.display(),
            "XFS quota setup skipped: not on Linux"
        );
        Ok(EnforcementStatus::Unavailable("not on Linux".to_string()))
    }

    /// Set XFS project quota limits via quotactl(Q_XSETPQLIM).
    ///
    /// Returns `Ok(())` on success, or `Err(reason)` if quotactl fails
    /// (e.g., not on XFS, quotas not enabled, insufficient privileges).
    #[cfg(target_os = "linux")]
    fn set_project_quota(
        upper_dir: &Path,
        project_id: u32,
        storage_quota_mb: u64,
        inode_quota: u64,
    ) -> std::result::Result<(), String> {
        use std::ffi::CString;

        // Q_XSETPQLIM = QCMD(Q_XSETQLIM, PRJQUOTA) = 0x00800005
        const Q_XSETPQLIM: libc::c_int = 0x00800005_u32 as i32;

        #[repr(C)]
        struct FsDiskQuota {
            d_version: i8,
            d_flags: i8,
            d_fieldmask: u16,
            d_id: u32,
            d_blk_hardlimit: u64,
            d_blk_softlimit: u64,
            d_ino_hardlimit: u64,
            d_ino_softlimit: u64,
            d_bcount: u64,
            d_icount: u64,
            d_itimer: i32,
            d_btimer: i32,
            d_iwarns: u16,
            d_bwarns: u16,
            d_padding2: i32,
            d_rtb_hardlimit: u64,
            d_rtb_softlimit: u64,
            d_rtbcount: u64,
            d_rtbtimer: i32,
            d_rtbwarns: u16,
            d_padding3: i16,
            d_padding4: [i8; 8],
        }

        let dq = FsDiskQuota {
            d_version: 1,             // FS_DQUOT_VERSION
            d_flags: 2,               // XFS_PROJ_QUOTA
            d_fieldmask: 0x08 | 0x80, // FS_DQ_BHARD | FS_DQ_IHARD
            d_id: project_id,
            // A4: XFS quota d_blk_hardlimit is always in "basic blocks" (512 bytes),
            // regardless of the filesystem's actual block size. This is the XFS quota
            // interface convention (see fs/xfs/xfs_dquot.h: XFS_FSB_TO_BB). Conversion:
            // MB * 1024 (KB/MB) * 2 (512-byte blocks per KB) = MB * 2048 basic blocks.
            d_blk_hardlimit: storage_quota_mb * 1024 * 2,
            d_blk_softlimit: 0,
            d_ino_hardlimit: inode_quota,
            d_ino_softlimit: 0,
            d_bcount: 0,
            d_icount: 0,
            d_itimer: 0,
            d_btimer: 0,
            d_iwarns: 0,
            d_bwarns: 0,
            d_padding2: 0,
            d_rtb_hardlimit: 0,
            d_rtb_softlimit: 0,
            d_rtbcount: 0,
            d_rtbtimer: 0,
            d_rtbwarns: 0,
            d_padding3: 0,
            d_padding4: [0; 8],
        };

        let dev = Self::find_block_device(upper_dir)
            .ok_or_else(|| "could not determine block device for quota enforcement".to_string())?;

        let c_dev = CString::new(dev.as_str())
            .map_err(|_| "invalid block device path for quotactl".to_string())?;

        let ret = unsafe {
            libc::quotactl(
                Q_XSETPQLIM,
                c_dev.as_ptr(),
                // R1: Mask high bit to prevent sign wrap when casting u32 -> i32.
                // XFS project IDs above 0x7FFF_FFFF would become negative i32,
                // causing quotactl to fail or apply to the wrong project.
                (project_id & 0x7FFF_FFFF) as i32,
                &dq as *const FsDiskQuota as *mut libc::c_char,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("quotactl(Q_XSETPQLIM) failed: {err}"));
        }

        Ok(())
    }

    /// Find the block device for the filesystem containing the given path
    /// by reading /proc/mounts.
    #[cfg(target_os = "linux")]
    fn find_block_device(path: &Path) -> Option<String> {
        let path_str = path.to_string_lossy();
        let mounts = std::fs::read_to_string("/proc/mounts").ok()?;

        let mut best_match: Option<(&str, &str)> = None;
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let mount_point = parts[1];
            if path_str.starts_with(mount_point)
                && best_match
                    .map(|(_, mp)| mount_point.len() > mp.len())
                    .unwrap_or(true)
            {
                best_match = Some((parts[0], mount_point));
            }
        }

        best_match.map(|(dev, _)| dev.to_string())
    }

    /// Remove project quota for a branch (best-effort cleanup).
    ///
    /// 1. Zero out quota limits via quotactl(Q_XSETPQLIM) with b_hard=0, i_hard=0
    /// 2. Reset project ID to 0 via FS_IOC_FSSETXATTR
    ///
    /// Errors are logged but never propagated — rollback must not fail due to
    /// quota cleanup issues.
    #[cfg(target_os = "linux")]
    pub fn remove(upper_dir: &Path) -> Result<()> {
        // Recompute the same deterministic project ID used during setup
        let project_id = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(upper_dir.to_string_lossy().as_bytes());
            u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
        };

        // Step 1: Zero out quota limits via quotactl(Q_XSETPQLIM)
        if let Err(e) = Self::set_project_quota(upper_dir, project_id, 0, 0) {
            tracing::warn!(
                path = %upper_dir.display(),
                project_id,
                error = %e,
                "best-effort quota limit cleanup failed"
            );
        }

        // Step 2: Reset project ID to 0 via FS_IOC_FSSETXATTR
        const FS_IOC_FSSETXATTR: libc::c_ulong = 0x40100020;

        #[repr(C)]
        struct FsxAttr {
            fsx_xflags: u32,
            fsx_extsize: u32,
            fsx_nextents: u32,
            fsx_projid: u32,
            fsx_cowextsize: u32,
            fsx_pad: [u8; 8],
        }

        let attr = FsxAttr {
            fsx_xflags: 0,
            fsx_extsize: 0,
            fsx_nextents: 0,
            fsx_projid: 0,
            fsx_cowextsize: 0,
            fsx_pad: [0; 8],
        };

        match std::fs::File::open(upper_dir) {
            Ok(fd) => {
                use std::os::unix::io::AsRawFd;
                let ret = unsafe {
                    libc::ioctl(fd.as_raw_fd(), FS_IOC_FSSETXATTR, &attr as *const FsxAttr)
                };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    tracing::warn!(
                        path = %upper_dir.display(),
                        error = %err,
                        "best-effort project ID reset failed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    path = %upper_dir.display(),
                    error = %e,
                    "best-effort quota cleanup skipped: cannot open directory"
                );
            }
        }

        tracing::debug!(
            path = %upper_dir.display(),
            project_id,
            "XFS quota cleanup completed (best-effort)"
        );
        Ok(())
    }

    /// Remove project quota for a branch (no-op on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn remove(upper_dir: &Path) -> Result<()> {
        tracing::debug!(
            path = %upper_dir.display(),
            "XFS quota cleanup skipped (not on Linux)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_quota_remove_always_ok() {
        // remove() should return Ok for any path, even nonexistent ones
        let result = QuotaManager::remove(&PathBuf::from("/nonexistent/path"));
        assert!(result.is_ok(), "remove() should always return Ok");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_quota_setup_non_linux() {
        // On non-Linux, setup() should return Ok with Unavailable status
        let result = QuotaManager::setup(&PathBuf::from("/tmp/fake-upper"), 1024, 10000);
        assert!(result.is_ok(), "setup() should return Ok on non-Linux");
        assert!(
            matches!(result.unwrap(), EnforcementStatus::Unavailable(_)),
            "non-Linux should return Unavailable"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_quota_setup_unavailable_message() {
        let result = QuotaManager::setup(&PathBuf::from("/tmp/fake"), 512, 5000).unwrap();
        match result {
            EnforcementStatus::Unavailable(msg) => {
                assert!(
                    msg.contains("not on Linux"),
                    "expected 'not on Linux' in message, got: {}",
                    msg
                );
            }
            EnforcementStatus::Active => panic!("expected Unavailable on non-Linux"),
        }
    }

    #[test]
    fn test_enforcement_status_equality() {
        assert_eq!(EnforcementStatus::Active, EnforcementStatus::Active);
        assert_eq!(
            EnforcementStatus::Unavailable("a".to_string()),
            EnforcementStatus::Unavailable("a".to_string())
        );
        assert_ne!(
            EnforcementStatus::Active,
            EnforcementStatus::Unavailable("x".to_string())
        );
    }

    #[test]
    fn test_enforcement_status_debug() {
        let active = format!("{:?}", EnforcementStatus::Active);
        assert!(active.contains("Active"));

        let unavail = format!(
            "{:?}",
            EnforcementStatus::Unavailable("test reason".to_string())
        );
        assert!(unavail.contains("Unavailable"));
        assert!(unavail.contains("test reason"));
    }

    #[test]
    fn test_enforcement_status_clone() {
        let original = EnforcementStatus::Unavailable("cloned".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_quota_remove_multiple_paths() {
        // remove() should always return Ok regardless of path
        for path in &["/nonexistent", "/tmp/a/b/c/d/e", "", "/sys/fs/cgroup/fake"] {
            let result = QuotaManager::remove(&PathBuf::from(path));
            assert!(result.is_ok(), "remove({}) should return Ok", path);
        }
    }
}
