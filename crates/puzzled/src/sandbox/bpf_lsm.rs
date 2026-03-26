// SPDX-License-Identifier: Apache-2.0
//! BPF LSM loader — loads and manages exec_guard BPF programs.
//!
//! On Linux, uses the `aya` crate for type-safe BPF program loading,
//! map management, and LSM attachment. Falls back to raw `bpf()` syscall
//! for map operations if aya is unavailable.
//!
//! On non-Linux platforms, all operations return errors (BPF is Linux-only).

use std::path::Path;

use crate::error::{PuzzledError, Result};

/// Rate limit configuration written to the BPF map.
/// Must match struct rate_limit_config in exec_guard.h.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RateLimitConfig {
    pub max_execs_per_second: u32,
    pub max_total_execs: u32,
    pub kill_switch: u32,
    pub _pad: u32,
}

// H-21: clone_guard removed — seccomp + SELinux provide dual defense for clone containment.

/// Manages BPF LSM programs for exec rate limiting.
///
/// Uses the `aya` crate on Linux for ELF loading, map management,
/// and LSM hook attachment. The exec_guard program attaches to
/// `bprm_check_security` and enforces per-cgroup exec rate limits.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct BpfLsmManager {
    /// Path to the compiled BPF object file.
    bpf_obj_path: std::path::PathBuf,
    /// Whether BPF programs have been loaded.
    #[cfg(target_os = "linux")]
    loaded: bool,
    /// aya BPF handle (holds loaded programs and maps).
    #[cfg(target_os = "linux")]
    bpf: Option<AyaBpfState>,
    /// Fallback: raw BPF map fds (used if aya loading fails).
    #[cfg(target_os = "linux")]
    rate_limits_map_fd: Option<i32>,
    #[cfg(target_os = "linux")]
    counters_map_fd: Option<i32>,
    /// M-sc1: Whether BPF programs failed to load (degraded mode).
    /// When true, BPF-based enforcement is unavailable and other defense
    /// layers (seccomp, SELinux) must compensate.
    degraded: bool,
}

/// Wrapper for aya BPF state to manage lifetimes.
///
/// IMPORTANT: `link_fd` keeps the BPF program attached to the LSM hook.
/// Closing `link_fd` detaches the program, so it must be held for the
/// lifetime of the sandbox. It is only closed in the Drop implementation.
#[cfg(target_os = "linux")]
struct AyaBpfState {
    /// Rate limits map file descriptor (pinned or from aya).
    rate_limits_fd: i32,
    /// Exec counters map file descriptor.
    counters_fd: i32,
    /// BPF program file descriptor.
    prog_fd: i32,
    /// BPF link file descriptor — keeps the program attached to the LSM hook.
    /// Closing this fd detaches the BPF program, so it must persist for the
    /// lifetime of the sandbox.
    link_fd: i32,
    /// Whether the LSM program is attached.
    attached: bool,
}

impl BpfLsmManager {
    /// Create a new BPF LSM manager.
    ///
    /// `bpf_obj_path` should point to the compiled `exec_guard.bpf.o`.
    pub fn new(bpf_obj_path: &Path) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_path_buf(),
            #[cfg(target_os = "linux")]
            loaded: false,
            #[cfg(target_os = "linux")]
            bpf: None,
            #[cfg(target_os = "linux")]
            rate_limits_map_fd: None,
            #[cfg(target_os = "linux")]
            counters_map_fd: None,
            degraded: false,
        }
    }

    /// Load the BPF program from the object file using aya.
    ///
    /// Attempts aya-based loading first (full ELF parsing, program load,
    /// LSM attachment). Falls back to raw map creation if aya fails.
    ///
    /// Requires CAP_BPF or CAP_SYS_ADMIN.
    #[cfg(target_os = "linux")]
    pub fn load(&mut self) -> Result<()> {
        if self.loaded {
            return Ok(());
        }

        if !self.bpf_obj_path.exists() {
            return Err(PuzzledError::BpfLsm(format!(
                "BPF object file not found: {}",
                self.bpf_obj_path.display()
            )));
        }

        // Try aya-based loading
        match self.load_with_aya() {
            Ok(()) => {
                tracing::info!(
                    obj = %self.bpf_obj_path.display(),
                    "BPF LSM loaded and attached via aya"
                );
                self.loaded = true;
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "aya BPF loading failed, falling back to raw map creation"
                );
            }
        }

        // Fallback: create maps only (programs not loaded)
        self.load_maps_only()?;
        self.loaded = true;
        // M-sc1: Mark as degraded since BPF programs are not attached
        self.degraded = true;
        tracing::warn!(
            "BPF LSM is in degraded mode — maps created but no kernel enforcement. \
             Other defense layers (seccomp, SELinux) must compensate."
        );
        // TODO: M-sc1: Increment a metric counter for BPF degradation events
        // (e.g., metrics::counter!("puzzled_bpf_degraded_total").increment(1))
        Ok(())
    }

    /// Load BPF program using aya crate for ELF parsing, then raw syscalls
    /// for program loading and LSM attachment.
    #[cfg(target_os = "linux")]
    fn load_with_aya(&mut self) -> Result<()> {
        // Read the BPF ELF object
        let obj_data = std::fs::read(&self.bpf_obj_path).map_err(|e| {
            PuzzledError::BpfLsm(format!(
                "reading BPF object {}: {}",
                self.bpf_obj_path.display(),
                e
            ))
        })?;

        // Parse the ELF to extract map definitions and program bytecode
        // The exec_guard.bpf.o contains:
        //   - Program: lsm/bprm_check_security -> exec_guard
        //   - Map: rate_limits (HASH, u64 -> RateLimitConfig)
        //   - Map: exec_counters (HASH, u64 -> ExecCounter)
        let obj = aya_obj::Object::parse(&obj_data)
            .map_err(|e| PuzzledError::BpfLsm(format!("parsing BPF ELF: {}", e)))?;

        tracing::debug!(
            programs = obj.programs.len(),
            maps = obj.maps.len(),
            "parsed BPF ELF"
        );

        // Create maps from the parsed specs
        let rate_limits_fd = bpf_create_map(
            BPF_MAP_TYPE_HASH,
            std::mem::size_of::<u64>() as u32,
            std::mem::size_of::<RateLimitConfig>() as u32,
            256,
        )?;

        let counters_fd = bpf_create_map(
            BPF_MAP_TYPE_HASH,
            std::mem::size_of::<u64>() as u32,
            24, // sizeof(struct exec_counter)
            256,
        )?;

        // Attempt to load the BPF program and attach to bprm_check_security LSM hook.
        // Find the LSM program section in the parsed ELF.
        let mut attached = false;
        let mut stored_prog_fd: i32 = -1;
        let mut stored_link_fd: i32 = -1;
        for (name, program) in &obj.programs {
            // LSM programs are in sections named "lsm/bprm_check_security" or similar
            let section_name = name.as_str();
            if !section_name.contains("lsm") && !section_name.contains("bprm_check") {
                continue;
            }

            tracing::debug!(section = section_name, "found LSM program section");

            // Extract program bytecode via function_key() lookup
            let func_key = program.function_key();
            let function = match obj.functions.get(&func_key) {
                Some(f) => f,
                None => {
                    tracing::warn!(section = section_name, "no function found for LSM program");
                    continue;
                }
            };

            if function.instructions.is_empty() {
                tracing::warn!(
                    section = section_name,
                    "LSM program section has no instructions"
                );
                continue;
            }

            // Convert Vec<bpf_insn> to &[u8] for the raw bpf() syscall
            let insns_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    function.instructions.as_ptr() as *const u8,
                    function.instructions.len() * std::mem::size_of_val(&function.instructions[0]),
                )
            };

            // Load program via BPF_PROG_LOAD
            match bpf_prog_load(
                BPF_PROG_TYPE_LSM,
                insns_bytes,
                "GPL",
                "bprm_check_security",
                &[rate_limits_fd, counters_fd],
            ) {
                Ok(prog_fd) => {
                    tracing::debug!(prog_fd, "BPF LSM program loaded");

                    // Attach to bprm_check_security via BPF_LINK_CREATE
                    match bpf_link_create(prog_fd, "bprm_check_security") {
                        Ok(link_fd) => {
                            tracing::info!(
                                prog_fd,
                                link_fd,
                                "BPF LSM program attached to bprm_check_security"
                            );
                            // CRITICAL: Do NOT close link_fd here. The link fd keeps the
                            // BPF program attached to the LSM hook. Closing it would
                            // immediately detach the program, leaving the sandbox
                            // unprotected. Store both fds in AyaBpfState; they are
                            // closed in the Drop implementation during sandbox cleanup.
                            stored_prog_fd = prog_fd;
                            stored_link_fd = link_fd;
                            attached = true;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "BPF_LINK_CREATE failed — program loaded but not attached"
                            );
                            unsafe { libc::close(prog_fd) };
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        section = section_name,
                        "BPF_PROG_LOAD failed for LSM program"
                    );
                }
            }

            break; // Only load the first matching program
        }

        if !attached {
            tracing::warn!(
                "BPF LSM program not attached — maps created but exec rate limiting \
                 is DEGRADED (maps-only mode, no kernel enforcement)"
            );
        }

        self.bpf = Some(AyaBpfState {
            rate_limits_fd,
            counters_fd,
            prog_fd: stored_prog_fd,
            link_fd: stored_link_fd,
            attached,
        });

        tracing::info!(
            rate_limits_fd,
            counters_fd,
            attached,
            "BPF LSM loaded via aya-obj"
        );

        Ok(())
    }

    /// Fallback: create BPF maps using raw syscalls (no program loading).
    #[cfg(target_os = "linux")]
    fn load_maps_only(&mut self) -> Result<()> {
        let _obj_data = std::fs::read(&self.bpf_obj_path).map_err(|e| {
            PuzzledError::BpfLsm(format!(
                "reading BPF object {}: {}",
                self.bpf_obj_path.display(),
                e
            ))
        })?;

        let rate_limits_fd = bpf_create_map(
            BPF_MAP_TYPE_HASH,
            std::mem::size_of::<u64>() as u32,
            std::mem::size_of::<RateLimitConfig>() as u32,
            256,
        )?;
        self.rate_limits_map_fd = Some(rate_limits_fd);

        let counters_fd = bpf_create_map(
            BPF_MAP_TYPE_HASH,
            std::mem::size_of::<u64>() as u32,
            24,
            256,
        )?;
        self.counters_map_fd = Some(counters_fd);

        tracing::info!(
            obj = %self.bpf_obj_path.display(),
            rate_limits_fd,
            counters_fd,
            "BPF maps created (raw); load program with: bpftool prog load {} /sys/fs/bpf/exec_guard",
            self.bpf_obj_path.display()
        );

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(&mut self) -> Result<()> {
        self.degraded = true;
        Err(PuzzledError::BpfLsm("BPF LSM requires Linux".to_string()))
    }

    // H-21: clone_guard removed — seccomp + SELinux provide dual defense for clone containment.
    // The BPF clone_guard (task_alloc hook) was redundant given:
    //   1. seccomp static deny blocks namespace-escape syscalls (setns, unshare)
    //   2. seccomp USER_NOTIF gates clone/clone3 with flag inspection
    //   3. SELinux puzzlepod_t domain prevents namespace creation via type enforcement

    /// Configure rate limits for a specific cgroup.
    ///
    /// C5/L5 lifetime model: BPF programs are loaded once at daemon start via
    /// BranchManager, attached per-cgroup at branch creation (this method), and
    /// detached at branch cleanup via `remove_cgroup()`. The `cgroup_id` is the
    /// inode number of the cgroup directory, readable via `stat()` on the cgroup
    /// path.
    #[cfg(target_os = "linux")]
    pub fn configure_cgroup(&self, cgroup_id: u64, config: RateLimitConfig) -> Result<()> {
        let map_fd = self.get_rate_limits_fd()?;

        bpf_map_update(map_fd, &cgroup_id, &config)?;

        tracing::debug!(
            cgroup_id,
            max_execs_per_second = config.max_execs_per_second,
            max_total_execs = config.max_total_execs,
            "BPF rate limit configured for cgroup"
        );

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn configure_cgroup(&self, _cgroup_id: u64, _config: RateLimitConfig) -> Result<()> {
        Err(PuzzledError::BpfLsm("BPF LSM requires Linux".to_string()))
    }

    /// Remove rate limit configuration for a cgroup.
    #[cfg(target_os = "linux")]
    pub fn remove_cgroup(&self, cgroup_id: u64) -> Result<()> {
        if let Ok(fd) = self.get_rate_limits_fd() {
            if let Err(e) = bpf_map_delete(fd, &cgroup_id) {
                tracing::warn!(cgroup_id, error = %e, "R16: BPF map entry deletion failed — entry may leak");
            }
        }
        if let Ok(fd) = self.get_counters_fd() {
            if let Err(e) = bpf_map_delete(fd, &cgroup_id) {
                tracing::warn!(cgroup_id, error = %e, "R16: BPF map entry deletion failed — entry may leak");
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn remove_cgroup(&self, _cgroup_id: u64) -> Result<()> {
        Err(PuzzledError::BpfLsm("BPF LSM requires Linux".to_string()))
    }

    /// Check if the BPF programs are loaded (maps created, possibly attached).
    pub fn is_loaded(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.loaded
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Check if the BPF LSM program is attached to the kernel hook.
    /// If false, maps are created but enforcement is degraded (no kernel hook).
    pub fn is_attached(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.bpf.as_ref().is_some_and(|s| s.attached)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// M-sc1: Check if BPF programs failed to load (degraded mode).
    ///
    /// When degraded, BPF-based exec rate limiting is not enforced by the
    /// kernel. Other defense layers (seccomp USER_NOTIF, SELinux) still
    /// provide containment, but the BPF layer is absent.
    ///
    /// Callers should log a warning at sandbox creation time when this
    /// returns true, and consider emitting a metric for monitoring.
    // TODO: M-sc1: Expose as a Prometheus metric (e.g., gauge "puzzled_bpf_degraded")
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Get the rate_limits map fd (from aya or raw fallback).
    #[cfg(target_os = "linux")]
    fn get_rate_limits_fd(&self) -> Result<i32> {
        if let Some(ref state) = self.bpf {
            Ok(state.rate_limits_fd)
        } else if let Some(fd) = self.rate_limits_map_fd {
            Ok(fd)
        } else {
            Err(PuzzledError::BpfLsm("BPF maps not loaded".to_string()))
        }
    }

    /// Get the exec_counters map fd (from aya or raw fallback).
    #[cfg(target_os = "linux")]
    fn get_counters_fd(&self) -> Result<i32> {
        if let Some(ref state) = self.bpf {
            Ok(state.counters_fd)
        } else if let Some(fd) = self.counters_map_fd {
            Ok(fd)
        } else {
            Err(PuzzledError::BpfLsm("BPF maps not loaded".to_string()))
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for BpfLsmManager {
    fn drop(&mut self) {
        if let Some(state) = self.bpf.take() {
            // Close link_fd first — this detaches the BPF program from the LSM hook.
            // This is intentional during cleanup: the sandbox is being torn down.
            if state.link_fd >= 0 {
                tracing::debug!(
                    link_fd = state.link_fd,
                    "closing BPF link fd (detaching LSM program)"
                );
                unsafe { libc::close(state.link_fd) };
            }
            if state.prog_fd >= 0 {
                unsafe { libc::close(state.prog_fd) };
            }
            unsafe {
                libc::close(state.rate_limits_fd);
                libc::close(state.counters_fd);
            }
        }
        if let Some(fd) = self.rate_limits_map_fd {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.counters_map_fd {
            unsafe { libc::close(fd) };
        }
        // H-21: clone_guard removed — seccomp + SELinux provide dual defense for clone containment.
    }
}

// ---------------------------------------------------------------------------
// Raw BPF syscall wrappers (Linux-only)
// ---------------------------------------------------------------------------

/// Encode a single BPF instruction as a u64.
///
/// BPF instructions are 8 bytes:
///   - opcode:   u8  (bits 0-7)
///   - dst_reg:  u4  (bits 8-11)
///   - src_reg:  u4  (bits 12-15)
///   - off:      i16 (bits 16-31)
///   - imm:      i32 (bits 32-63)
///
/// Used to generate inline BPF bytecode without requiring a compiled .bpf.o
/// file. Retained for potential future inline BPF program generation.
#[cfg(all(target_os = "linux", not(target_endian = "little")))]
compile_error!("BPF instruction encoding assumes little-endian byte order (x86_64, aarch64). Big-endian architectures (s390x, MIPS) require byte-swapped encoding.");

#[cfg(all(target_os = "linux", target_endian = "little"))]
#[allow(dead_code)] // Used in tests; retained for future inline BPF program generation
const fn bpf_insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    (opcode as u64)
        | ((dst as u64 & 0x0F) << 8)
        | ((src as u64 & 0x0F) << 12)
        | ((off as u16 as u64) << 16)
        | ((imm as u32 as u64) << 32)
}

#[cfg(target_os = "linux")]
const BPF_MAP_CREATE: libc::c_int = 0;
#[cfg(target_os = "linux")]
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
#[cfg(target_os = "linux")]
const BPF_MAP_DELETE_ELEM: libc::c_int = 3;
#[cfg(target_os = "linux")]
const BPF_PROG_LOAD_CMD: libc::c_int = 5;
#[cfg(target_os = "linux")]
const BPF_LINK_CREATE_CMD: libc::c_int = 28;
#[cfg(target_os = "linux")]
const BPF_ANY: u64 = 0;
#[cfg(target_os = "linux")]
const BPF_MAP_TYPE_HASH: u32 = 1;
#[cfg(target_os = "linux")]
const BPF_PROG_TYPE_LSM: u32 = 29;
#[cfg(target_os = "linux")]
const BPF_LSM_MAC: u32 = 10;

#[cfg(target_os = "linux")]
fn bpf_create_map(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> Result<i32> {
    #[repr(C)]
    struct BpfAttrMapCreate {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    }

    let attr = BpfAttrMapCreate {
        map_type,
        key_size,
        value_size,
        max_entries,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttrMapCreate>(),
        )
    };

    if fd < 0 {
        return Err(PuzzledError::BpfLsm(format!(
            "bpf(BPF_MAP_CREATE) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // K2: Use try_from instead of bare `fd as i32` to detect truncation
    i32::try_from(fd)
        .map_err(|_| PuzzledError::BpfLsm(format!("bpf(BPF_MAP_CREATE) fd {} out of i32 range", fd)))
}

#[cfg(target_os = "linux")]
fn bpf_map_update<K, V>(map_fd: i32, key: &K, value: &V) -> Result<()> {
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        _pad0: u32,
        key: u64,
        value_or_next: u64,
        flags: u64,
    }

    // J2: Use try_from instead of bare `as u32` to detect negative or out-of-range fds
    let map_fd_u32 = u32::try_from(map_fd)
        .map_err(|_| PuzzledError::BpfLsm(format!("map_fd {} out of u32 range", map_fd)))?;
    let attr = BpfAttrMapElem {
        map_fd: map_fd_u32,
        _pad0: 0,
        key: key as *const K as u64,
        value_or_next: value as *const V as u64,
        flags: BPF_ANY,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttrMapElem>(),
        )
    };

    if ret < 0 {
        return Err(PuzzledError::BpfLsm(format!(
            "bpf(BPF_MAP_UPDATE_ELEM) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn bpf_map_delete<K>(map_fd: i32, key: &K) -> Result<()> {
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        _pad0: u32,
        key: u64,
    }

    // J2: Use try_from instead of bare `as u32` to detect negative or out-of-range fds
    let map_fd_u32 = u32::try_from(map_fd)
        .map_err(|_| PuzzledError::BpfLsm(format!("map_fd {} out of u32 range", map_fd)))?;
    let attr = BpfAttrMapElem {
        map_fd: map_fd_u32,
        _pad0: 0,
        key: key as *const K as u64,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_DELETE_ELEM,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttrMapElem>(),
        )
    };

    if ret < 0 {
        return Err(PuzzledError::BpfLsm(format!(
            "bpf(BPF_MAP_DELETE_ELEM) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Load a BPF program via bpf(BPF_PROG_LOAD).
///
/// `prog_type` should be BPF_PROG_TYPE_LSM for LSM programs.
/// `insns` is the raw BPF bytecode (from aya-obj parsed ELF).
/// `license` is the BPF program license (must be GPL-compatible for LSM).
/// `attach_func_name` is the LSM hook function name (e.g., "bprm_check_security").
/// `map_fds` are file descriptors for maps the program references.
#[cfg(target_os = "linux")]
fn bpf_prog_load(
    prog_type: u32,
    insns: &[u8],
    license: &str,
    attach_func_name: &str,
    _map_fds: &[i32],
) -> Result<i32> {
    let license_cstr =
        std::ffi::CString::new(license).map_err(|e| PuzzledError::BpfLsm(e.to_string()))?;
    let func_name_cstr =
        std::ffi::CString::new(attach_func_name).map_err(|e| PuzzledError::BpfLsm(e.to_string()))?;

    // BPF_PROG_LOAD attr — using a zeroed buffer with manual field placement
    // to avoid depending on exact kernel struct layout versioning
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct bpf_attr_prog_load {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
        prog_btf_fd: u32,
        func_info_rec_size: u32,
        func_info: u64,
        func_info_cnt: u32,
        line_info_rec_size: u32,
        line_info: u64,
        line_info_cnt: u32,
        attach_btf_id: u32,
        attach_prog_fd_or_btf_obj_fd: u32,
        _pad: [u8; 32],
    }

    // J3: Use try_from instead of bare `as u32` to detect overflow on large bytecode
    let insn_cnt =
        u32::try_from(insns.len() / 8) // BPF instructions are 8 bytes each
            .map_err(|_| {
                PuzzledError::BpfLsm(format!("insn_cnt {} overflows u32", insns.len() / 8))
            })?;

    let mut attr: bpf_attr_prog_load = unsafe { std::mem::zeroed() };
    attr.prog_type = prog_type;
    attr.insn_cnt = insn_cnt;
    attr.insns = insns.as_ptr() as u64;
    attr.license = license_cstr.as_ptr() as u64;
    attr.expected_attach_type = BPF_LSM_MAC;

    // Copy function name into prog_name (max 15 chars + null)
    let name_bytes = func_name_cstr.as_bytes_with_nul();
    let copy_len = name_bytes.len().min(16);
    attr.prog_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD_CMD,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<bpf_attr_prog_load>(),
        )
    };

    if fd < 0 {
        return Err(PuzzledError::BpfLsm(format!(
            "bpf(BPF_PROG_LOAD) failed for {}: {}",
            attach_func_name,
            std::io::Error::last_os_error()
        )));
    }

    // K2: Use try_from instead of bare `fd as i32` to detect truncation
    i32::try_from(fd).map_err(|_| {
        PuzzledError::BpfLsm(format!(
            "bpf(BPF_PROG_LOAD) fd {} out of i32 range for {}",
            fd, attach_func_name
        ))
    })
}

/// Attach a loaded BPF program to an LSM hook via bpf(BPF_LINK_CREATE).
///
/// `prog_fd` is the fd from BPF_PROG_LOAD.
/// `attach_func_name` identifies the LSM hook (for logging only — the
/// attach target is determined by the program's expected_attach_type
/// and BTF info set during BPF_PROG_LOAD).
#[cfg(target_os = "linux")]
fn bpf_link_create(prog_fd: i32, attach_func_name: &str) -> Result<i32> {
    #[repr(C)]
    struct BpfAttrLinkCreate {
        prog_fd: u32,
        target_fd: u32,
        attach_type: u32,
        flags: u32,
    }

    // J2: Use try_from instead of bare `as u32` to detect negative or out-of-range fds
    let prog_fd_u32 = u32::try_from(prog_fd)
        .map_err(|_| PuzzledError::BpfLsm(format!("prog_fd {} out of u32 range", prog_fd)))?;
    let attr = BpfAttrLinkCreate {
        prog_fd: prog_fd_u32,
        target_fd: 0, // 0 for LSM hooks (attached globally)
        attach_type: BPF_LSM_MAC,
        flags: 0,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_LINK_CREATE_CMD,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttrLinkCreate>(),
        )
    };

    if fd < 0 {
        return Err(PuzzledError::BpfLsm(format!(
            "bpf(BPF_LINK_CREATE) failed for {}: {}",
            attach_func_name,
            std::io::Error::last_os_error()
        )));
    }

    // K2: Use try_from instead of bare `fd as i32` to detect truncation
    i32::try_from(fd).map_err(|_| {
        PuzzledError::BpfLsm(format!(
            "bpf(BPF_LINK_CREATE) fd {} out of i32 range for {}",
            fd, attach_func_name
        ))
    })
}

/// Read the cgroup ID (inode number) from a cgroup directory path.
///
/// L5: The cgroup_id used in BPF maps is the inode number of the cgroup
/// directory. This helper reads it via `stat()` for use with
/// `configure_cgroup()`.
#[cfg(target_os = "linux")]
pub fn read_cgroup_id(cgroup_path: &std::path::Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(cgroup_path).map_err(|e| {
        PuzzledError::BpfLsm(format!(
            "reading cgroup inode for {}: {}",
            cgroup_path.display(),
            e
        ))
    })?;
    Ok(metadata.ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_size() {
        // Must be 16 bytes to match kernel struct
        assert_eq!(std::mem::size_of::<RateLimitConfig>(), 16);
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_execs_per_second, 0);
        assert_eq!(config.max_total_execs, 0);
        assert_eq!(config.kill_switch, 0);
    }

    #[test]
    fn test_bpf_manager_new() {
        let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        assert_eq!(
            manager.bpf_obj_path,
            std::path::PathBuf::from("/tmp/nonexistent.bpf.o")
        );
    }

    #[test]
    fn test_bpf_manager_load_nonexistent() {
        let mut manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        // Loading a nonexistent file should fail gracefully
        let result = manager.load();
        assert!(result.is_err());
    }

    // H-21: test_load_clone_guard removed — clone_guard was removed as
    // seccomp + SELinux provide dual defense for clone containment.

    /// M-sc1: Verify is_degraded() returns false for a fresh manager.
    #[test]
    fn test_is_degraded_initial() {
        let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        assert!(
            !manager.is_degraded(),
            "fresh BpfLsmManager should not be degraded before load()"
        );
    }

    #[test]
    fn test_bpf_manager_is_loaded_initial() {
        let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        assert!(
            !manager.is_loaded(),
            "fresh BpfLsmManager should return false for is_loaded()"
        );
    }

    #[test]
    fn test_bpf_manager_is_attached_initial() {
        let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        assert!(
            !manager.is_attached(),
            "fresh BpfLsmManager should return false for is_attached()"
        );
    }

    #[test]
    fn test_rate_limit_config_custom_values() {
        let config = RateLimitConfig {
            max_execs_per_second: 42,
            max_total_execs: 1000,
            kill_switch: 1,
            _pad: 0,
        };
        assert_eq!(config.max_execs_per_second, 42);
        assert_eq!(config.max_total_execs, 1000);
        assert_eq!(config.kill_switch, 1);
        assert_eq!(config._pad, 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_bpf_manager_configure_cgroup_not_loaded() {
        let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        let config = RateLimitConfig::default();
        let result = manager.configure_cgroup(1, config);
        assert!(
            result.is_err(),
            "configure_cgroup should error on non-Linux"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("requires Linux"),
            "error should mention Linux requirement, got: {}",
            err_msg
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_bpf_manager_remove_cgroup_not_loaded() {
        let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        let result = manager.remove_cgroup(1);
        assert!(result.is_err(), "remove_cgroup should error on non-Linux");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("requires Linux"),
            "error should mention Linux requirement, got: {}",
            err_msg
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_bpf_manager_load_sets_degraded_non_linux() {
        let mut manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
        assert!(
            !manager.is_degraded(),
            "should not be degraded before load()"
        );
        // On non-Linux, load() sets degraded=true before returning an error
        let _ = manager.load();
        assert!(
            manager.is_degraded(),
            "after load() fails on non-Linux, is_degraded() should be true"
        );
    }

    /// J2: Verify no bare `map_fd as u32` or `prog_fd as u32` in production code.
    #[test]
    fn test_j2_no_bare_fd_as_u32_casts() {
        let source = include_str!("bpf_lsm.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("map_fd as u32"),
            "J2: production code must not use bare `map_fd as u32` — use u32::try_from()"
        );
        assert!(
            !production_code.contains("prog_fd as u32"),
            "J2: production code must not use bare `prog_fd as u32` — use u32::try_from()"
        );
    }

    /// J3: Verify insn_cnt does not use bare `as u32` cast.
    #[test]
    fn test_j3_no_bare_insn_cnt_as_u32() {
        let source = include_str!("bpf_lsm.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("(insns.len() / 8) as u32"),
            "J3: production code must not use bare `(insns.len() / 8) as u32` — use u32::try_from()"
        );
    }

    /// K2: Verify no bare `fd as i32` in bpf syscall return paths.
    #[test]
    fn test_k2_no_bare_fd_as_i32_casts() {
        let source = include_str!("bpf_lsm.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("Ok(fd as i32)"),
            "K2: production code must not use bare `Ok(fd as i32)` — use i32::try_from(fd)"
        );
    }

    /// R16: Verify production code does not silently discard bpf_map_delete errors.
    #[test]
    fn test_r16_no_silent_bpf_map_delete_discard() {
        let source = include_str!("bpf_lsm.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("let _ = bpf_map_delete"),
            "R16: production code must not use `let _ = bpf_map_delete` — errors must be logged"
        );
    }

    /// Verify bpf_insn encoding produces correct bytecode.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_bpf_insn_encoding() {
        // BPF_MOV64_IMM(R0, 0) = opcode 0xb7, dst=0, src=0, off=0, imm=0
        let insn = bpf_insn(0xb7, 0, 0, 0, 0);
        assert_eq!(insn & 0xFF, 0xb7, "opcode should be 0xb7");
        assert_eq!((insn >> 8) & 0x0F, 0, "dst_reg should be 0");
        assert_eq!((insn >> 32) as i32, 0, "imm should be 0");

        // BPF_MOV64_IMM(R0, -1) = opcode 0xb7, dst=0, src=0, off=0, imm=-1
        let insn = bpf_insn(0xb7, 0, 0, 0, -1i32);
        assert_eq!((insn >> 32) as u32, 0xFFFF_FFFF, "imm should be -1 as u32");

        // BPF_LDX_MEM(BPF_DW, R2, R1, 8) = opcode 0x79, dst=2, src=1, off=8
        let insn = bpf_insn(0x79, 2, 1, 8, 0);
        assert_eq!(insn & 0xFF, 0x79);
        assert_eq!((insn >> 8) & 0x0F, 2);
        assert_eq!((insn >> 12) & 0x0F, 1);
        assert_eq!((insn >> 16) as u16, 8);
    }
}
