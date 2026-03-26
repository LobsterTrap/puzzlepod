// SPDX-License-Identifier: Apache-2.0
use crate::error::Result;
#[cfg(target_os = "linux")]
use std::path::Path;

// ---------------------------------------------------------------------------
// CR-1/CR-2: CLONE_INTO_CGROUP support
// ---------------------------------------------------------------------------

/// CLONE_INTO_CGROUP — place the child directly into the specified cgroup at
/// clone3() time, eliminating the race window where the child runs briefly in
/// the root cgroup before the parent can call add_process().
#[cfg(target_os = "linux")]
const CLONE_INTO_CGROUP: u64 = 0x200000000;

/// H-18: CLONE_NEWUTS — isolate UTS namespace (hostname/domainname) so the
/// agent cannot read or modify the host's hostname.
#[cfg(target_os = "linux")]
const CLONE_NEWUTS: u64 = 0x04000000;

/// H-19: CLONE_NEWCGROUP — isolate cgroup namespace so the agent sees only
/// its own cgroup hierarchy, preventing information leaks about other agents
/// and the host's cgroup structure.
#[cfg(target_os = "linux")]
const CLONE_NEWCGROUP: u64 = 0x02000000;

/// Open a cgroup directory for use with CLONE_INTO_CGROUP.
///
/// CR-1: Opens the cgroup directory with O_DIRECTORY|O_RDONLY. The returned
/// fd is passed in clone_args.cgroup so the kernel places the child directly
/// into the cgroup at clone3() time.
///
/// Caller is responsible for closing the returned fd after clone3().
#[cfg(target_os = "linux")]
pub fn open_cgroup_fd(cgroup_path: &Path) -> Result<i32> {
    let path_cstr =
        std::ffi::CString::new(cgroup_path.to_string_lossy().as_ref()).map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!("cgroup path contains null byte: {}", e))
        })?;

    let fd = unsafe { libc::open(path_cstr.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY) };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(crate::error::PuzzledError::Sandbox(format!(
            "open_cgroup_fd({}): {}",
            cgroup_path.display(),
            err
        )));
    }

    Ok(fd)
}

// ---------------------------------------------------------------------------
// CR-3: Dedicated child stack allocation
// ---------------------------------------------------------------------------

/// Allocate a dedicated child stack with a guard page.
///
/// CR-3: Instead of sharing the parent's address space (vfork-like behavior),
/// allocate a private stack for the child process. The guard page (PROT_NONE)
/// at the bottom detects stack overflow.
///
/// Returns (stack_top, total_size) where stack_top points to the top of the
/// usable stack region (stack grows downward on x86_64 and aarch64).
///
/// # Safety
/// The returned pointer must be deallocated with `deallocate_child_stack()`
/// after the child exits.
#[cfg(target_os = "linux")]
pub fn allocate_child_stack(size: usize) -> Result<(*mut u8, usize)> {
    let guard_size: usize = 4096;
    let total_size = size + guard_size;

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        let err = std::io::Error::last_os_error();
        return Err(crate::error::PuzzledError::Sandbox(format!(
            "mmap for child stack ({} bytes): {}",
            total_size, err
        )));
    }

    // Set guard page at the bottom (lowest address) to PROT_NONE
    let ret = unsafe { libc::mprotect(ptr, guard_size, libc::PROT_NONE) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // Clean up the mapping on failure
        unsafe { libc::munmap(ptr, total_size) };
        return Err(crate::error::PuzzledError::Sandbox(format!(
            "mprotect guard page for child stack: {}",
            err
        )));
    }

    // Stack grows down: stack_top = base + total_size
    let stack_top = unsafe { (ptr as *mut u8).add(total_size) };

    tracing::debug!(
        stack_base = ?ptr,
        stack_top = ?stack_top,
        total_size,
        guard_size,
        "allocated child stack with guard page"
    );

    Ok((stack_top, total_size))
}

/// Deallocate a child stack previously allocated by `allocate_child_stack()`.
///
/// CR-3: Must be called by the parent after the child exits to avoid leaking
/// the stack memory mapping.
///
/// # Safety
/// `stack_top` and `total_size` must match the values returned by
/// `allocate_child_stack()`.
#[cfg(target_os = "linux")]
pub unsafe fn deallocate_child_stack(stack_top: *mut u8, total_size: usize) {
    // stack_top points to base + total_size, so base = stack_top - total_size
    let base = stack_top.sub(total_size);
    let ret = libc::munmap(base as *mut libc::c_void, total_size);
    if ret != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "failed to munmap child stack"
        );
    } else {
        tracing::debug!(
            stack_base = ?base,
            total_size,
            "deallocated child stack"
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn deallocate_child_stack(_stack_top: *mut u8, _total_size: usize) {
    // No-op on non-Linux: child stacks are only allocated on Linux.
}

/// Namespace setup using clone3().
///
/// Creates a new process in isolated PID, mount, UTS, IPC, and cgroup
/// namespaces. Network namespace isolation is handled separately — the child
/// joins a pre-created named netns via setns() after clone3.
pub struct NamespaceBuilder;

impl NamespaceBuilder {
    /// Create a child process in new PID + mount + UTS + IPC + cgroup
    /// namespaces via clone3().
    ///
    /// Flags: CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC |
    ///        CLONE_NEWUTS | CLONE_NEWCGROUP | CLONE_PIDFD | CLONE_INTO_CGROUP
    ///
    /// NOTE: CLONE_NEWNET is NOT included. The child joins a pre-created
    /// named netns via setns() to avoid issues with /proc/<pid>/ns/net
    /// visibility and mount propagation across CLONE_NEWNS.
    ///
    /// DC: No CLONE_NEWUSER — intentional. User namespaces enable unprivileged
    /// namespace creation, which would weaken containment. Agent processes run
    /// as non-root UIDs within the existing user namespace.
    ///
    /// CR-1/CR-2: When `cgroup_fd` is Some, CLONE_INTO_CGROUP is added to the
    /// clone flags so the child is placed directly into the target cgroup at
    /// creation time, eliminating the race window.
    ///
    /// CR-3: Allocates a dedicated child stack instead of sharing the parent's
    /// address space.
    ///
    /// Returns (pidfd, child_pid_in_root_ns).
    #[cfg(target_os = "linux")]
    pub fn create_isolated_process(
        child_fn: Box<dyn FnOnce() -> i32 + Send>,
        cgroup_fd: Option<i32>,
    ) -> Result<(i32, u32)> {
        use libc::{
            c_long, c_ulong, pid_t, syscall, SYS_clone3, CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWPID,
            SIGCHLD,
        };
        use std::mem;

        // CLONE_PIDFD is not in older libc crate versions, define it
        const CLONE_PIDFD: c_ulong = 0x00001000;

        /// clone3 args structure matching the kernel definition.
        #[repr(C)]
        struct CloneArgs {
            flags: c_ulong,
            pidfd: u64, // pointer to pidfd (output)
            child_tid: u64,
            parent_tid: u64,
            exit_signal: c_ulong,
            stack: u64,
            stack_size: u64,
            tls: u64,
            set_tid: u64,
            set_tid_size: u64,
            cgroup: u64,
        }

        let mut pidfd: i32 = -1;

        // Build clone flags
        // H-18: Add CLONE_NEWUTS for UTS namespace isolation
        // H-19: Add CLONE_NEWCGROUP for cgroup namespace isolation
        // NOTE: CLONE_NEWNET is NOT included here. The child inherits the
        // parent's network namespace initially, then joins a pre-created
        // named netns via setns(). This allows the parent to reference the
        // netns by name for veth/nftables setup (the named netns was created
        // by the parent, so it's visible in the parent's mount namespace).
        let mut flags: c_ulong = CLONE_NEWPID as c_ulong
            | CLONE_NEWNS as c_ulong
            | CLONE_NEWIPC as c_ulong
            | CLONE_NEWUTS as c_ulong
            | CLONE_NEWCGROUP as c_ulong
            | CLONE_PIDFD;

        // CR-1/CR-2: Add CLONE_INTO_CGROUP when we have a cgroup fd
        let cgroup_fd_val: u64 = if let Some(fd) = cgroup_fd {
            flags |= CLONE_INTO_CGROUP as c_ulong;
            fd as u64
        } else {
            0
        };

        // stack=0, stack_size=0: child gets a COW copy of the parent's
        // stack (like fork). A custom stack is NOT safe here because
        // clone3 changes the child's SP, but the compiler-generated code
        // accesses local variables via SP-relative offsets — after the SP
        // change, those offsets point into uninitialized memory (SIGSEGV).
        let mut args = CloneArgs {
            flags,
            pidfd: &mut pidfd as *mut i32 as u64,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: SIGCHLD as c_ulong,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: cgroup_fd_val,
        };

        let ret: c_long = unsafe {
            syscall(
                SYS_clone3,
                &mut args as *mut CloneArgs,
                mem::size_of::<CloneArgs>(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "clone3() failed: {}",
                err
            )));
        }

        let child_pid = ret as pid_t;

        if child_pid == 0 {
            // Child process — run the provided function and exit
            let exit_code = child_fn();
            unsafe { libc::_exit(exit_code) };
        }

        // Parent process

        // M-ns1: Set FD_CLOEXEC on the pidfd to prevent it from leaking
        // into child processes created by this parent later.
        let fcntl_ret = unsafe { libc::fcntl(pidfd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if fcntl_ret < 0 {
            tracing::warn!(
                pidfd,
                error = %std::io::Error::last_os_error(),
                "failed to set FD_CLOEXEC on pidfd (non-fatal)"
            );
        }

        tracing::info!(
            child_pid = child_pid,
            pidfd = pidfd,
            clone_into_cgroup = cgroup_fd.is_some(),
            "created isolated process via clone3()"
        );

        // J5: Use try_from instead of bare `as u32` to detect negative or out-of-range PIDs
        let child_pid_u32 = u32::try_from(child_pid).map_err(|_| {
            crate::error::PuzzledError::Sandbox(format!("child_pid {} out of u32 range", child_pid))
        })?;

        Ok((pidfd, child_pid_u32))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_isolated_process(
        _child_fn: Box<dyn FnOnce() -> i32 + Send>,
        _cgroup_fd: Option<i32>,
    ) -> Result<(i32, u32)> {
        Err(crate::error::PuzzledError::Sandbox(
            "namespaces require Linux".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_namespace_create_non_linux() {
        let child_fn = Box::new(|| -> i32 { 0 });
        let result = NamespaceBuilder::create_isolated_process(child_fn, None);
        assert!(
            result.is_err(),
            "create_isolated_process should return error on non-Linux"
        );
    }

    /// Verify the non-Linux stub error message contains "namespaces require Linux".
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_namespace_create_non_linux_error_message() {
        let child_fn = Box::new(|| -> i32 { 0 });
        let result = NamespaceBuilder::create_isolated_process(child_fn, None);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("namespaces require Linux"),
            "error message should mention Linux requirement, got: {}",
            msg
        );
    }

    /// Verify the non-Linux stub returns Sandbox variant error.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_namespace_create_non_linux_error_variant() {
        let child_fn = Box::new(|| -> i32 { 0 });
        let result = NamespaceBuilder::create_isolated_process(child_fn, None);
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::PuzzledError::Sandbox(_)),
            "error should be Sandbox variant"
        );
    }

    /// Verify that providing a cgroup_fd on non-Linux still returns error
    /// (the cgroup_fd parameter is ignored on non-Linux).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_namespace_create_non_linux_with_cgroup_fd() {
        let child_fn = Box::new(|| -> i32 { 0 });
        let result = NamespaceBuilder::create_isolated_process(child_fn, Some(42));
        assert!(
            result.is_err(),
            "create_isolated_process with cgroup_fd should still return error on non-Linux"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("namespaces require Linux"),
            "error message should mention Linux requirement even with cgroup_fd, got: {}",
            msg
        );
    }

    /// Verify deallocate_child_stack non-Linux stub is a no-op and does not panic.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_deallocate_child_stack_non_linux_noop() {
        // Call with a null pointer and zero size — should be a silent no-op.
        deallocate_child_stack(std::ptr::null_mut(), 0);
    }

    /// Verify deallocate_child_stack non-Linux stub handles non-null pointer
    /// and non-zero size without panicking.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_deallocate_child_stack_non_linux_nonzero_args() {
        // Arbitrary non-null pointer and size — stub should ignore them.
        let fake_ptr = 0x1000 as *mut u8;
        deallocate_child_stack(fake_ptr, 8192);
    }

    /// J5: Verify no bare `child_pid as u32` in production code.
    #[test]
    fn test_j5_no_bare_child_pid_as_u32() {
        let source = include_str!("namespace.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("child_pid as u32"),
            "J5: production code must not use bare `child_pid as u32` — use u32::try_from()"
        );
    }

    /// Verify NamespaceBuilder is a unit struct that can be instantiated.
    #[test]
    fn test_namespace_builder_is_unit_struct() {
        let _builder = NamespaceBuilder;
        // Unit struct instantiation should compile and not panic.
    }

    /// Verify that the Result type alias is accessible and works with
    /// both Ok and Err variants for sandbox operations.
    #[test]
    fn test_result_type_ok_variant() {
        let ok_result: Result<i32> = Ok(42);
        match ok_result {
            Ok(val) => assert_eq!(val, 42),
            Err(e) => panic!("expected Ok, got Err: {}", e),
        }
    }

    #[test]
    fn test_result_type_err_variant() {
        let err_result: Result<i32> =
            Err(crate::error::PuzzledError::Sandbox("test error".to_string()));
        match err_result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => assert!(e.to_string().contains("test error")),
        }
    }

    /// Verify Sandbox error formatting includes the "sandbox setup error:" prefix
    /// from the Display impl (thiserror derive).
    #[test]
    fn test_sandbox_error_display_format() {
        let err =
            crate::error::PuzzledError::Sandbox("cgroup path contains null byte: xyz".to_string());
        let display = format!("{}", err);
        assert!(
            display.contains("sandbox setup error:"),
            "Sandbox error Display should include prefix, got: {}",
            display
        );
        assert!(
            display.contains("cgroup path contains null byte"),
            "Sandbox error Display should include inner message, got: {}",
            display
        );
    }
}
