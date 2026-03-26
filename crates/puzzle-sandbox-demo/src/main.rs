// SPDX-License-Identifier: Apache-2.0
//! puzzle-sandbox-demo — Live kernel enforcement demo for PuzzlePod
//!
//! Demonstrates real Landlock + seccomp + cgroup enforcement by running escape
//! attempts before and after applying kernel restrictions. The before/after
//! structure proves that containment is real: operations that succeed without
//! enforcement are blocked with enforcement.
//!
//! Usage:
//!   sudo target/release/puzzle-sandbox-demo --sandbox-dir /tmp/sandbox-test

use std::path::PathBuf;

/// Top-level CLI: `puzzle-sandbox-demo` can either run the sandbox enforcement demo
/// (Linux only) or generate a diff between two directories (cross-platform).
#[derive(clap::Parser)]
#[command(
    name = "puzzle-sandbox-demo",
    about = "Live kernel enforcement demo + diff tool"
)]
enum TopCommand {
    /// Run the live kernel enforcement demo (Linux only)
    Run {
        /// Directory to use as the sandbox root (will be created if needed)
        #[arg(long, default_value = "/tmp/puzzle-sandbox-demo")]
        sandbox_dir: PathBuf,
    },
    /// Generate a diff between an OverlayFS upper layer and a base directory
    Diff {
        /// Path to the OverlayFS upper directory
        #[arg(long)]
        upper: PathBuf,
        /// Path to the base (lower) directory
        #[arg(long)]
        base: PathBuf,
    },
    /// Execute a command inside the sandbox with full enforcement (Linux only)
    ///
    /// Applies Landlock, seccomp-BPF, cgroup limits, and capability drop,
    /// then execs the specified command. The command inherits all enforcement
    /// and cannot remove it.
    Exec {
        /// Directory to use as the sandbox root (will be created if needed)
        #[arg(long, default_value = "/tmp/sandbox-exec")]
        sandbox_dir: PathBuf,
        /// Additional directories to grant read access (can be repeated)
        #[arg(long = "allow-read")]
        allow_read: Vec<PathBuf>,
        /// Maximum number of processes (cgroup pids.max)
        #[arg(long, default_value_t = 64)]
        pids_max: u32,
        /// Maximum memory in bytes (cgroup memory.max, default 256 MiB)
        #[arg(long, default_value_t = 268435456)]
        memory_max: u64,
        /// Command and arguments to execute inside the sandbox
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
}

fn main() {
    use clap::Parser;

    let cmd = TopCommand::parse();
    match cmd {
        TopCommand::Run { sandbox_dir } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = sandbox_dir;
                eprintln!("puzzle-sandbox-demo run requires Linux (Landlock, seccomp, cgroups).");
                eprintln!("Run inside the Lima VM: limactl shell puzzled-dev");
                std::process::exit(1);
            }
            #[cfg(target_os = "linux")]
            {
                linux::run_with_dir(sandbox_dir);
            }
        }
        TopCommand::Diff { upper, base } => {
            run_diff(&upper, &base);
        }
        TopCommand::Exec {
            sandbox_dir,
            allow_read,
            pids_max,
            memory_max,
            command,
        } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (sandbox_dir, allow_read, pids_max, memory_max, command);
                eprintln!("puzzle-sandbox-demo exec requires Linux (Landlock, seccomp, cgroups).");
                eprintln!("Run inside the Lima VM: limactl shell puzzled-dev");
                std::process::exit(1);
            }
            #[cfg(target_os = "linux")]
            {
                let exit_code =
                    linux::run_exec(sandbox_dir, allow_read, pids_max, memory_max, command);
                std::process::exit(exit_code);
            }
        }
    }
}

fn run_diff(upper: &std::path::Path, base: &std::path::Path) {
    use puzzled::diff::DiffEngine;
    use puzzled_types::FileChangeKind;

    const GREEN: &str = "\x1b[0;32m";
    const RED: &str = "\x1b[0;31m";
    const YELLOW: &str = "\x1b[1;33m";
    const CYAN: &str = "\x1b[0;36m";
    const BOLD: &str = "\x1b[1m";
    const NC: &str = "\x1b[0m";

    let engine = DiffEngine::new();
    match engine.generate(upper, base, None) {
        Ok(changes) => {
            if changes.is_empty() {
                println!("  No changes detected.");
                return;
            }

            let mut added = 0u32;
            let mut modified = 0u32;
            let mut deleted = 0u32;
            let mut metadata = 0u32;

            for c in &changes {
                let (prefix, color) = match c.kind {
                    FileChangeKind::Added => ("+", GREEN),
                    FileChangeKind::Modified => ("~", YELLOW),
                    FileChangeKind::Deleted => ("-", RED),
                    FileChangeKind::MetadataChanged => ("M", CYAN),
                    FileChangeKind::Renamed => ("R", YELLOW),
                    FileChangeKind::Symlink => ("S", CYAN),
                    // Q6: New special file type variants
                    FileChangeKind::Hardlink => ("H", CYAN),
                    FileChangeKind::BlockDevice => ("B", RED),
                    FileChangeKind::CharDevice => ("C", RED),
                    FileChangeKind::Fifo => ("F", CYAN),
                };
                match c.kind {
                    FileChangeKind::Added => added += 1,
                    FileChangeKind::Modified => modified += 1,
                    FileChangeKind::Deleted => deleted += 1,
                    FileChangeKind::MetadataChanged => metadata += 1,
                    FileChangeKind::Renamed => modified += 1,
                    FileChangeKind::Symlink => added += 1,
                    // Q6: Count special file types as added
                    FileChangeKind::Hardlink
                    | FileChangeKind::BlockDevice
                    | FileChangeKind::CharDevice
                    | FileChangeKind::Fifo => added += 1,
                }
                println!(
                    "  {color}{BOLD}{prefix}{NC} {} ({} bytes)",
                    c.path.display(),
                    c.size
                );
            }

            println!();
            let mut parts = Vec::new();
            if added > 0 {
                parts.push(format!("{GREEN}{added} added{NC}"));
            }
            if modified > 0 {
                parts.push(format!("{YELLOW}{modified} modified{NC}"));
            }
            if deleted > 0 {
                parts.push(format!("{RED}{deleted} deleted{NC}"));
            }
            if metadata > 0 {
                parts.push(format!("{CYAN}{metadata} metadata{NC}"));
            }
            println!(
                "  {BOLD}{}{NC} files changed ({})",
                changes.len(),
                parts.join(", ")
            );
        }
        Err(e) => {
            eprintln!("  {RED}Error:{NC} Failed to generate diff: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::os::unix::io::FromRawFd;
    use std::path::PathBuf;
    use std::process;

    // ─── ANSI Colors ────────────────────────────────────────────────────

    const RED: &str = "\x1b[0;31m";
    const GREEN: &str = "\x1b[0;32m";
    const YELLOW: &str = "\x1b[1;33m";
    const BLUE: &str = "\x1b[0;34m";
    const BOLD: &str = "\x1b[1m";
    const DIM: &str = "\x1b[2m";
    const NC: &str = "\x1b[0m";

    fn ok(msg: &str) {
        println!("  {GREEN}✓{NC} {msg}");
    }

    fn fail_msg(msg: &str) {
        println!("  {RED}✗{NC} {msg}");
    }

    fn info(msg: &str) {
        println!("  {DIM}▸{NC} {msg}");
    }

    fn escape_header(phase: &str) {
        println!();
        println!("  {BOLD}{BLUE}── {phase} ──{NC}");
        println!();
    }

    fn test_result(name: &str, blocked: bool, expected_blocked: bool) {
        if blocked == expected_blocked {
            if blocked {
                ok(&format!("{name} → {GREEN}BLOCKED{NC} (kernel denied)"));
            } else {
                ok(&format!("{name} → {YELLOW}allowed{NC} (no enforcement)"));
            }
        } else {
            fail_msg(&format!("{name} → UNEXPECTED result"));
        }
    }

    fn make_pipe() -> (i32, i32) {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert!(ret == 0, "pipe() failed");
        (fds[0], fds[1])
    }

    // ─── Escape Attempts ────────────────────────────────────────────────

    /// Test 1: Read /etc/shadow (credential theft)
    fn try_read_shadow() -> bool {
        match fs::File::open("/etc/shadow") {
            Ok(mut f) => {
                let mut buf = [0u8; 64];
                let _ = f.read(&mut buf);
                false // not blocked
            }
            Err(_) => true, // blocked
        }
    }

    /// Test 2: Write outside sandbox
    fn try_write_escape() -> bool {
        let path = "/tmp/puzzle-sandbox-demo-escape-test.txt";
        match fs::write(path, "exfiltrated data") {
            Ok(_) => {
                let _ = fs::remove_file(path);
                false // not blocked
            }
            Err(_) => true, // blocked
        }
    }

    /// Test 3: mount() syscall (container escape vector)
    fn try_mount() -> bool {
        let src = CString::new("none").unwrap();
        let target = CString::new("/tmp").unwrap();
        let fstype = CString::new("tmpfs").unwrap();
        let ret = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if ret == 0 {
            unsafe {
                libc::umount(target.as_ptr());
            }
            false // not blocked
        } else {
            true // blocked (EPERM)
        }
    }

    /// Test 4: ptrace() syscall (process injection)
    fn try_ptrace() -> bool {
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if ret == 0 {
            false // not blocked
        } else {
            true // blocked (EPERM)
        }
    }

    /// Test 5: Fork bomb (exceed PID limit)
    fn try_fork_bomb(limit: usize) -> (usize, usize) {
        let mut children: Vec<libc::pid_t> = Vec::new();
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for _ in 0..limit {
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                failed += 1;
            } else if pid == 0 {
                unsafe {
                    libc::_exit(0);
                }
            } else {
                succeeded += 1;
                children.push(pid);
            }
        }

        for pid in &children {
            unsafe {
                libc::waitpid(*pid, std::ptr::null_mut(), 0);
            }
        }

        (succeeded, failed)
    }

    // ─── Enforcement Setup ──────────────────────────────────────────────

    fn apply_landlock(sandbox_dir: &std::path::Path) {
        use landlock::{
            Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetError, RulesetStatus, ABI,
        };

        let abi = ABI::V4;
        let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
        let write_access = AccessFs::WriteFile
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::MakeReg
            | AccessFs::MakeDir;

        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .expect("handle_access")
            .create()
            .expect("create ruleset")
            .add_rule(PathBeneath::new(
                PathFd::new(sandbox_dir).expect("open sandbox_dir"),
                read_access | write_access,
            ))
            .expect("add sandbox rule")
            .add_rules(
                ["/usr/lib64", "/usr/lib", "/usr/libexec"]
                    .iter()
                    .filter_map(|p| {
                        PathFd::new(p)
                            .ok()
                            .map(|fd| Ok::<_, RulesetError>(PathBeneath::new(fd, read_access)))
                    }),
            )
            .expect("add lib rules")
            .add_rule(PathBeneath::new(
                PathFd::new("/proc").expect("open /proc"),
                read_access,
            ))
            .expect("add /proc rule")
            .add_rules(
                ["/dev/null", "/dev/urandom", "/dev/zero"]
                    .iter()
                    .filter_map(|p| {
                        PathFd::new(p).ok().map(|fd| {
                            Ok::<_, RulesetError>(PathBeneath::new(
                                fd,
                                read_access | AccessFs::WriteFile,
                            ))
                        })
                    }),
            )
            .expect("add /dev rules")
            .restrict_self()
            .expect("restrict_self");

        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                ok("Landlock ruleset applied (fully enforced)");
            }
            RulesetStatus::PartiallyEnforced => {
                ok("Landlock ruleset applied (partially enforced — older kernel)");
            }
            RulesetStatus::NotEnforced => {
                fail_msg("Landlock NOT enforced (kernel may not support it)");
            }
        }
    }

    fn apply_seccomp() {
        use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

        let mut filter =
            ScmpFilterContext::new_filter(ScmpAction::Allow).expect("create seccomp filter");

        // Deny list aligned with puzzled's SeccompBuilder (see seccomp/filter.rs).
        // Uses KillProcess (fail-closed) to match the production puzzled behavior:
        // blocked syscalls terminate the offending process immediately, preventing
        // the agent from probing for alternative escape paths.
        let deny_syscalls = [
            "ptrace",
            "kexec_load",
            "kexec_file_load",
            "init_module",
            "finit_module",
            "delete_module",
            "mount",
            "umount2",
            "pivot_root",
            "setns",
            "unshare",
            "bpf",
            "userfaultfd",
            "perf_event_open",
            "mount_setattr",
            "move_mount",
            "open_tree",
            "fsopen",
            "fspick",
            "fsconfig",
            "fsmount",
            "reboot",
            "swapon",
            "swapoff",
            "acct",
            "iopl",
            "ioperm",
            // io_uring bypasses seccomp for submitted operations
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            // Cross-process memory access
            "process_vm_readv",
            "process_vm_writev",
            // Process comparison info leak
            "kcmp",
            // Keyring manipulation
            "add_key",
            "keyctl",
            "request_key",
            // Execution domain change
            "personality",
            // Kernel log access
            "syslog",
            // Kernel profiling info leak
            "lookup_dcookie",
            // Handle-based file access bypass
            "name_to_handle_at",
            "open_by_handle_at",
            // Fileless execution
            "memfd_create",
            "memfd_secret",
            // Prevent chroot-based container/namespace escape
            "chroot",
            // Prevent time manipulation attacks
            "settimeofday",
            "clock_settime",
            // SysV IPC — block shared memory, semaphores, and message queues
            // to prevent cross-namespace communication (aligned with puzzled)
            "shmget",
            "shmat",
            "shmctl",
            "shmdt",
            "semget",
            "semop",
            "semctl",
            "semtimedop",
            "msgget",
            "msgsnd",
            "msgrcv",
            "msgctl",
        ];
        // NOTE: clone/clone3 intentionally NOT denied — agents need them
        // for thread creation. Namespace flags are gated separately.

        for name in &deny_syscalls {
            if let Ok(syscall) = ScmpSyscall::from_name(name) {
                filter
                    .add_rule(ScmpAction::KillProcess, syscall)
                    .unwrap_or_else(|e| {
                        eprintln!("    warning: could not add rule for {name}: {e}");
                    });
            }
        }

        // x86_64: block modify_ldt to prevent LDT call gate privilege escalation
        #[cfg(target_arch = "x86_64")]
        if let Ok(syscall) = ScmpSyscall::from_name("modify_ldt") {
            filter
                .add_rule(ScmpAction::KillProcess, syscall)
                .unwrap_or_else(|e| {
                    eprintln!("    warning: could not add rule for modify_ldt: {e}");
                });
        }

        filter.load().expect("load seccomp filter");
        ok("seccomp-BPF filter loaded (escape syscalls denied)");
    }

    fn drop_capabilities() {
        // Drop all capabilities from the bounding set
        for cap in 0..=63u64 {
            let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
            if ret < 0 {
                // EINVAL = capability doesn't exist on this kernel
                break;
            }
        }

        // Clear ambient capabilities
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            );
        }

        // Set NO_NEW_PRIVS
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret == 0 {
            ok("Capabilities dropped + NO_NEW_PRIVS set");
        } else {
            fail_msg("Failed to set NO_NEW_PRIVS");
        }
    }

    const CGROUP_PATH: &str = "/sys/fs/cgroup/puzzle-sandbox-demo-test";

    /// Clean up stale cgroup from a previous interrupted run.
    fn cleanup_stale_cgroup() {
        let cgroup_path = PathBuf::from(CGROUP_PATH);
        if cgroup_path.exists() {
            // Kill any stale processes still in the cgroup
            if let Ok(procs) = fs::read_to_string(cgroup_path.join("cgroup.procs")) {
                for line in procs.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                        unsafe {
                            libc::waitpid(pid, std::ptr::null_mut(), 0);
                        };
                    }
                }
            }
            // Move any remaining procs to root cgroup
            cleanup_cgroup(&cgroup_path);
            info("Cleaned up stale cgroup from previous run");
        }
    }

    fn setup_cgroup(child_pid: u32) -> Option<PathBuf> {
        let cgroup_path = PathBuf::from(CGROUP_PATH);

        if let Err(e) = fs::create_dir_all(&cgroup_path) {
            fail_msg(&format!("Could not create cgroup: {e}"));
            return None;
        }

        let parent_subtree = PathBuf::from("/sys/fs/cgroup/cgroup.subtree_control");
        if parent_subtree.exists() {
            let _ = fs::write(&parent_subtree, "+pids +memory");
        }

        let pids_max = cgroup_path.join("pids.max");
        if let Err(e) = fs::write(&pids_max, "8") {
            fail_msg(&format!("Could not set pids.max: {e}"));
            let _ = fs::remove_dir(&cgroup_path);
            return None;
        }

        let mem_max = cgroup_path.join("memory.max");
        let _ = fs::write(&mem_max, "67108864"); // 64 MiB

        let procs = cgroup_path.join("cgroup.procs");
        if let Err(e) = fs::write(&procs, child_pid.to_string()) {
            fail_msg(&format!("Could not move child into cgroup: {e}"));
            let _ = fs::remove_dir(&cgroup_path);
            return None;
        }

        ok(&format!(
            "cgroup scope created (pids.max=8, memory.max=64MiB, child PID {child_pid})"
        ));
        Some(cgroup_path)
    }

    fn cleanup_cgroup(cgroup_path: &std::path::Path) {
        if let Ok(procs) = fs::read_to_string(cgroup_path.join("cgroup.procs")) {
            let parent_procs = PathBuf::from("/sys/fs/cgroup/cgroup.procs");
            for line in procs.lines() {
                let _ = fs::write(&parent_procs, line);
            }
        }
        let _ = fs::remove_dir(cgroup_path);
    }

    // ─── Child Process ──────────────────────────────────────────────────

    fn run_child(sandbox_dir: &std::path::Path, enforce: bool, mut write_pipe: fs::File) {
        if enforce {
            // Wait for parent to set up cgroup
            let mut read_pipe = unsafe { fs::File::from_raw_fd(3) };
            let mut buf = [0u8; 1];
            let _ = read_pipe.read(&mut buf);
            drop(read_pipe);

            info("Applying Landlock filesystem restrictions...");
            apply_landlock(sandbox_dir);

            info("Loading seccomp-BPF syscall filter...");
            apply_seccomp();

            info("Dropping capabilities (PR_CAPBSET_DROP + NO_NEW_PRIVS)...");
            drop_capabilities();

            println!();
            info(&format!(
                "{BOLD}Enforcement active.{NC} Attempting escape vectors..."
            ));
        }

        println!();

        let r1 = try_read_shadow();
        test_result("Read /etc/shadow (credential theft)", r1, enforce);

        let r2 = try_write_escape();
        test_result("Write /tmp/escape.txt (data exfiltration)", r2, enforce);

        let r3 = try_mount();
        test_result("mount() syscall (container escape)", r3, enforce);

        // Fork bomb MUST run before ptrace — PTRACE_TRACEME causes the
        // process to stop on SIGCHLD from forked children, deadlocking.
        let fork_target = 20;
        let (succeeded, failed) = try_fork_bomb(fork_target);
        if enforce {
            if failed > 0 {
                ok(&format!(
                    "Fork bomb: {succeeded} succeeded, \
                     {RED}{failed} blocked{NC} by cgroup pids.max \
                     → {GREEN}BLOCKED{NC}"
                ));
            } else {
                fail_msg(&format!(
                    "Fork bomb: all {succeeded} forks succeeded \
                     (cgroup not enforcing)"
                ));
            }
        } else {
            ok(&format!(
                "Fork bomb: all {succeeded} forks succeeded \
                 → {YELLOW}allowed{NC} (no enforcement)"
            ));
        }

        let r4 = try_ptrace();
        test_result("ptrace() syscall (process injection)", r4, enforce);

        // Report results back to parent
        let blocked_count = [r1, r2, r3, r4].iter().filter(|&&x| x == enforce).count();
        let fork_ok = if enforce { failed > 0 } else { failed == 0 };
        let total = if fork_ok {
            blocked_count + 1
        } else {
            blocked_count
        };

        let msg = format!("{total}/5");
        let _ = write_pipe.write_all(msg.as_bytes());
        drop(write_pipe);

        process::exit(0);
    }

    // ─── Entry Point ────────────────────────────────────────────────────

    pub fn run_with_dir(sandbox_dir_arg: PathBuf) {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!(
                "{RED}Error:{NC} puzzle-sandbox-demo must be run as root \
                 (for cgroups + namespace setup)"
            );
            eprintln!("  sudo target/release/puzzle-sandbox-demo");
            process::exit(1);
        }

        cleanup_stale_cgroup();

        fs::create_dir_all(&sandbox_dir_arg).expect("create sandbox dir");
        let sandbox_dir = sandbox_dir_arg
            .canonicalize()
            .expect("canonicalize sandbox dir");

        println!();
        println!(
            "  {BOLD}{BLUE}\
             ════════════════════════════════════════════════════════════════\
             {NC}"
        );
        println!("  {BOLD}{BLUE}  Live Kernel Enforcement Demo{NC}");
        println!(
            "  {BOLD}{BLUE}\
             ════════════════════════════════════════════════════════════════\
             {NC}"
        );
        println!();
        info("This demo applies REAL Landlock + seccomp + cgroup enforcement");
        info("to a child process, then attempts 5 escape vectors.");
        info(&format!("Sandbox directory: {}", sandbox_dir.display()));
        println!();

        // ─── Phase 1: Without Enforcement ───────────────────────────────

        escape_header("Phase 1: WITHOUT Enforcement (baseline)");
        info("Running escape attempts with NO kernel restrictions.");
        info("All attempts should SUCCEED (proving the tests are real).");

        let (result_r, result_w) = make_pipe();

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            panic!("fork failed");
        } else if pid == 0 {
            unsafe { libc::close(result_r) };
            let wf = unsafe { fs::File::from_raw_fd(result_w) };
            run_child(&sandbox_dir, false, wf);
            unreachable!();
        }

        unsafe { libc::close(result_w) };
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        let mut result_buf = String::new();
        let mut rrf = unsafe { fs::File::from_raw_fd(result_r) };
        let _ = rrf.read_to_string(&mut result_buf);

        println!();
        info(&format!(
            "Baseline result: {BOLD}{result_buf}{NC} tests passed as expected"
        ));

        // ─── Phase 2: With Enforcement ──────────────────────────────────

        escape_header("Phase 2: WITH Enforcement (Landlock + seccomp + cgroup)");
        info(
            "Now applying REAL kernel enforcement before running \
             the same tests.",
        );
        info("All escape attempts should be BLOCKED by the kernel.");
        println!();

        let (sync_r, sync_w) = make_pipe();
        let (res_r, res_w) = make_pipe();

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            panic!("fork failed");
        } else if pid == 0 {
            unsafe {
                libc::close(sync_w);
                libc::close(res_r);
                if sync_r != 3 {
                    libc::dup2(sync_r, 3);
                    libc::close(sync_r);
                }
            }
            let wf = unsafe { fs::File::from_raw_fd(res_w) };
            run_child(&sandbox_dir, true, wf);
            unreachable!();
        }

        unsafe {
            libc::close(sync_r);
            libc::close(res_w);
        }

        let cgroup_path = setup_cgroup(pid as u32);
        println!();

        // Signal child: cgroup is ready
        unsafe { libc::close(sync_w) };

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        let mut result_buf = String::new();
        let mut rrf = unsafe { fs::File::from_raw_fd(res_r) };
        let _ = rrf.read_to_string(&mut result_buf);

        if let Some(ref cg) = cgroup_path {
            cleanup_cgroup(cg);
        }

        // ─── Summary ───────────────────────────────────────────────────

        println!();
        println!("  {BOLD}{BLUE}── Summary ──{NC}");
        println!();
        info(&format!(
            "Escape attempts blocked: {BOLD}{GREEN}{result_buf}{NC}"
        ));
        println!();
        println!("  {BOLD}Enforcement mechanisms used:{NC}");
        println!("    {GREEN}✓{NC} Landlock — irrevocable filesystem ACL (kernel LSM)");
        println!("    {GREEN}✓{NC} seccomp-BPF — irrevocable syscall filter (incl. io_uring)");
        println!("    {GREEN}✓{NC} cgroup pids.max — kernel-enforced process limit");
        println!("    {GREEN}✓{NC} Capabilities — all dropped via PR_CAPBSET_DROP + NO_NEW_PRIVS");
        println!();
        println!("  {BOLD}Key:{NC} All enforcement survives daemon crash.");
        println!("  The agent process cannot remove its own restrictions.");
        println!();

        let _ = fs::remove_dir_all(&sandbox_dir);
    }

    // ─── Exec Subcommand ────────────────────────────────────────────────

    const EXEC_CGROUP_PATH: &str = "/sys/fs/cgroup/sandbox-exec";

    /// Landlock rules for exec mode: allows executing system binaries and
    /// reading shared libraries, but restricts writes to the sandbox dir only.
    ///
    /// Uses the best available ABI to ensure all access types are handled.
    /// Unhandled access types cause Landlock to operate in best-effort mode,
    /// which silently allows those access types — a security gap.
    fn apply_landlock_exec(sandbox_dir: &std::path::Path, extra_read_paths: &[PathBuf]) {
        use landlock::{
            Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetError, RulesetStatus, ABI,
        };

        // Use the highest ABI we know about so that all access types are
        // handled. The landlock crate's best-effort compatibility will
        // downgrade flags the running kernel doesn't support, but the
        // key point is we *request* handling everything so the kernel
        // doesn't silently allow unhandled access types.
        let abi = ABI::V5;
        let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
        let exec_access = read_access | AccessFs::Execute;
        let write_access = AccessFs::WriteFile
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::MakeSym
            | AccessFs::Refer
            | AccessFs::Truncate;

        let mut rs = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .expect("handle_access")
            .create()
            .expect("create ruleset")
            // Sandbox dir: read + write (the only writable area)
            .add_rule(PathBeneath::new(
                PathFd::new(sandbox_dir).expect("open sandbox_dir"),
                read_access | write_access,
            ))
            .expect("add sandbox rule");

        // System binaries: read + execute (needed for execvp)
        rs = rs
            .add_rules(["/usr/bin", "/usr/sbin"].iter().filter_map(|p| {
                PathFd::new(p)
                    .ok()
                    .map(|fd| Ok::<_, RulesetError>(PathBeneath::new(fd, exec_access)))
            }))
            .expect("add exec rules");

        // Shared libraries: read + execute (dynamic linker needs Execute)
        rs = rs
            .add_rules(
                ["/usr/lib64", "/usr/lib", "/usr/libexec"]
                    .iter()
                    .filter_map(|p| {
                        PathFd::new(p)
                            .ok()
                            .map(|fd| Ok::<_, RulesetError>(PathBeneath::new(fd, exec_access)))
                    }),
            )
            .expect("add lib rules");

        // /etc: read-only (needed for /etc/ld.so.cache, /etc/localtime, etc.)
        // Note: writes to /etc/* are denied by Landlock (no write rule).
        rs = rs
            .add_rules(["/etc"].iter().filter_map(|p| {
                PathFd::new(p)
                    .ok()
                    .map(|fd| Ok::<_, RulesetError>(PathBeneath::new(fd, read_access)))
            }))
            .expect("add /etc rules");

        // /boot: read-only (deny writes to kernel images, grub, initramfs)
        rs = rs
            .add_rules(["/boot"].iter().filter_map(|p| {
                PathFd::new(p)
                    .ok()
                    .map(|fd| Ok::<_, RulesetError>(PathBeneath::new(fd, read_access)))
            }))
            .expect("add /boot rules");

        // /proc: read-only (sensitive paths are masked via bind-mount)
        rs = rs
            .add_rule(PathBeneath::new(
                PathFd::new("/proc").expect("open /proc"),
                read_access,
            ))
            .expect("add /proc rule");

        // Device files: read + write
        rs = rs
            .add_rules(
                ["/dev/null", "/dev/urandom", "/dev/zero"]
                    .iter()
                    .filter_map(|p| {
                        PathFd::new(p).ok().map(|fd| {
                            Ok::<_, RulesetError>(PathBeneath::new(
                                fd,
                                read_access | AccessFs::WriteFile,
                            ))
                        })
                    }),
            )
            .expect("add /dev rules");

        // Extra read paths from --allow-read
        if !extra_read_paths.is_empty() {
            rs = rs
                .add_rules(extra_read_paths.iter().filter_map(|p| {
                    PathFd::new(p)
                        .ok()
                        .map(|fd| Ok::<_, RulesetError>(PathBeneath::new(fd, read_access)))
                }))
                .expect("add extra read rules");
        }

        let status = rs.restrict_self().expect("restrict_self");
        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                ok("Landlock ruleset applied (fully enforced)");
            }
            RulesetStatus::PartiallyEnforced => {
                // Expected: directory-only flags stripped for file paths,
                // or kernel ABI is newer than requested.
                ok("Landlock ruleset applied (partially enforced)");
            }
            RulesetStatus::NotEnforced => {
                fail_msg("Landlock NOT enforced (kernel may not support it)");
            }
        }
    }

    fn setup_cgroup_exec(child_pid: u32, pids_max: u32, memory_max: u64) -> Option<PathBuf> {
        let cgroup_path = PathBuf::from(EXEC_CGROUP_PATH);

        if let Err(e) = fs::create_dir_all(&cgroup_path) {
            fail_msg(&format!("Could not create exec cgroup: {e}"));
            return None;
        }

        let parent_subtree = PathBuf::from("/sys/fs/cgroup/cgroup.subtree_control");
        if parent_subtree.exists() {
            let _ = fs::write(&parent_subtree, "+pids +memory");
        }

        if let Err(e) = fs::write(cgroup_path.join("pids.max"), pids_max.to_string()) {
            fail_msg(&format!("Could not set pids.max: {e}"));
            let _ = fs::remove_dir(&cgroup_path);
            return None;
        }

        let _ = fs::write(cgroup_path.join("memory.max"), memory_max.to_string());

        if let Err(e) = fs::write(cgroup_path.join("cgroup.procs"), child_pid.to_string()) {
            fail_msg(&format!("Could not move child into exec cgroup: {e}"));
            let _ = fs::remove_dir(&cgroup_path);
            return None;
        }

        ok(&format!(
            "cgroup scope created (pids.max={pids_max}, memory.max={memory_max}, child PID {child_pid})"
        ));
        Some(cgroup_path)
    }

    /// Apply all enforcement layers and exec the command. Called from the
    /// innermost process (grandchild with PID NS, or child as fallback).
    fn apply_enforcement_and_exec(
        sandbox_dir: &std::path::Path,
        allow_read: &[PathBuf],
        command: &[String],
    ) -> ! {
        info("Applying Landlock filesystem restrictions...");
        apply_landlock_exec(sandbox_dir, allow_read);

        info("Loading seccomp-BPF syscall filter...");
        apply_seccomp();

        info("Dropping capabilities (PR_CAPBSET_DROP + NO_NEW_PRIVS)...");
        drop_capabilities();

        println!();

        let cmd = CString::new(command[0].as_str()).expect("invalid command");
        let args: Vec<CString> = command
            .iter()
            .map(|a| CString::new(a.as_str()).expect("invalid argument"))
            .collect();
        let c_args: Vec<*const libc::c_char> = args
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        unsafe { libc::execvp(cmd.as_ptr(), c_args.as_ptr()) };

        let err = std::io::Error::last_os_error();
        eprintln!("{RED}Error:{NC} execvp({}) failed: {err}", command[0]);
        process::exit(127);
    }

    /// Sensitive procfs/sysfs paths to mask (aligned with puzzled SENSITIVE_PATHS).
    /// Only includes /proc paths since the demo doesn't grant /sys access.
    const EXEC_SENSITIVE_PATHS: &[&str] = &[
        "/proc/kcore",
        "/proc/sysrq-trigger",
        "/proc/keys",
        "/proc/kmsg",
        "/proc/kallsyms",
        "/proc/sched_debug",
        "/proc/timer_list",
    ];

    /// Mask sensitive /proc paths by bind-mounting /dev/null over them.
    /// Must be called inside the mount namespace, after /proc remount,
    /// and before Landlock (which blocks mount). Best-effort: failures
    /// are logged but do not abort.
    fn mask_sensitive_paths() {
        let dev_null = CString::new("/dev/null").unwrap();
        let none = CString::new("none").unwrap();
        let mut masked = 0u32;

        for path_str in EXEC_SENSITIVE_PATHS {
            let target = CString::new(*path_str).unwrap();

            if unsafe { libc::access(target.as_ptr(), libc::F_OK) } != 0 {
                continue;
            }

            let ret = unsafe {
                libc::mount(
                    dev_null.as_ptr(),
                    target.as_ptr(),
                    none.as_ptr(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                continue;
            }

            // Remount read-only to prevent unmounting
            unsafe {
                libc::mount(
                    dev_null.as_ptr(),
                    target.as_ptr(),
                    none.as_ptr(),
                    libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                    std::ptr::null(),
                );
            }
            masked += 1;
        }

        if masked > 0 {
            ok(&format!("Masked {masked} sensitive /proc paths"));
        }
    }

    /// Remount /proc scoped to the new PID namespace. Must be called after
    /// unshare(CLONE_NEWNS) and before seccomp (which blocks mount/umount).
    /// Follows the puzzled pattern from sandbox/mod.rs.
    fn remount_proc() -> bool {
        unsafe {
            // Make the mount tree private so umount2(/proc) does not
            // propagate to the parent's mount namespace.
            let root = CString::new("/").unwrap();
            if libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                eprintln!(
                    "  {YELLOW}warning:{NC} mount(MS_REC|MS_PRIVATE) failed: {}",
                    std::io::Error::last_os_error()
                );
                return false;
            }

            let proc_path = CString::new("/proc").unwrap();
            let proc_type = CString::new("proc").unwrap();

            // Detach inherited /proc (shows host PIDs)
            if libc::umount2(proc_path.as_ptr(), libc::MNT_DETACH) != 0 {
                eprintln!(
                    "  {YELLOW}warning:{NC} umount2(/proc) failed: {}",
                    std::io::Error::last_os_error()
                );
                return false;
            }

            // Mount fresh /proc scoped to this PID namespace
            if libc::mount(
                proc_type.as_ptr(),
                proc_path.as_ptr(),
                proc_type.as_ptr(),
                0,
                std::ptr::null(),
            ) != 0
            {
                eprintln!(
                    "  {YELLOW}warning:{NC} mount(proc) failed: {}",
                    std::io::Error::last_os_error()
                );
                return false;
            }
        }
        true
    }

    fn run_exec_child(
        sandbox_dir: &std::path::Path,
        allow_read: &[PathBuf],
        command: &[String],
    ) -> ! {
        // Wait for parent to set up cgroup (EOF on fd 3 = ready)
        let mut read_pipe = unsafe { fs::File::from_raw_fd(3) };
        let mut buf = [0u8; 1];
        let _ = read_pipe.read(&mut buf);
        drop(read_pipe);

        // Attempt PID + mount namespace isolation (before seccomp blocks these)
        let ns_ret = unsafe { libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) };
        if ns_ret == 0 {
            ok("PID + mount namespace created");

            // Fork so the grandchild becomes PID 1 in the new namespace
            let grandchild = unsafe { libc::fork() };
            if grandchild < 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("{RED}Error:{NC} fork after unshare failed: {err}");
                process::exit(1);
            }
            if grandchild > 0 {
                // Intermediate child: wait for grandchild and propagate exit code
                let mut status: i32 = 0;
                unsafe { libc::waitpid(grandchild, &mut status, 0) };
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    1
                };
                process::exit(code);
            }

            // Grandchild: PID 1 in new namespace
            if remount_proc() {
                ok("/proc remounted (scoped to PID namespace)");
                mask_sensitive_paths();
            }

            apply_enforcement_and_exec(sandbox_dir, allow_read, command);
        }

        // Fallback: unshare failed — continue without namespace isolation
        let err = std::io::Error::last_os_error();
        eprintln!(
            "  {YELLOW}warning:{NC} unshare(NEWPID|NEWNS) failed: {err} \
             — continuing without namespace isolation"
        );

        apply_enforcement_and_exec(sandbox_dir, allow_read, command);
    }

    pub fn run_exec(
        sandbox_dir_arg: PathBuf,
        allow_read: Vec<PathBuf>,
        pids_max: u32,
        memory_max: u64,
        command: Vec<String>,
    ) -> i32 {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!(
                "{RED}Error:{NC} puzzle-sandbox-demo exec must be run as root \
                 (for cgroups + enforcement setup)"
            );
            return 1;
        }

        if command.is_empty() {
            eprintln!("{RED}Error:{NC} No command specified");
            return 1;
        }

        // Clean up stale exec cgroup from a previous run
        let exec_cgroup = PathBuf::from(EXEC_CGROUP_PATH);
        if exec_cgroup.exists() {
            if let Ok(procs) = fs::read_to_string(exec_cgroup.join("cgroup.procs")) {
                for line in procs.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                    }
                }
            }
            cleanup_cgroup(&exec_cgroup);
        }

        fs::create_dir_all(&sandbox_dir_arg).expect("create sandbox dir");
        let sandbox_dir = sandbox_dir_arg
            .canonicalize()
            .expect("canonicalize sandbox dir");

        let (sync_r, sync_w) = make_pipe();

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            panic!("fork failed");
        } else if pid == 0 {
            // Child: set up sync pipe on fd 3, then wait for cgroup
            unsafe {
                libc::close(sync_w);
                if sync_r != 3 {
                    libc::dup2(sync_r, 3);
                    libc::close(sync_r);
                }
            }
            run_exec_child(&sandbox_dir, &allow_read, &command);
        }

        // Parent: close read end of sync pipe
        unsafe { libc::close(sync_r) };

        // Set up cgroup with configured limits
        let cgroup_path = setup_cgroup_exec(pid as u32, pids_max, memory_max);

        // Signal child: cgroup is ready (close write end → child gets EOF)
        unsafe { libc::close(sync_w) };

        // Wait for child to complete
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        // Cleanup
        if let Some(ref cg) = cgroup_path {
            cleanup_cgroup(cg);
        }
        let _ = fs::remove_dir_all(&sandbox_dir);

        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        }
    }
}
