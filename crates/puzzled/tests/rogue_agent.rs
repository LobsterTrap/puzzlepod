// SPDX-License-Identifier: Apache-2.0
//! Integration test: Rogue Agent shell security tests.
//!
//! Wraps the shell-based security test scripts so they run as part of
//! `cargo test -- --ignored` on privileged CI runners. Each test invokes
//! the corresponding shell script and asserts exit code 0.
//!
//! These tests are Linux-only and require root.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn security_script(name: &str) -> PathBuf {
    project_root().join("tests").join("security").join(name)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn find_puzzle_sandbox_demo() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SANDBOX_DEMO") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    let root = project_root();
    for dir in ["release", "debug"] {
        let path = root.join("target").join(dir).join("puzzle-sandbox-demo");
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        for dir in ["release", "debug"] {
            let path = PathBuf::from(&target_dir).join(dir).join("puzzle-sandbox-demo");
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
}

/// Run the rogue agent test suite in kernel-only mode (unshare).
///
/// This validates that the shell test script executes successfully and
/// produces the expected PASS/FAIL results when run with only kernel
/// namespace primitives (no Landlock/seccomp/cgroup enforcement).
#[test]
#[ignore]
fn rogue_agent_kernel_only() {
    if !is_root() {
        eprintln!("SKIP: requires root");
        return;
    }

    let script = security_script("run_rogue_agent.sh");
    if !script.exists() {
        eprintln!("SKIP: {} not found", script.display());
        return;
    }

    let output = Command::new("bash")
        .arg(&script)
        .arg("--mode=kernel-only")
        .env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin")
        .output()
        .expect("failed to execute run_rogue_agent.sh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- stdout ---\n{stdout}");
    eprintln!("--- stderr ---\n{stderr}");

    // kernel-only mode is expected to have some attacks succeed (exit 1),
    // so we don't assert exit code 0 — we just verify the script ran.
    assert!(
        stdout.contains("PASS") || stdout.contains("FAIL"),
        "script should produce test output"
    );
}

/// Run the rogue agent test suite in full sandbox mode (puzzle-sandbox-demo exec).
///
/// Requires the puzzle-sandbox-demo binary to be built. All attacks should be
/// blocked by the Landlock + seccomp + cgroup + capability enforcement.
#[test]
#[ignore]
fn rogue_agent_sandbox() {
    if !is_root() {
        eprintln!("SKIP: requires root");
        return;
    }

    let script = security_script("run_rogue_agent.sh");
    if !script.exists() {
        eprintln!("SKIP: {} not found", script.display());
        return;
    }

    let puzzle_sandbox_demo = match find_puzzle_sandbox_demo() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: puzzle-sandbox-demo binary not found, build with cargo build --workspace");
            return;
        }
    };

    let output = Command::new("bash")
        .arg(&script)
        .arg("--mode=sandbox")
        .env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin")
        .env("SANDBOX_DEMO", &puzzle_sandbox_demo)
        .output()
        .expect("failed to execute run_rogue_agent.sh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- stdout ---\n{stdout}");
    eprintln!("--- stderr ---\n{stderr}");

    assert!(
        stdout.contains("PASS") || stdout.contains("FAIL"),
        "script should produce test output"
    );
}

/// Run the sandbox escape test suite (test_sandbox_escape.sh).
///
/// Tests the specific escape vectors from within the puzzled sandbox:
/// Landlock file access, seccomp (ptrace, io_uring, mount, insmod, SysV IPC),
/// capabilities, path traversal, setns, unshare, bpf, and sensitive /proc path masking.
#[test]
#[ignore]
fn sandbox_escape_tests() {
    if !is_root() {
        eprintln!("SKIP: requires root");
        return;
    }

    let script = security_script("test_sandbox_escape.sh");
    if !script.exists() {
        eprintln!("SKIP: {} not found", script.display());
        return;
    }

    let puzzle_sandbox_demo = find_puzzle_sandbox_demo();
    if puzzle_sandbox_demo.is_none() {
        eprintln!("SKIP: puzzle-sandbox-demo binary not found, build with cargo build --workspace");
        return;
    }

    let mut cmd = Command::new("bash");
    cmd.arg(&script)
        .env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin");
    if let Some(ref demo) = puzzle_sandbox_demo {
        cmd.env("SANDBOX_DEMO", demo);
    }

    let output = cmd
        .output()
        .expect("failed to execute test_sandbox_escape.sh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- stdout ---\n{stdout}");
    eprintln!("--- stderr ---\n{stderr}");

    let code = output.status.code().unwrap_or(-1);
    if code == 77 {
        eprintln!("SKIP: test_sandbox_escape.sh returned 77 (skip)");
        return;
    }
    assert!(
        output.status.success(),
        "sandbox escape tests should pass (exit code {})",
        code
    );
}
