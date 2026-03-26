// SPDX-License-Identifier: Apache-2.0
// ---------------------------------------------------------------------------
// Process memory reading for syscall argument inspection
// ---------------------------------------------------------------------------
// Functions are only called from libseccomp_v2_5-gated code at runtime.
#![allow(dead_code)]

/// Read a null-terminated string from a process's memory via /proc/<pid>/mem.
///
/// Used to extract the execve binary path from the agent's address space.
/// The address comes from the seccomp notification's syscall argument.
#[cfg(target_os = "linux")]
pub(super) fn read_string_from_proc_mem(
    pid: u32,
    addr: usize,
) -> std::result::Result<String, String> {
    use std::io::{Read, Seek, SeekFrom};

    if addr == 0 {
        return Err("null pointer".to_string());
    }

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file =
        std::fs::File::open(&mem_path).map_err(|e| format!("opening {}: {}", mem_path, e))?;

    file.seek(SeekFrom::Start(addr as u64))
        .map_err(|e| format!("seeking to 0x{:x} in {}: {}", addr, mem_path, e))?;

    // T11: Read up to 4096 bytes looking for null terminator (PATH_MAX on Linux).
    // Partial reads are fail-closed: if read() returns fewer bytes than available
    // and the null terminator falls beyond, the syscall is denied (safe default).
    let mut buf = vec![0u8; 4096];
    let n = file
        .read(&mut buf)
        .map_err(|e| format!("reading from {}: {}", mem_path, e))?;

    // P2-N3: Find null terminator — return error if not found within buffer
    let end = buf[..n].iter().position(|&b| b == 0).ok_or_else(|| {
        format!(
            "no null terminator found within {} bytes read from {}",
            n, mem_path
        )
    })?;

    String::from_utf8(buf[..end].to_vec()).map_err(|e| format!("invalid UTF-8 in path: {}", e))
}

/// Read a u64 value from a process's memory via /proc/<pid>/mem.
///
/// Used to extract the clone flags from `struct clone_args` in the agent's
/// address space. The address comes from the seccomp notification's arg0
/// for clone3 (which is a pointer to the struct, not the flags directly).
#[cfg(target_os = "linux")]
pub(super) fn read_u64_from_proc_mem(pid: u32, addr: usize) -> std::result::Result<u64, String> {
    use std::io::{Read, Seek, SeekFrom};

    if addr == 0 {
        return Err("null pointer".to_string());
    }

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file =
        std::fs::File::open(&mem_path).map_err(|e| format!("opening {}: {}", mem_path, e))?;

    file.seek(SeekFrom::Start(addr as u64))
        .map_err(|e| format!("seeking to 0x{:x} in {}: {}", addr, mem_path, e))?;

    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)
        .map_err(|e| format!("reading u64 from {}: {}", mem_path, e))?;

    Ok(u64::from_ne_bytes(buf))
}

/// Read a sockaddr structure from a process's memory via /proc/<pid>/mem.
///
/// Returns (address_family, ip_string, port) for AF_INET and AF_INET6.
#[cfg(target_os = "linux")]
pub(super) fn read_sockaddr_from_proc_mem(
    pid: u32,
    addr: usize,
    len: usize,
) -> std::result::Result<(u16, String, u16), String> {
    use std::io::{Read, Seek, SeekFrom};

    if addr == 0 || len == 0 {
        return Err("null sockaddr".to_string());
    }

    // Cap read length to prevent excessive reads
    let read_len = len.min(128);

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file =
        std::fs::File::open(&mem_path).map_err(|e| format!("opening {}: {}", mem_path, e))?;

    file.seek(SeekFrom::Start(addr as u64))
        .map_err(|e| format!("seeking to 0x{:x}: {}", addr, e))?;

    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf)
        .map_err(|e| format!("reading sockaddr: {}", e))?;

    // Parse address family (first 2 bytes, native byte order)
    let family = u16::from_ne_bytes([buf[0], buf[1]]);

    match family as i32 {
        libc::AF_INET => {
            if read_len < std::mem::size_of::<libc::sockaddr_in>() {
                return Err("sockaddr_in too short".to_string());
            }
            // Port is bytes 2-3 in network byte order
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            // IP address is bytes 4-7
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            Ok((family, ip, port))
        }
        libc::AF_INET6 => {
            if read_len < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err("sockaddr_in6 too short".to_string());
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            // IPv6 address is bytes 8-23
            let mut segments = [0u16; 8];
            for i in 0..8 {
                segments[i] = u16::from_be_bytes([buf[8 + i * 2], buf[9 + i * 2]]);
            }
            let ip = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            );
            Ok((family, ip, port))
        }
        libc::AF_UNIX => {
            // Unix domain socket — extract path
            let path_bytes = &buf[2..];
            let end = path_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(path_bytes.len());
            let path = String::from_utf8_lossy(&path_bytes[..end]).to_string();
            Ok((family, path, 0))
        }
        _ => Err(format!("unsupported address family: {}", family)),
    }
}
