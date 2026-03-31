// SPDX-License-Identifier: Apache-2.0
//! §3.4 G3/G4: Secure memory region for credential storage.
//!
//! Provides `SecureRegion` — an mmap-backed memory region with:
//! - `mlock()` to prevent swapping to disk
//! - `MADV_DONTDUMP` to exclude from core dumps
//! - Guard pages (`PROT_NONE`) for overflow detection
//! - Volatile zeroize on `Drop` with compiler fence
//!
//! Also provides `SecureCredentialStore` (slot-based credential storage) and
//! `CredentialManager` (thread-safe async wrapper with zero-copy access).

use std::collections::HashMap;
use std::sync::atomic::{compiler_fence, Ordering};

/// Errors from secure memory operations.
#[derive(Debug, thiserror::Error)]
pub enum SecureMemoryError {
    #[error(
        "mlock failed: {0} (mlock_required=true, cannot store credentials in swappable memory)"
    )]
    MlockFailed(std::io::Error),
    #[error("mmap failed: {0}")]
    MmapFailed(std::io::Error),
    #[error("store is full: {used}/{capacity} slots used")]
    StoreFull { used: usize, capacity: usize },
    #[error("credential too large: {size} bytes exceeds slot capacity {capacity}")]
    CredentialTooLarge { size: usize, capacity: usize },
    #[error("credential not found: {0}")]
    NotFound(String),
    #[error("rotate failed: new value ({new_size} bytes) exceeds slot capacity ({capacity})")]
    RotateExceedsCapacity { new_size: usize, capacity: usize },
}

// ---------------------------------------------------------------------------
// SecureRegion — mmap-backed secure memory
// ---------------------------------------------------------------------------

/// A memory region backed by `mmap(MAP_ANONYMOUS | MAP_PRIVATE)` with
/// security hardening: `mlock`, `MADV_DONTDUMP`, and `PROT_NONE` guard pages.
pub(crate) struct SecureRegion {
    /// Pointer to the start of the full allocation (including guard pages).
    base_ptr: *mut u8,
    /// Total allocation size including guard pages.
    total_size: usize,
    /// Offset from base_ptr to the usable region (after the leading guard page).
    usable_offset: usize,
    /// Size of the usable region (excluding guard pages).
    usable_size: usize,
    /// Page size on this system.
    #[allow(dead_code)]
    page_size: usize,
}

// SAFETY: SecureRegion manages raw memory that is not shared across threads
// by itself. Thread safety is provided by the CredentialManager's RwLock.
unsafe impl Send for SecureRegion {}
unsafe impl Sync for SecureRegion {}

impl SecureRegion {
    /// Create a new secure memory region.
    ///
    /// - `size`: desired usable size (will be rounded up to page boundary)
    /// - `mlock_required`: if true, `mlock()` failure is fatal
    ///
    /// Layout: [guard page] [usable region] [guard page]
    pub fn new(size: usize, mlock_required: bool) -> Result<Self, SecureMemoryError> {
        let page_size = page_size();
        // Round up to page boundary
        let usable_size = (size + page_size - 1) & !(page_size - 1);
        // Total = leading guard + usable + trailing guard
        let total_size = usable_size + 2 * page_size;

        // SAFETY: mmap with MAP_ANONYMOUS|MAP_PRIVATE allocates zeroed private memory.
        // NULL base lets the kernel choose the address. fd=-1, offset=0 for anonymous.
        // Return value is checked for MAP_FAILED before use.
        let base_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if base_ptr == libc::MAP_FAILED {
            return Err(SecureMemoryError::MmapFailed(
                std::io::Error::last_os_error(),
            ));
        }
        let base_ptr = base_ptr as *mut u8;

        // SAFETY: mprotect on regions within our mmap allocation. Pointers are valid
        // and within bounds (leading guard = base_ptr, trailing = base_ptr + page_size + usable_size).
        // On failure, we munmap the entire allocation before returning.
        unsafe {
            // Leading guard page
            if libc::mprotect(base_ptr as *mut libc::c_void, page_size, libc::PROT_NONE) != 0 {
                libc::munmap(base_ptr as *mut libc::c_void, total_size);
                return Err(SecureMemoryError::MmapFailed(
                    std::io::Error::last_os_error(),
                ));
            }
            // Trailing guard page
            let trailing = base_ptr.add(page_size + usable_size);
            if libc::mprotect(trailing as *mut libc::c_void, page_size, libc::PROT_NONE) != 0 {
                libc::munmap(base_ptr as *mut libc::c_void, total_size);
                return Err(SecureMemoryError::MmapFailed(
                    std::io::Error::last_os_error(),
                ));
            }
        }

        // SAFETY: base_ptr.add(page_size) is within the mmap'd region (total_size > page_size).
        let usable_ptr = unsafe { base_ptr.add(page_size) };

        // SAFETY: usable_ptr points to page-aligned memory within our allocation.
        // Lock usable region in RAM (prevent swapping).
        let mlock_result = unsafe { libc::mlock(usable_ptr as *const libc::c_void, usable_size) };
        if mlock_result != 0 {
            let err = std::io::Error::last_os_error();
            if mlock_required {
                unsafe {
                    libc::munmap(base_ptr as *mut libc::c_void, total_size);
                }
                return Err(SecureMemoryError::MlockFailed(err));
            }
            // §3.4 T2.4: PRD requires Critical audit event when mlock fails with
            // mlock_required=false. Use tracing::error! with structured audit fields
            // so the audit subsystem can capture this as a Critical event.
            tracing::error!(
                error = %err,
                audit_type = "credential.mlock_failed",
                severity = "critical",
                "§3.4 G3: mlock() failed — credentials may be swapped to disk. \
                 Set LimitMEMLOCK=infinity in puzzled.service."
            );
        }

        // SAFETY: Advisory only — MADV_DONTDUMP tells the kernel to exclude this
        // region from core dumps. usable_ptr and usable_size are valid.
        unsafe {
            libc::madvise(
                usable_ptr as *mut libc::c_void,
                usable_size,
                libc::MADV_DONTDUMP,
            );
        }

        Ok(Self {
            base_ptr,
            total_size,
            usable_offset: page_size,
            usable_size,
            page_size,
        })
    }

    /// Write data to the region at the given offset.
    ///
    /// # Panics
    /// Panics if `offset + data.len()` exceeds the usable region.
    pub fn write(&self, offset: usize, data: &[u8]) {
        assert!(
            offset + data.len() <= self.usable_size,
            "SecureRegion::write out of bounds: offset={} len={} usable={}",
            offset,
            data.len(),
            self.usable_size
        );
        // SAFETY: Bounds checked by assert above. dst is within the usable region.
        unsafe {
            let dst = self.base_ptr.add(self.usable_offset + offset);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
    }

    /// Read data from the region at the given offset.
    ///
    /// # Panics
    /// Panics if `offset + len` exceeds the usable region.
    pub fn read(&self, offset: usize, len: usize) -> &[u8] {
        assert!(
            offset + len <= self.usable_size,
            "SecureRegion::read out of bounds: offset={} len={} usable={}",
            offset,
            len,
            self.usable_size
        );
        // SAFETY: Bounds checked by assert above. src is within the usable region.
        // The returned slice borrows &self, so the region cannot be dropped while in use.
        unsafe {
            let src = self.base_ptr.add(self.usable_offset + offset);
            std::slice::from_raw_parts(src, len)
        }
    }

    /// Volatile-zeroize a specific slot in the region.
    pub fn zeroize_slot(&self, offset: usize, len: usize) {
        assert!(
            offset + len <= self.usable_size,
            "SecureRegion::zeroize_slot out of bounds"
        );
        // SAFETY: Bounds checked by assert above. write_volatile ensures the compiler
        // cannot elide the zeroing. compiler_fence after the block prevents reordering.
        unsafe {
            let ptr = self.base_ptr.add(self.usable_offset + offset);
            for i in 0..len {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Total usable size of the region.
    #[cfg(test)]
    pub fn usable_size(&self) -> usize {
        self.usable_size
    }
}

impl Drop for SecureRegion {
    fn drop(&mut self) {
        // SAFETY: Zeroize the entire usable region using write_volatile to prevent
        // the compiler from eliding the write. compiler_fence ensures ordering.
        unsafe {
            let ptr = self.base_ptr.add(self.usable_offset);
            for i in 0..self.usable_size {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        compiler_fence(Ordering::SeqCst);

        // SAFETY: munlock + munmap on the original allocation. base_ptr and sizes
        // are unchanged since construction. Must occur unconditionally in drop.
        unsafe {
            let usable_ptr = self.base_ptr.add(self.usable_offset);
            libc::munlock(usable_ptr as *const libc::c_void, self.usable_size);
            libc::munmap(self.base_ptr as *mut libc::c_void, self.total_size);
        }
    }
}

/// Get the system page size.
fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) is a read-only query with no side effects.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

// ---------------------------------------------------------------------------
// SecureCredentialStore — slot-based credential storage
// ---------------------------------------------------------------------------

/// A single credential slot within the SecureRegion.
#[derive(Debug, Clone)]
struct CredentialSlot {
    /// Offset into the SecureRegion.
    offset: usize,
    /// Current length of the credential value.
    len: usize,
    /// Maximum capacity of this slot (fixed at allocation time).
    capacity: usize,
}

/// Slot-based credential store backed by a `SecureRegion`.
///
/// Credentials are stored in fixed-size slots within the secure region.
/// Each slot has a maximum capacity set at allocation time.
pub struct SecureCredentialStore {
    region: SecureRegion,
    /// Maps phantom token → slot metadata.
    index: HashMap<String, CredentialSlot>,
    /// Next available offset for allocation.
    next_offset: usize,
    /// Maximum credential value size per slot.
    slot_capacity: usize,
    /// Maximum number of credentials.
    max_credentials: usize,
}

impl SecureCredentialStore {
    /// Create a new credential store.
    ///
    /// - `max_credentials`: maximum number of credentials
    /// - `slot_capacity`: maximum bytes per credential value
    /// - `mlock_required`: if true, fail if mlock() is unavailable
    pub fn new(
        max_credentials: usize,
        slot_capacity: usize,
        mlock_required: bool,
    ) -> Result<Self, SecureMemoryError> {
        let total_size = max_credentials * slot_capacity;
        let region = SecureRegion::new(total_size, mlock_required)?;
        Ok(Self {
            region,
            index: HashMap::with_capacity(max_credentials),
            next_offset: 0,
            slot_capacity,
            max_credentials,
        })
    }

    /// Store a credential value under the given phantom token key.
    pub fn store(&mut self, phantom_token: &str, value: &[u8]) -> Result<(), SecureMemoryError> {
        if value.len() > self.slot_capacity {
            return Err(SecureMemoryError::CredentialTooLarge {
                size: value.len(),
                capacity: self.slot_capacity,
            });
        }
        if self.index.len() >= self.max_credentials {
            return Err(SecureMemoryError::StoreFull {
                used: self.index.len(),
                capacity: self.max_credentials,
            });
        }

        // Allocate a new slot
        let offset = self.next_offset;
        self.next_offset += self.slot_capacity;

        // Write the credential value
        self.region.write(offset, value);

        self.index.insert(
            phantom_token.to_string(),
            CredentialSlot {
                offset,
                len: value.len(),
                capacity: self.slot_capacity,
            },
        );

        Ok(())
    }

    /// Resolve a phantom token to the credential value bytes.
    pub fn resolve(&self, phantom_token: &str) -> Option<&[u8]> {
        let slot = self.index.get(phantom_token)?;
        Some(self.region.read(slot.offset, slot.len))
    }

    /// Rotate a credential: zeroize old value, write new value in the same slot.
    pub fn rotate(
        &mut self,
        phantom_token: &str,
        new_value: &[u8],
    ) -> Result<(), SecureMemoryError> {
        let slot = self
            .index
            .get_mut(phantom_token)
            .ok_or_else(|| SecureMemoryError::NotFound(phantom_token.to_string()))?;

        if new_value.len() > slot.capacity {
            return Err(SecureMemoryError::RotateExceedsCapacity {
                new_size: new_value.len(),
                capacity: slot.capacity,
            });
        }

        // Zeroize old value — zeroize full capacity (not just len) to clear tail
        // bytes from prior credentials that may have been longer than the current one.
        self.region.zeroize_slot(slot.offset, slot.capacity);
        // Write new value
        self.region.write(slot.offset, new_value);
        slot.len = new_value.len();

        Ok(())
    }

    /// Remove a credential: zeroize the slot and remove from index.
    pub fn remove(&mut self, phantom_token: &str) -> Result<(), SecureMemoryError> {
        let slot = self
            .index
            .remove(phantom_token)
            .ok_or_else(|| SecureMemoryError::NotFound(phantom_token.to_string()))?;
        // Zeroize full slot capacity to clear all residual credential bytes.
        self.region.zeroize_slot(slot.offset, slot.capacity);
        Ok(())
    }

    /// Scan a byte buffer for any credential values (direct byte comparison).
    ///
    /// Returns a list of (phantom_token, byte_offset) for each match found.
    /// Uses direct byte comparison — NO Aho-Corasick or other algorithms that
    /// would copy credential values to heap memory.
    pub fn scan_bytes(&self, haystack: &[u8]) -> Vec<(String, usize)> {
        let mut matches = Vec::new();
        for (token, slot) in &self.index {
            let needle = self.region.read(slot.offset, slot.len);
            if needle.is_empty() {
                continue;
            }
            // Simple byte search — O(n*m) but credentials are short and
            // this avoids any heap allocation of credential bytes.
            for i in 0..=(haystack.len().saturating_sub(needle.len())) {
                if &haystack[i..i + needle.len()] == needle {
                    matches.push((token.clone(), i));
                }
            }
        }
        matches
    }

    /// Number of credentials currently stored.
    pub fn credential_count(&self) -> usize {
        self.index.len()
    }

    /// Check if a phantom token exists in the store.
    pub fn contains(&self, phantom_token: &str) -> bool {
        self.index.contains_key(phantom_token)
    }
}

// ---------------------------------------------------------------------------
// §3.4 G4: CredentialManager — thread-safe async wrapper
// ---------------------------------------------------------------------------

use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

/// Thread-safe async credential manager wrapping `SecureCredentialStore`.
///
/// All credential access goes through `tokio::sync::RwLock` to ensure
/// safe concurrent reads and exclusive writes.
pub struct CredentialManager {
    store: Arc<RwLock<SecureCredentialStore>>,
}

impl CredentialManager {
    /// Create a new credential manager.
    pub fn new(
        max_credentials: usize,
        slot_capacity: usize,
        mlock_required: bool,
    ) -> Result<Self, SecureMemoryError> {
        let store = SecureCredentialStore::new(max_credentials, slot_capacity, mlock_required)?;
        Ok(Self {
            store: Arc::new(RwLock::new(store)),
        })
    }

    /// Resolve a phantom token to a `SecureRef` that borrows credential bytes
    /// from the secure region.
    ///
    /// The returned `SecureRef` holds the read lock — the credential bytes remain
    /// valid and accessible as long as the `SecureRef` is alive. No credential
    /// data is copied to heap memory.
    pub async fn resolve(&self, phantom_token: &str) -> Option<SecureRef> {
        let guard = self.store.clone().read_owned().await;
        let slot = guard.index.get(phantom_token)?;
        let offset = slot.offset;
        let len = slot.len;
        Some(SecureRef {
            _guard: guard,
            // SAFETY: The guard keeps the RwLock held, and the SecureRegion's
            // memory is valid for the lifetime of the guard. We store offset/len
            // to reconstruct the slice when dereferenced.
            offset,
            len,
        })
    }

    /// Store a credential value under the given phantom token.
    pub async fn store(&self, phantom_token: &str, value: &[u8]) -> Result<(), SecureMemoryError> {
        let mut guard = self.store.write().await;
        guard.store(phantom_token, value)
    }

    /// Rotate a credential: zeroize old value, write new value (same slot).
    ///
    /// M-12: Caller responsibility — the `new_value` parameter borrows from the caller.
    /// Callers MUST ensure the source buffer is wrapped in `Zeroizing<Vec<u8>>` (or
    /// equivalent) so that the caller's copy is zeroized after this call returns.
    /// The mlock'd store will hold its own copy in the secure region; the caller's
    /// heap copy must not persist.
    pub async fn rotate(
        &self,
        phantom_token: &str,
        new_value: &[u8],
    ) -> Result<(), SecureMemoryError> {
        let mut guard = self.store.write().await;
        guard.rotate(phantom_token, new_value)
    }

    /// Remove a credential: zeroize the slot and remove from index.
    pub async fn remove(&self, phantom_token: &str) -> Result<(), SecureMemoryError> {
        let mut guard = self.store.write().await;
        guard.remove(phantom_token)
    }

    /// Scan a byte buffer for any stored credential values.
    ///
    /// Returns (phantom_token, byte_offset) pairs for each match.
    pub async fn scan_bytes(&self, haystack: &[u8]) -> Vec<(String, usize)> {
        let guard = self.store.read().await;
        guard.scan_bytes(haystack)
    }

    /// Number of credentials currently stored.
    pub async fn credential_count(&self) -> usize {
        let guard = self.store.read().await;
        guard.credential_count()
    }

    /// Check if a phantom token exists.
    pub async fn contains(&self, phantom_token: &str) -> bool {
        let guard = self.store.read().await;
        guard.contains(phantom_token)
    }
}

/// A zero-copy reference to credential bytes in the secure region.
///
/// Holds an `OwnedRwLockReadGuard` to keep the lock alive while the caller
/// accesses the credential. Does NOT implement `Clone` or `Copy` —
/// credential bytes cannot be duplicated.
pub struct SecureRef {
    _guard: OwnedRwLockReadGuard<SecureCredentialStore>,
    offset: usize,
    len: usize,
}

impl Deref for SecureRef {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: The guard keeps the SecureCredentialStore (and its SecureRegion)
        // alive. The offset/len were validated when the SecureRef was created.
        self._guard.region.read(self.offset, self.len)
    }
}

impl std::fmt::Debug for SecureRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED credential ref]")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_region_alloc_dealloc() {
        let region = SecureRegion::new(4096, false).unwrap();
        assert!(region.usable_size() >= 4096);
        // Drop should not panic
    }

    #[test]
    fn test_secure_region_write_read() {
        let region = SecureRegion::new(4096, false).unwrap();
        let data = b"secret-api-key-12345";
        region.write(0, data);
        let read_back = region.read(0, data.len());
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_secure_region_zeroize_slot() {
        let region = SecureRegion::new(4096, false).unwrap();
        let data = b"sensitive-credential";
        region.write(0, data);

        // Verify data is there
        assert_eq!(region.read(0, data.len()), data);

        // Zeroize
        region.zeroize_slot(0, data.len());

        // Verify zeroed
        let zeroed = region.read(0, data.len());
        assert!(zeroed.iter().all(|&b| b == 0), "slot should be zeroed");
    }

    #[test]
    fn test_secure_region_multiple_offsets() {
        let region = SecureRegion::new(4096, false).unwrap();
        let data1 = b"credential-one";
        let data2 = b"credential-two";

        region.write(0, data1);
        region.write(256, data2);

        assert_eq!(region.read(0, data1.len()), data1);
        assert_eq!(region.read(256, data2.len()), data2);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_secure_region_write_out_of_bounds() {
        let region = SecureRegion::new(64, false).unwrap();
        // usable_size is at least one page (4096), so write beyond that
        let data = vec![0u8; region.usable_size() + 1];
        region.write(0, &data);
    }

    #[test]
    fn test_credential_store_basic() {
        let mut store = SecureCredentialStore::new(16, 4096, false).unwrap();

        store.store("pt_test_abc123", b"real-api-key").unwrap();
        assert_eq!(store.credential_count(), 1);

        let resolved = store.resolve("pt_test_abc123").unwrap();
        assert_eq!(resolved, b"real-api-key");

        assert!(store.resolve("pt_nonexistent").is_none());
    }

    #[test]
    fn test_credential_store_rotate() {
        let mut store = SecureCredentialStore::new(16, 4096, false).unwrap();
        store.store("pt_test_key1", b"old-secret").unwrap();

        store.rotate("pt_test_key1", b"new-secret-value").unwrap();

        let resolved = store.resolve("pt_test_key1").unwrap();
        assert_eq!(resolved, b"new-secret-value");
    }

    #[test]
    fn test_credential_store_remove() {
        let mut store = SecureCredentialStore::new(16, 4096, false).unwrap();
        store.store("pt_test_remove", b"to-be-removed").unwrap();
        assert_eq!(store.credential_count(), 1);

        store.remove("pt_test_remove").unwrap();
        assert_eq!(store.credential_count(), 0);
        assert!(store.resolve("pt_test_remove").is_none());
    }

    #[test]
    fn test_credential_store_scan_bytes() {
        let mut store = SecureCredentialStore::new(16, 4096, false).unwrap();
        store.store("pt_token_a", b"secret-A").unwrap();
        store.store("pt_token_b", b"secret-B").unwrap();

        let body = b"The response contains secret-A in the body text";
        let matches = store.scan_bytes(body);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "pt_token_a");

        let no_match = b"nothing sensitive here";
        assert!(store.scan_bytes(no_match).is_empty());
    }

    #[test]
    fn test_credential_store_capacity_limit() {
        let mut store = SecureCredentialStore::new(2, 64, false).unwrap();
        store.store("pt_1", b"val1").unwrap();
        store.store("pt_2", b"val2").unwrap();

        let err = store.store("pt_3", b"val3").unwrap_err();
        assert!(matches!(err, SecureMemoryError::StoreFull { .. }));
    }

    #[test]
    fn test_credential_store_value_too_large() {
        let mut store = SecureCredentialStore::new(16, 32, false).unwrap();
        let big_value = vec![0u8; 33];

        let err = store.store("pt_big", &big_value).unwrap_err();
        assert!(matches!(err, SecureMemoryError::CredentialTooLarge { .. }));
    }

    #[test]
    fn test_credential_store_rotate_exceeds_capacity() {
        let mut store = SecureCredentialStore::new(16, 32, false).unwrap();
        store.store("pt_rot", b"short").unwrap();

        let big_value = vec![0u8; 33];
        let err = store.rotate("pt_rot", &big_value).unwrap_err();
        assert!(matches!(
            err,
            SecureMemoryError::RotateExceedsCapacity { .. }
        ));
    }

    #[test]
    fn test_credential_store_contains() {
        let mut store = SecureCredentialStore::new(16, 4096, false).unwrap();
        store.store("pt_exists", b"val").unwrap();

        assert!(store.contains("pt_exists"));
        assert!(!store.contains("pt_nope"));
    }

    // -----------------------------------------------------------------------
    // CredentialManager (async) tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_manager_store_and_resolve() {
        let mgr = CredentialManager::new(16, 4096, false).unwrap();
        mgr.store("pt_mgr_test", b"manager-secret").await.unwrap();

        let secret_ref = mgr.resolve("pt_mgr_test").await.unwrap();
        assert_eq!(&*secret_ref, b"manager-secret");
        assert_eq!(mgr.credential_count().await, 1);
    }

    #[tokio::test]
    async fn test_manager_resolve_missing() {
        let mgr = CredentialManager::new(16, 4096, false).unwrap();
        assert!(mgr.resolve("pt_nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_manager_rotate() {
        let mgr = CredentialManager::new(16, 4096, false).unwrap();
        mgr.store("pt_rot", b"old-value").await.unwrap();

        mgr.rotate("pt_rot", b"new-value-here").await.unwrap();

        let secret_ref = mgr.resolve("pt_rot").await.unwrap();
        assert_eq!(&*secret_ref, b"new-value-here");
    }

    #[tokio::test]
    async fn test_manager_remove() {
        let mgr = CredentialManager::new(16, 4096, false).unwrap();
        mgr.store("pt_rm", b"removable").await.unwrap();
        assert!(mgr.contains("pt_rm").await);

        mgr.remove("pt_rm").await.unwrap();
        assert!(!mgr.contains("pt_rm").await);
        assert_eq!(mgr.credential_count().await, 0);
    }

    #[tokio::test]
    async fn test_manager_scan_bytes() {
        let mgr = CredentialManager::new(16, 4096, false).unwrap();
        mgr.store("pt_scan", b"leak-me").await.unwrap();

        let body = b"response body contains leak-me somewhere";
        let matches = mgr.scan_bytes(body).await;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "pt_scan");
    }

    #[tokio::test]
    async fn test_manager_concurrent_reads() {
        let mgr = Arc::new(CredentialManager::new(16, 4096, false).unwrap());
        mgr.store("pt_concurrent", b"shared-secret").await.unwrap();

        let mut handles = vec![];
        for _ in 0..10 {
            let m = mgr.clone();
            handles.push(tokio::spawn(async move {
                let r = m.resolve("pt_concurrent").await.unwrap();
                assert_eq!(&*r, b"shared-secret");
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_secure_ref_debug_redacted() {
        let mgr = CredentialManager::new(16, 4096, false).unwrap();
        mgr.store("pt_debug", b"super-secret").await.unwrap();

        let r = mgr.resolve("pt_debug").await.unwrap();
        let debug_str = format!("{:?}", r);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("super-secret"));
    }

    // §4.2: Cross-branch isolation — Branch A's phantom token cannot resolve
    // through Branch B's CredentialManager.
    #[tokio::test]
    async fn test_cross_branch_isolation() {
        let mgr_a = CredentialManager::new(16, 4096, false).unwrap();
        let mgr_b = CredentialManager::new(16, 4096, false).unwrap();

        mgr_a.store("pt_branch_a_token", b"secret-A").await.unwrap();
        mgr_b.store("pt_branch_b_token", b"secret-B").await.unwrap();

        // Branch A's token should not resolve in Branch B's manager
        let result = mgr_b.resolve("pt_branch_a_token").await;
        assert!(
            result.is_none(),
            "§4.2: Branch A's phantom token must NOT resolve through Branch B's manager"
        );

        // Branch B's token should not resolve in Branch A's manager
        let result = mgr_a.resolve("pt_branch_b_token").await;
        assert!(
            result.is_none(),
            "§4.2: Branch B's phantom token must NOT resolve through Branch A's manager"
        );

        // Each manager should resolve its own tokens
        let a = mgr_a.resolve("pt_branch_a_token").await.unwrap();
        assert_eq!(&*a, b"secret-A");
        let b = mgr_b.resolve("pt_branch_b_token").await.unwrap();
        assert_eq!(&*b, b"secret-B");
    }

    // §4.3: Concurrent rotate + resolve race condition test
    #[tokio::test]
    async fn test_concurrent_rotate_and_resolve() {
        let mgr = std::sync::Arc::new(CredentialManager::new(16, 4096, false).unwrap());
        mgr.store("pt_race", b"initial-value").await.unwrap();

        let mgr_reader = mgr.clone();
        let mgr_writer = mgr.clone();

        // Spawn concurrent readers and a writer
        let reader_handle = tokio::spawn(async move {
            for _ in 0..50 {
                let r = mgr_reader.resolve("pt_race").await.unwrap();
                let val = std::str::from_utf8(&r).unwrap().to_string();
                // Value must be either "initial-value" or "rotated-value" — never corrupt
                assert!(
                    val == "initial-value" || val == "rotated-value",
                    "§4.3: concurrent read during rotate must see consistent value, got: {}",
                    val
                );
                tokio::task::yield_now().await;
            }
        });

        let writer_handle = tokio::spawn(async move {
            for _ in 0..10 {
                mgr_writer
                    .rotate("pt_race", b"rotated-value")
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            }
        });

        reader_handle.await.unwrap();
        writer_handle.await.unwrap();

        // After all rotations, value should be "rotated-value"
        let final_val = mgr.resolve("pt_race").await.unwrap();
        assert_eq!(&*final_val, b"rotated-value");
    }

    // §4.2: mlock enforcement — when mlock_required=true and mlock fails,
    // SecureRegion creation should fail.
    #[test]
    fn test_mlock_required_enforced() {
        // With mlock_required=false, creation should succeed even if mlock fails
        let region = SecureRegion::new(4096, false);
        assert!(
            region.is_ok(),
            "SecureRegion with mlock_required=false should succeed"
        );

        // With mlock_required=true, creation should succeed on systems with
        // sufficient RLIMIT_MEMLOCK (the test environment should have this).
        let region = SecureRegion::new(4096, true);
        // We can't force mlock to fail without RLIMIT manipulation (requires root),
        // so we just verify the flag is respected and creation succeeds.
        assert!(
            region.is_ok(),
            "SecureRegion with mlock_required=true should succeed with sufficient RLIMIT_MEMLOCK"
        );
    }

    // Edge case: maximum credential size boundary
    #[tokio::test]
    async fn test_max_credential_size_boundary() {
        let slot_capacity = 128;
        let mgr = CredentialManager::new(4, slot_capacity, false).unwrap();

        // Exactly slot_capacity bytes should succeed
        let exact = vec![b'A'; slot_capacity];
        let result = mgr.store("pt_exact", &exact).await;
        assert!(
            result.is_ok(),
            "credential of exactly slot_capacity should fit"
        );

        // One byte over should fail
        let over = vec![b'B'; slot_capacity + 1];
        let result = mgr.store("pt_over", &over).await;
        assert!(
            result.is_err(),
            "credential exceeding slot_capacity should fail"
        );
    }
}
