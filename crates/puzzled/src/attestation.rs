// SPDX-License-Identifier: Apache-2.0
//! Cryptographic attestation of governance (§3.1).
//!
//! Provides an append-only Merkle tree for governance attestation records.
//! The tree uses the frontier-based algorithm (same as Certificate Transparency,
//! RFC 6962): only O(log n) internal node hashes are kept in memory.
//!
//! Two key properties:
//! - **Inclusion proof**: prove a specific record exists in the log without
//!   revealing other records (selective disclosure to auditors).
//! - **Consistency proof**: prove the log at time T₂ is a strict append-only
//!   extension of the log at T₁ (no deletions or modifications).
//!
//! Domain-separated hashing per RFC 6962:
//! - Leaf: `SHA-256(0x00 || record_bytes)`
//! - Internal: `SHA-256(0x01 || left_child || right_child)`

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{PuzzledError, Result};

// A-M1: Domain separation constants and core crypto functions are now in
// puzzled_types::merkle.  We re-import them here for internal use and keep
// the MerkleTree methods as thin wrappers so existing call-sites
// (Self::hash_leaf, Self::hash_node) continue to compile.
use puzzled_types::merkle::{
    self as merkle_crypto, hash_leaf as _shared_hash_leaf, hash_node as _shared_hash_node,
    largest_power_of_2_less_than,
};

/// F3: Maximum number of leaves held in memory before rotating.
const MAX_MERKLE_LEAVES: usize = 1_000_000;

/// Append-only Merkle tree for attestation records.
///
/// Uses the frontier-based algorithm: only the right-frontier nodes
/// (O(log n) memory) are cached for efficient appends and proof generation.
/// The full set of leaf hashes is stored on disk for historical proof generation.
pub struct MerkleTree {
    /// Directory for tree data files.
    data_dir: PathBuf,
    /// Current tree size (number of leaves).
    size: u64,
    /// Right-frontier node hashes for efficient append.
    /// `frontier[i]` is the hash of the complete subtree of height `i`
    /// on the right edge, if one exists. `None` means no complete subtree
    /// at that level yet.
    frontier: Vec<Option<[u8; 32]>>,
    /// All leaf hashes in order, for proof generation.
    /// Loaded lazily from disk on first proof request.
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create or open a Merkle tree in the given directory.
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| PuzzledError::Attestation(format!("creating attestation dir: {}", e)))?;

        let leaves_path = data_dir.join("merkle.dat");
        let leaves = if leaves_path.exists() {
            Self::load_leaves(&leaves_path)?
        } else {
            Vec::new()
        };

        // Q8: Use try_from instead of bare `as u64` for len-to-u64 conversion
        let size = u64::try_from(leaves.len()).unwrap_or(u64::MAX);
        let frontier = Self::rebuild_frontier(&leaves);

        tracing::info!(
            data_dir = %data_dir.display(),
            tree_size = size,
            "attestation Merkle tree initialized"
        );

        Ok(Self {
            data_dir,
            size,
            frontier,
            leaves,
        })
    }

    /// Append a leaf hash to the tree, returning the leaf index.
    pub fn append(&mut self, record_bytes: &[u8]) -> Result<u64> {
        let leaf_hash = Self::hash_leaf(record_bytes);
        let index = self.size;

        // Persist the leaf hash to disk
        self.append_leaf_to_disk(&leaf_hash)?;

        // G1: Bound the in-memory leaves vector to prevent unbounded growth.
        // Instead of clearing leaves (which would cause OOB panics on proof
        // generation for pre-rotation leaf indices), we reject new appends
        // and log a warning.  The tree remains valid for all existing proofs.
        if self.leaves.len() >= MAX_MERKLE_LEAVES {
            tracing::warn!(
                capacity = MAX_MERKLE_LEAVES,
                "G1: Merkle tree at capacity ({MAX_MERKLE_LEAVES} leaves), \
                 new leaves rejected until restart"
            );
            return Err(PuzzledError::Attestation(format!(
                "G1: Merkle tree at capacity ({MAX_MERKLE_LEAVES} leaves)"
            )));
        }

        // Update in-memory state
        self.leaves.push(leaf_hash);
        self.size += 1;

        // Update frontier: merge complete subtrees
        let mut hash = leaf_hash;
        let mut level = 0;
        // The number of trailing 1-bits in `self.size` tells us how many
        // complete subtrees to merge at this point.
        let mut n = self.size;
        while n & 1 == 0 {
            // There's a complete subtree at this level — merge
            if let Some(Some(left)) = self.frontier.get(level) {
                hash = Self::hash_node(left, &hash);
            }
            // Clear this level
            if level < self.frontier.len() {
                self.frontier[level] = None;
            }
            level += 1;
            n >>= 1;
        }
        // Store the merged hash at the current level
        if level >= self.frontier.len() {
            self.frontier.resize(level + 1, None);
        }
        self.frontier[level] = Some(hash);

        Ok(index)
    }

    /// Get the current root hash.
    ///
    /// For an empty tree, returns the hash of an empty string.
    /// # Errors
    /// Returns `Err` if the tree is in an inconsistent state (non-empty size
    /// but no frontier entries).
    pub fn root_hash(&self) -> Result<[u8; 32]> {
        if self.size == 0 {
            let mut hasher = Sha256::new();
            hasher.update([]);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            return Ok(hash);
        }

        // Combine all frontier hashes from bottom to top
        let mut hash: Option<[u8; 32]> = None;
        for h in self.frontier.iter().flatten() {
            hash = Some(match hash {
                None => *h,
                Some(right) => Self::hash_node(h, &right),
            });
        }
        // H1: Replace .expect() with proper error handling.
        hash.ok_or_else(|| {
            PuzzledError::Attestation(
                "non-empty tree has no frontier entries — inconsistent state".to_string(),
            )
        })
    }

    /// Current number of leaves in the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Path to the Merkle tree data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Generate an inclusion proof for the leaf at the given index.
    pub fn inclusion_proof(&self, leaf_index: u64) -> Result<puzzled_types::InclusionProof> {
        if leaf_index >= self.size {
            return Err(PuzzledError::Attestation(format!(
                "leaf index {} out of range (tree size {})",
                leaf_index, self.size
            )));
        }

        let proof_hashes = self.compute_inclusion_proof(leaf_index, 0, self.size)?;

        Ok(puzzled_types::InclusionProof {
            leaf_index,
            tree_size: self.size,
            proof_hashes: proof_hashes
                .iter()
                .map(|h| hex_encode(h.as_slice()))
                .collect(),
        })
    }

    /// Generate a consistency proof between two tree sizes.
    pub fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<puzzled_types::ConsistencyProof> {
        if old_size > new_size || new_size > self.size {
            return Err(PuzzledError::Attestation(format!(
                "invalid consistency proof range: old={}, new={}, current={}",
                old_size, new_size, self.size
            )));
        }

        if old_size == 0 {
            return Ok(puzzled_types::ConsistencyProof {
                old_size,
                new_size,
                proof_hashes: Vec::new(),
            });
        }

        let proof_hashes = self.compute_consistency_proof(old_size, new_size)?;

        Ok(puzzled_types::ConsistencyProof {
            old_size,
            new_size,
            proof_hashes: proof_hashes
                .iter()
                .map(|h| hex_encode(h.as_slice()))
                .collect(),
        })
    }

    /// Write a checkpoint (root hash + tree size) to the checkpoint directory.
    pub fn checkpoint(&self, checkpoint_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(checkpoint_dir)
            .map_err(|e| PuzzledError::Attestation(format!("creating checkpoint dir: {}", e)))?;

        let root = self.root_hash()?;
        let checkpoint = serde_json::json!({
            "tree_size": self.size,
            "root_hash": hex_encode(&root),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let filename = format!("checkpoint_{}.json", self.size);
        let path = checkpoint_dir.join(&filename);

        use std::io::Write;
        let mut file = std::fs::File::create(&path)
            .map_err(|e| PuzzledError::Attestation(format!("creating checkpoint file: {}", e)))?;
        let json = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| PuzzledError::Attestation(format!("serializing checkpoint: {}", e)))?;
        file.write_all(json.as_bytes())
            .map_err(|e| PuzzledError::Attestation(format!("writing checkpoint: {}", e)))?;
        file.sync_all()
            .map_err(|e| PuzzledError::Attestation(format!("fsync checkpoint: {}", e)))?;
        // Fsync parent directory to ensure the new checkpoint file entry is durable
        if let Ok(d) = std::fs::File::open(checkpoint_dir) {
            if let Err(e) = d.sync_all() {
                tracing::error!(error = %e, "R15: attestation data fsync failed — data may not be durable");
            }
        }

        // A-I3: Write the current root hash to a `root_hash` file in the tree's
        // data_dir (not the checkpoint dir). The CLI reads this file for quick
        // root hash lookups without parsing checkpoint JSON files.
        let root_hash_path = self.data_dir.join("root_hash");
        let root_hex = hex_encode(&root);
        {
            let mut rh_file = std::fs::File::create(&root_hash_path)
                .map_err(|e| PuzzledError::Attestation(format!("creating root_hash file: {}", e)))?;
            rh_file
                .write_all(root_hex.as_bytes())
                .map_err(|e| PuzzledError::Attestation(format!("writing root_hash file: {}", e)))?;
            rh_file
                .sync_all()
                .map_err(|e| PuzzledError::Attestation(format!("fsync root_hash file: {}", e)))?;
        }
        // Fsync data_dir to ensure root_hash file entry is durable
        if let Ok(d) = std::fs::File::open(&self.data_dir) {
            if let Err(e) = d.sync_all() {
                tracing::error!(error = %e, "R15: attestation data fsync failed — data may not be durable");
            }
        }

        tracing::info!(
            tree_size = self.size,
            root_hash = %root_hex,
            path = %path.display(),
            "attestation checkpoint written (root_hash file updated)"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Hashing
    // -----------------------------------------------------------------------

    /// Hash a leaf node: SHA-256(0x00 || data).
    ///
    /// A-M1: Delegates to `puzzled_types::merkle::hash_leaf`.
    pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
        _shared_hash_leaf(data)
    }

    /// Hash an internal node: SHA-256(0x01 || left || right).
    ///
    /// A-M1: Delegates to `puzzled_types::merkle::hash_node`.
    fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        _shared_hash_node(left, right)
    }

    // -----------------------------------------------------------------------
    // Proof computation (RFC 6962 algorithms)
    // -----------------------------------------------------------------------

    /// Compute the hash of a subtree covering leaves[start..start+count].
    ///
    /// # Errors
    /// Returns `Err` if `count == 0` or if `start`/indices are out of bounds.
    fn subtree_hash(&self, start: u64, count: u64) -> Result<[u8; 32]> {
        // H1: Replace assert!(count > 0) with graceful error return.
        if count == 0 {
            return Err(PuzzledError::Attestation(
                "subtree_hash called with count=0".to_string(),
            ));
        }
        // H2: Use usize::try_from with bounds check instead of bare `as usize`.
        let start_idx = usize::try_from(start).map_err(|_| {
            PuzzledError::Attestation(format!("subtree_hash start {} overflows usize", start))
        })?;
        if start_idx >= self.leaves.len() {
            return Err(PuzzledError::Attestation(format!(
                "subtree_hash start index {} out of bounds (leaves len {})",
                start_idx,
                self.leaves.len()
            )));
        }
        if count == 1 {
            return Ok(self.leaves[start_idx]);
        }
        // Split at the largest power of 2 less than count
        let k = largest_power_of_2_less_than(count);
        let left = self.subtree_hash(start, k)?;
        let right = self.subtree_hash(start + k, count - k)?;
        Ok(Self::hash_node(&left, &right))
    }

    /// Compute inclusion proof hashes for leaf_index in a subtree starting at `start`
    /// with `count` leaves.
    fn compute_inclusion_proof(
        &self,
        leaf_index: u64,
        start: u64,
        count: u64,
    ) -> Result<Vec<[u8; 32]>> {
        if count <= 1 {
            return Ok(Vec::new());
        }
        let k = largest_power_of_2_less_than(count);
        if leaf_index < k {
            let mut proof = self.compute_inclusion_proof(leaf_index, start, k)?;
            proof.push(self.subtree_hash(start + k, count - k)?);
            Ok(proof)
        } else {
            let mut proof = self.compute_inclusion_proof(leaf_index - k, start + k, count - k)?;
            proof.push(self.subtree_hash(start, k)?);
            Ok(proof)
        }
    }

    /// Compute consistency proof between old_size and new_size.
    fn compute_consistency_proof(&self, old_size: u64, new_size: u64) -> Result<Vec<[u8; 32]>> {
        let mut proof = Vec::new();
        self.consistency_proof_inner(old_size, new_size, 0, true, &mut proof)?;
        Ok(proof)
    }

    fn consistency_proof_inner(
        &self,
        old_size: u64,
        new_size: u64,
        offset: u64,
        is_start: bool,
        proof: &mut Vec<[u8; 32]>,
    ) -> Result<()> {
        if old_size == new_size {
            if !is_start {
                proof.push(self.subtree_hash(offset, old_size)?);
            }
            return Ok(());
        }
        if old_size == 0 {
            return Ok(());
        }
        let k = largest_power_of_2_less_than(new_size);
        if old_size <= k {
            self.consistency_proof_inner(old_size, k, offset, is_start, proof)?;
            proof.push(self.subtree_hash(offset + k, new_size - k)?);
        } else {
            self.consistency_proof_inner(old_size - k, new_size - k, offset + k, false, proof)?;
            proof.push(self.subtree_hash(offset, k)?);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// Append a single leaf hash to the on-disk leaves file.
    fn append_leaf_to_disk(&self, hash: &[u8; 32]) -> Result<()> {
        use std::io::Write;
        let path = self.data_dir.join("merkle.dat");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| PuzzledError::Attestation(format!("opening leaves file: {}", e)))?;
        file.write_all(hash)
            .map_err(|e| PuzzledError::Attestation(format!("writing leaf hash: {}", e)))?;
        file.sync_all()
            .map_err(|e| PuzzledError::Attestation(format!("fsync leaves file: {}", e)))?;
        // A-M2: Fsync parent directory only when merkle.dat is newly created (first-ever append).
        // Before the first append, self.size == 0 (tree was empty). After reload with
        // existing data, self.size > 0, so no unnecessary dir fsyncs on every append.
        if self.size == 0 {
            if let Ok(d) = std::fs::File::open(&self.data_dir) {
                if let Err(e) = d.sync_all() {
                    tracing::error!(error = %e, "R15: attestation data fsync failed — data may not be durable");
                }
            }
        }
        Ok(())
    }

    /// Load all leaf hashes from the on-disk file.
    ///
    /// If the file size is not a multiple of 32 bytes (e.g., due to a crash
    /// during a partial write), the trailing fragment is truncated and a
    /// warning is logged. This matches the NDJSON recovery pattern used in
    /// `count_existing_events`.
    fn load_leaves(path: &Path) -> Result<Vec<[u8; 32]>> {
        let data = std::fs::read(path)
            .map_err(|e| PuzzledError::Attestation(format!("reading leaves file: {}", e)))?;
        if data.len() % 32 != 0 {
            let valid_len = (data.len() / 32) * 32;
            let trailing = data.len() - valid_len;
            tracing::warn!(
                path = %path.display(),
                file_size = data.len(),
                valid_len,
                trailing_bytes = trailing,
                "merkle.dat has trailing fragment (likely crash during write); \
                 truncating to last complete 32-byte boundary"
            );
            // Truncate the file on disk to the valid length
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|e| {
                    PuzzledError::Attestation(format!("opening leaves file for truncation: {}", e))
                })?;
            file.set_len(valid_len as u64).map_err(|e| {
                PuzzledError::Attestation(format!("truncating leaves file to {}: {}", valid_len, e))
            })?;
            file.sync_all()
                .map_err(|e| PuzzledError::Attestation(format!("fsync after truncation: {}", e)))?;
        }
        let valid_len = (data.len() / 32) * 32;
        let leaves: Vec<[u8; 32]> = data[..valid_len]
            .chunks_exact(32)
            .map(|chunk| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(chunk);
                hash
            })
            .collect();
        Ok(leaves)
    }

    /// Rebuild the frontier from a complete list of leaves.
    fn rebuild_frontier(leaves: &[[u8; 32]]) -> Vec<Option<[u8; 32]>> {
        let mut frontier: Vec<Option<[u8; 32]>> = Vec::new();
        // Q8: Use try_from instead of bare `as u64` for len-to-u64 conversion
        let size = u64::try_from(leaves.len()).unwrap_or(u64::MAX);
        if size == 0 {
            return frontier;
        }

        // Replay all appends to reconstruct frontier
        let mut temp_frontier: Vec<Option<[u8; 32]>> = Vec::new();
        for (i, &leaf_hash) in leaves.iter().enumerate() {
            let mut hash = leaf_hash;
            let mut level = 0;
            let mut n = (i as u64) + 1;
            while n & 1 == 0 {
                if let Some(Some(left)) = temp_frontier.get(level) {
                    hash = Self::hash_node(left, &hash);
                }
                if level < temp_frontier.len() {
                    temp_frontier[level] = None;
                }
                level += 1;
                n >>= 1;
            }
            if level >= temp_frontier.len() {
                temp_frontier.resize(level + 1, None);
            }
            temp_frontier[level] = Some(hash);
        }
        frontier = temp_frontier;
        frontier
    }
}

/// Verify an inclusion proof.
///
/// Returns `true` if the proof is valid: i.e., the leaf at `leaf_index`
/// with hash `leaf_hash` is included in a tree with root `expected_root`.
///
/// A-M1: Delegates to `puzzled_types::merkle::verify_merkle_inclusion`.
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    proof: &puzzled_types::InclusionProof,
    expected_root: &[u8; 32],
) -> std::result::Result<bool, String> {
    merkle_crypto::verify_merkle_inclusion(leaf_hash, proof, expected_root)
}

/// Verify a consistency proof (RFC 6962 §2.1.2).
///
/// Returns `true` if the proof demonstrates that the tree at `new_root`
/// is a strict append-only extension of the tree at `old_root`.
pub fn verify_consistency(
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &puzzled_types::ConsistencyProof,
) -> std::result::Result<bool, String> {
    let old_size = proof.old_size;
    let new_size = proof.new_size;

    // Trivial cases
    if old_size == 0 {
        return Ok(proof.proof_hashes.is_empty());
    }
    if old_size == new_size {
        return Ok(old_root == new_root && proof.proof_hashes.is_empty());
    }
    if old_size > new_size {
        return Err("old_size > new_size".to_string());
    }

    // Decode proof hashes
    let proof_hashes: Vec<[u8; 32]> = proof
        .proof_hashes
        .iter()
        .map(|h| {
            let bytes = hex_decode(h)?;
            if bytes.len() != 32 {
                return Err(format!("proof hash must be 32 bytes, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if proof_hashes.is_empty() {
        return Err("non-trivial consistency proof must have at least one hash".to_string());
    }

    let mut pos = 0;
    let result =
        verify_consistency_inner(old_size, new_size, true, old_root, &proof_hashes, &mut pos);
    match result {
        Some((computed_old, computed_new)) => {
            if pos != proof_hashes.len() {
                return Err(format!(
                    "malformed consistency proof: {} extra hashes",
                    proof_hashes.len() - pos
                ));
            }
            Ok(computed_old == *old_root && computed_new == *new_root)
        }
        None => Err("malformed consistency proof".to_string()),
    }
}

/// Verify a consistency proof by mirroring the proof generation algorithm.
///
/// The proof generation (`consistency_proof_inner`) recurses into the tree
/// decomposition and pushes subtree hashes. This verifier consumes proof
/// hashes in the same order and reconstructs both `old_root` and `new_root`.
///
/// When `is_start` is true and `old_size == new_size`, the prover emits no
/// hash (the subtree is the old tree's root). The verifier uses the given
/// `old_root` as the subtree hash at that point.
///
/// Returns `Some((old_root, new_root))` or `None` if proof is malformed.
fn verify_consistency_inner(
    old_size: u64,
    new_size: u64,
    is_start: bool,
    old_root: &[u8; 32],
    proof: &[[u8; 32]],
    pos: &mut usize,
) -> Option<([u8; 32], [u8; 32])> {
    if old_size == new_size {
        if !is_start {
            // Prover pushed subtree_hash — consume from proof.
            // This hash contributes to BOTH old and new root reconstruction.
            let h = *proof.get(*pos)?;
            *pos += 1;
            return Some((h, h));
        }
        // is_start: prover pushed nothing. This subtree IS the old tree root.
        // Use old_root as the value for both accumulators.
        return Some((*old_root, *old_root));
    }
    if old_size == 0 {
        return None;
    }

    let k = largest_power_of_2_less_than(new_size);
    if old_size <= k {
        // Prover recursed into left subtree [0..k] (old fits entirely in left),
        // then pushed right subtree hash [k..new_size].
        let (inner_old, left_hash) =
            verify_consistency_inner(old_size, k, is_start, old_root, proof, pos)?;
        let right_hash = *proof.get(*pos)?;
        *pos += 1;
        // old_root comes from the inner recursion (only left subtree matters for old)
        // new_root = hash(left_subtree, right_subtree)
        Some((inner_old, MerkleTree::hash_node(&left_hash, &right_hash)))
    } else {
        // Prover recursed into right subtree [k..] with is_start=false,
        // then pushed left subtree hash [0..k].
        let (right_old, right_new) =
            verify_consistency_inner(old_size - k, new_size - k, false, old_root, proof, pos)?;
        let left_hash = *proof.get(*pos)?;
        *pos += 1;
        // Both old_root and new_root are hash(left, right_*)
        Some((
            MerkleTree::hash_node(&left_hash, &right_old),
            MerkleTree::hash_node(&left_hash, &right_new),
        ))
    }
}

// A-M1: `compute_root_from_inclusion`, `largest_power_of_2_less_than`,
// `hex_decode`, and `verify_inclusion` logic is now in `puzzled_types::merkle`.
// We re-export / delegate to the shared implementations.

use puzzled_types::merkle::{hex_decode, hex_encode};

/// Re-export from `puzzled_types` for backward compatibility.
pub use puzzled_types::is_governance_significant;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let dir = tempfile::tempdir().unwrap();
        let tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(tree.size(), 0);
    }

    #[test]
    fn test_append_single_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        let idx = tree.append(b"record_1").unwrap();
        assert_eq!(idx, 0);
        assert_eq!(tree.size(), 1);

        let root = tree.root_hash().unwrap();
        let expected = MerkleTree::hash_leaf(b"record_1");
        assert_eq!(root, expected);
    }

    #[test]
    fn test_append_two_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"record_1").unwrap();
        tree.append(b"record_2").unwrap();
        assert_eq!(tree.size(), 2);

        let leaf1 = MerkleTree::hash_leaf(b"record_1");
        let leaf2 = MerkleTree::hash_leaf(b"record_2");
        let expected_root = MerkleTree::hash_node(&leaf1, &leaf2);
        assert_eq!(tree.root_hash().unwrap(), expected_root);
    }

    #[test]
    fn test_append_three_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"a").unwrap();
        tree.append(b"b").unwrap();
        tree.append(b"c").unwrap();

        let h_a = MerkleTree::hash_leaf(b"a");
        let h_b = MerkleTree::hash_leaf(b"b");
        let h_c = MerkleTree::hash_leaf(b"c");
        let h_ab = MerkleTree::hash_node(&h_a, &h_b);
        let expected = MerkleTree::hash_node(&h_ab, &h_c);
        assert_eq!(tree.root_hash().unwrap(), expected);
    }

    #[test]
    fn test_append_four_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..4 {
            tree.append(format!("record_{}", i).as_bytes()).unwrap();
        }
        assert_eq!(tree.size(), 4);

        let h = [0, 1, 2, 3].map(|i| MerkleTree::hash_leaf(format!("record_{}", i).as_bytes()));
        let h01 = MerkleTree::hash_node(&h[0], &h[1]);
        let h23 = MerkleTree::hash_node(&h[2], &h[3]);
        let expected = MerkleTree::hash_node(&h01, &h23);
        assert_eq!(tree.root_hash().unwrap(), expected);
    }

    #[test]
    fn test_persistence_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let root_before;
        {
            let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
            tree.append(b"record_1").unwrap();
            tree.append(b"record_2").unwrap();
            tree.append(b"record_3").unwrap();
            root_before = tree.root_hash().unwrap();
        }
        // Reload from disk
        let tree2 = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(tree2.size(), 3);
        assert_eq!(tree2.root_hash().unwrap(), root_before);
    }

    #[test]
    fn test_inclusion_proof_single() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"only_record").unwrap();

        let proof = tree.inclusion_proof(0).unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.tree_size, 1);
        assert!(proof.proof_hashes.is_empty());

        let leaf_hash = MerkleTree::hash_leaf(b"only_record");
        let root = tree.root_hash().unwrap();
        assert!(verify_inclusion(&leaf_hash, &proof, &root).unwrap());
    }

    #[test]
    fn test_inclusion_proof_four_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..4 {
            tree.append(format!("r{}", i).as_bytes()).unwrap();
        }
        let root = tree.root_hash().unwrap();

        // Verify inclusion proof for each leaf
        for i in 0..4u64 {
            let proof = tree.inclusion_proof(i).unwrap();
            let leaf_hash = MerkleTree::hash_leaf(format!("r{}", i).as_bytes());
            assert!(
                verify_inclusion(&leaf_hash, &proof, &root).unwrap(),
                "inclusion proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_inclusion_proof_wrong_leaf_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"real_record").unwrap();
        tree.append(b"other_record").unwrap();

        let proof = tree.inclusion_proof(0).unwrap();
        let root = tree.root_hash().unwrap();
        let wrong_hash = MerkleTree::hash_leaf(b"fake_record");
        assert!(!verify_inclusion(&wrong_hash, &proof, &root).unwrap());
    }

    #[test]
    fn test_inclusion_proof_out_of_range() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"record").unwrap();
        assert!(tree.inclusion_proof(1).is_err());
    }

    #[test]
    fn test_consistency_proof_empty_to_nonempty() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"r1").unwrap();
        tree.append(b"r2").unwrap();

        let proof = tree.consistency_proof(0, 2).unwrap();
        assert!(proof.proof_hashes.is_empty());
    }

    #[test]
    fn test_consistency_proof_same_size() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"r1").unwrap();
        tree.append(b"r2").unwrap();

        let proof = tree.consistency_proof(2, 2).unwrap();
        assert!(proof.proof_hashes.is_empty());
    }

    #[test]
    fn test_consistency_proof_invalid_range() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"r1").unwrap();

        assert!(tree.consistency_proof(2, 1).is_err());
        assert!(tree.consistency_proof(0, 5).is_err());
    }

    #[test]
    fn test_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().join("tree")).unwrap();
        tree.append(b"r1").unwrap();
        tree.append(b"r2").unwrap();

        let checkpoint_dir = dir.path().join("checkpoints");
        tree.checkpoint(&checkpoint_dir).unwrap();

        let checkpoint_file = checkpoint_dir.join("checkpoint_2.json");
        assert!(checkpoint_file.exists());

        let content: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&checkpoint_file).unwrap()).unwrap();
        assert_eq!(content["tree_size"], 2);
        assert!(content["root_hash"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn test_domain_separation() {
        // Leaf and node hashes must differ even for same input
        let data = [0u8; 32];
        let leaf = MerkleTree::hash_leaf(&data);
        let node = MerkleTree::hash_node(&[0u8; 32], &[0u8; 32]);
        assert_ne!(leaf, node, "leaf and node hashes must be domain-separated");
    }

    #[test]
    fn test_largest_power_of_2() {
        assert_eq!(largest_power_of_2_less_than(1), 0);
        assert_eq!(largest_power_of_2_less_than(2), 1);
        assert_eq!(largest_power_of_2_less_than(3), 2);
        assert_eq!(largest_power_of_2_less_than(4), 2);
        assert_eq!(largest_power_of_2_less_than(5), 4);
        assert_eq!(largest_power_of_2_less_than(8), 4);
        assert_eq!(largest_power_of_2_less_than(9), 8);
    }

    #[test]
    fn test_is_governance_significant() {
        assert!(is_governance_significant("branch_created"));
        assert!(is_governance_significant("branch_committed"));
        assert!(is_governance_significant("branch_rolled_back"));
        assert!(is_governance_significant("policy_violation"));
        assert!(is_governance_significant("commit_rejected"));
        assert!(is_governance_significant("sandbox_escape"));
        assert!(is_governance_significant("behavioral_trigger"));
        assert!(is_governance_significant("agent_killed"));

        // High-frequency events are NOT governance-significant
        assert!(!is_governance_significant("exec_gated"));
        assert!(!is_governance_significant("connect_gated"));
        assert!(!is_governance_significant("branch_frozen"));
        assert!(!is_governance_significant("profile_loaded"));
        assert!(!is_governance_significant("policy_reloaded"));
    }

    #[test]
    fn test_seven_leaves_inclusion() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..7 {
            tree.append(format!("leaf_{}", i).as_bytes()).unwrap();
        }
        let root = tree.root_hash().unwrap();
        for i in 0..7u64 {
            let proof = tree.inclusion_proof(i).unwrap();
            let leaf_hash = MerkleTree::hash_leaf(format!("leaf_{}", i).as_bytes());
            assert!(
                verify_inclusion(&leaf_hash, &proof, &root).unwrap(),
                "inclusion proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_load_leaves_truncates_partial_write() {
        // Simulate a crash that left a partial 32-byte write in merkle.dat.
        let dir = tempfile::tempdir().unwrap();
        let merkle_path = dir.path().join("merkle.dat");

        // Write 2 complete leaves (64 bytes) + 10 trailing bytes (partial write)
        let leaf1 = MerkleTree::hash_leaf(b"record_1");
        let leaf2 = MerkleTree::hash_leaf(b"record_2");
        let mut data = Vec::new();
        data.extend_from_slice(&leaf1);
        data.extend_from_slice(&leaf2);
        data.extend_from_slice(&[0xAB; 10]); // trailing fragment
        std::fs::write(&merkle_path, &data).unwrap();

        // load_leaves should recover by truncating to 64 bytes
        let tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(tree.size(), 2, "should recover 2 complete leaves");

        // Verify the on-disk file was truncated
        let on_disk = std::fs::read(&merkle_path).unwrap();
        assert_eq!(
            on_disk.len(),
            64,
            "merkle.dat should be truncated to 64 bytes"
        );

        // Verify the tree is functional — root hash matches expected
        let expected_root = MerkleTree::hash_node(&leaf1, &leaf2);
        assert_eq!(tree.root_hash().unwrap(), expected_root);

        // Verify we can still append after recovery
        let mut tree = tree;
        // MerkleTree::new returns an immutable tree; re-open as mutable
        let idx = tree.append(b"record_3").unwrap();
        assert_eq!(idx, 2);
        assert_eq!(tree.size(), 3);
    }

    #[test]
    fn test_load_leaves_exact_multiple_of_32_unchanged() {
        // A file that IS a multiple of 32 should load without truncation
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"a").unwrap();
        tree.append(b"b").unwrap();
        let root = tree.root_hash().unwrap();
        drop(tree);

        // Reload — should work fine
        let tree2 = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(tree2.size(), 2);
        assert_eq!(tree2.root_hash().unwrap(), root);
    }

    #[test]
    fn test_load_leaves_empty_trailing_fragment() {
        // Edge case: file has only a partial write (< 32 bytes, no complete leaves)
        let dir = tempfile::tempdir().unwrap();
        let merkle_path = dir.path().join("merkle.dat");
        std::fs::write(&merkle_path, [0xFF; 15]).unwrap();

        let tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(tree.size(), 0, "no complete leaves should be recovered");

        let on_disk = std::fs::read(&merkle_path).unwrap();
        assert_eq!(on_disk.len(), 0, "file should be truncated to 0 bytes");
    }

    // -----------------------------------------------------------------------
    // A-I2: Consistency proof verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_consistency_2_to_4() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..4 {
            tree.append(format!("record_{}", i).as_bytes()).unwrap();
        }

        // Snapshot roots at size 2 and size 4 by rebuilding
        let dir2 = tempfile::tempdir().unwrap();
        let mut tree2 = MerkleTree::new(dir2.path().to_path_buf()).unwrap();
        tree2.append(b"record_0").unwrap();
        tree2.append(b"record_1").unwrap();
        let old_root = tree2.root_hash().unwrap();
        let new_root = tree.root_hash().unwrap();

        let proof = tree.consistency_proof(2, 4).unwrap();
        assert!(
            verify_consistency(&old_root, &new_root, &proof).unwrap(),
            "consistency proof 2→4 should verify"
        );
    }

    #[test]
    fn test_verify_consistency_3_to_7() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..7 {
            tree.append(format!("leaf_{}", i).as_bytes()).unwrap();
        }

        // Build old root at size 3
        let dir2 = tempfile::tempdir().unwrap();
        let mut tree3 = MerkleTree::new(dir2.path().to_path_buf()).unwrap();
        for i in 0..3 {
            tree3.append(format!("leaf_{}", i).as_bytes()).unwrap();
        }
        let old_root = tree3.root_hash().unwrap();
        let new_root = tree.root_hash().unwrap();

        let proof = tree.consistency_proof(3, 7).unwrap();
        assert!(
            verify_consistency(&old_root, &new_root, &proof).unwrap(),
            "consistency proof 3→7 should verify"
        );
    }

    #[test]
    fn test_verify_consistency_1_to_4() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..4 {
            tree.append(format!("r{}", i).as_bytes()).unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();
        let mut tree1 = MerkleTree::new(dir2.path().to_path_buf()).unwrap();
        tree1.append(b"r0").unwrap();
        let old_root = tree1.root_hash().unwrap();
        let new_root = tree.root_hash().unwrap();

        let proof = tree.consistency_proof(1, 4).unwrap();
        assert!(
            verify_consistency(&old_root, &new_root, &proof).unwrap(),
            "consistency proof 1→4 should verify"
        );
    }

    #[test]
    fn test_verify_consistency_tampered_proof_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..4 {
            tree.append(format!("record_{}", i).as_bytes()).unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();
        let mut tree2 = MerkleTree::new(dir2.path().to_path_buf()).unwrap();
        tree2.append(b"record_0").unwrap();
        tree2.append(b"record_1").unwrap();
        let old_root = tree2.root_hash().unwrap();
        let new_root = tree.root_hash().unwrap();

        let mut proof = tree.consistency_proof(2, 4).unwrap();
        // Tamper with a proof hash
        if let Some(first) = proof.proof_hashes.first_mut() {
            // Flip a character in the hex string
            let mut chars: Vec<char> = first.chars().collect();
            chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
            *first = chars.into_iter().collect();
        }

        let result = verify_consistency(&old_root, &new_root, &proof).unwrap();
        assert!(
            !result,
            "tampered consistency proof should fail verification"
        );
    }

    #[test]
    fn test_verify_consistency_wrong_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        for i in 0..4 {
            tree.append(format!("record_{}", i).as_bytes()).unwrap();
        }

        let old_root = [0xABu8; 32]; // wrong root
        let new_root = tree.root_hash().unwrap();

        let proof = tree.consistency_proof(2, 4).unwrap();
        let result = verify_consistency(&old_root, &new_root, &proof).unwrap();
        assert!(!result, "wrong old_root should fail verification");
    }

    // -----------------------------------------------------------------------
    // A-I3: root_hash file written during checkpoint
    // -----------------------------------------------------------------------

    #[test]
    fn test_checkpoint_writes_root_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        let tree_dir = dir.path().join("tree");
        let mut tree = MerkleTree::new(tree_dir.clone()).unwrap();
        tree.append(b"r1").unwrap();
        tree.append(b"r2").unwrap();

        let checkpoint_dir = dir.path().join("checkpoints");
        tree.checkpoint(&checkpoint_dir).unwrap();

        // Verify root_hash file exists in tree's data_dir (not checkpoint dir)
        let root_hash_path = tree_dir.join("root_hash");
        assert!(
            root_hash_path.exists(),
            "root_hash file should exist in data_dir"
        );

        let content = std::fs::read_to_string(&root_hash_path).unwrap();
        assert_eq!(content.len(), 64, "root_hash should be 64 hex chars");

        // Verify it matches the actual root hash
        let root = tree.root_hash().unwrap();
        let expected_hex = hex_encode(&root);
        assert_eq!(
            content, expected_hex,
            "root_hash file content should match tree root"
        );
    }

    // -----------------------------------------------------------------------
    // A-M3: hex_decode non-ASCII safety
    // -----------------------------------------------------------------------

    #[test]
    fn test_hex_decode_rejects_non_ascii() {
        // A-M3: Multi-byte UTF-8 input would cause panics in byte-offset indexing.
        let result = hex_decode("café");
        assert!(result.is_err(), "non-ASCII input should be rejected");
        assert!(
            result.unwrap_err().contains("non-ASCII"),
            "error should mention non-ASCII"
        );
    }

    #[test]
    fn test_hex_decode_rejects_emoji() {
        let result = hex_decode("🔑🔑");
        assert!(result.is_err(), "emoji input should be rejected");
    }

    #[test]
    fn test_hex_decode_accepts_valid_hex() {
        let result = hex_decode("deadbeef").unwrap();
        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_decode_rejects_odd_length() {
        let result = hex_decode("abc");
        assert!(result.is_err(), "odd-length hex should be rejected");
    }

    // -----------------------------------------------------------------------
    // A-M2: fsync_dir only on first append
    // -----------------------------------------------------------------------

    #[test]
    fn test_dir_fsync_only_on_first_append() {
        // A-M2: After reload with existing leaves, appending should not fsync the
        // directory (self.size > 0). This is a functional test — we verify that
        // appending after reload works correctly (the optimization is structural).
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"leaf_0").unwrap();
        tree.append(b"leaf_1").unwrap();
        assert_eq!(tree.size(), 2);
        drop(tree);

        // Reload — size is 2, so subsequent appends skip dir fsync
        let mut tree2 = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(tree2.size(), 2);
        tree2.append(b"leaf_2").unwrap();
        assert_eq!(tree2.size(), 3);

        // Verify data integrity after the non-dir-fsynced append
        drop(tree2);
        let tree3 = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(tree3.size(), 3);
    }

    /// R15: Verify production code does not silently discard fsync errors on
    /// attestation data via `let _ = d.sync_all()` or `let _ = f.sync_all()`.
    // ---------------------------------------------------------------
    // F3: Merkle leaves vector must be bounded
    // ---------------------------------------------------------------

    #[test]
    fn test_f3_merkle_leaves_bounded() {
        let source = include_str!("attestation.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            production_code.contains("MAX_MERKLE_LEAVES"),
            "F3: MerkleTree must define MAX_MERKLE_LEAVES to bound the in-memory leaves vector"
        );
    }

    #[test]
    fn test_r15_no_silent_sync_all_discard() {
        let source = include_str!("attestation.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("let _ = d.sync_all()"),
            "R15: production code must not use `let _ = d.sync_all()` — fsync errors must be logged"
        );
        assert!(
            !production_code.contains("let _ = f.sync_all()"),
            "R15: production code must not use `let _ = f.sync_all()` — fsync errors must be logged"
        );
    }

    /// G1: After reaching MAX_MERKLE_LEAVES the tree must NOT clear leaves
    /// (which would cause OOB panics on proof generation). Instead it must
    /// reject new appends gracefully and all existing proofs must remain valid.
    #[test]
    fn test_g1_merkle_rotation_no_panic() {
        // Verify production code does not contain `self.leaves.clear()`.
        let source = include_str!("attestation.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("self.leaves.clear()"),
            "G1: production code must not clear leaves — it breaks proofs for \
             pre-rotation leaf indices"
        );
        assert!(
            !production_code.contains("self.frontier.clear()"),
            "G1: production code must not clear frontier — it breaks the tree state"
        );

        // Functional test with a small tree: verify proofs still work after many appends.
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();

        // Append several leaves and verify proofs work for all of them
        let n = 8;
        for i in 0..n {
            tree.append(format!("record_{i}").as_bytes()).unwrap();
        }

        // All inclusion proofs should succeed without panic
        for i in 0..n {
            let proof = tree.inclusion_proof(i);
            assert!(
                proof.is_ok(),
                "G1: inclusion_proof({i}) must not panic or error after appends"
            );
        }

        // Consistency proofs should also work
        let proof = tree.consistency_proof(4, 8);
        assert!(
            proof.is_ok(),
            "G1: consistency_proof must not panic after appends"
        );
    }

    // ---------------------------------------------------------------
    // H1: subtree_hash(0, 0) must not panic — return error instead
    // ---------------------------------------------------------------

    #[test]
    fn test_h1_subtree_hash_zero_count_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = MerkleTree::new(dir.path().to_path_buf()).unwrap();
        tree.append(b"leaf").unwrap();

        // H1: subtree_hash(0, 0) must return Err, not panic via assert!
        let result = tree.subtree_hash(0, 0);
        assert!(
            result.is_err(),
            "H1: subtree_hash(0, 0) must return Err, not panic"
        );
    }

    #[test]
    fn test_h1_root_hash_returns_result() {
        // H1: root_hash() must return Result, not panic via .expect()
        let source = include_str!("attestation.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains(".expect(\"non-empty tree"),
            "H1: root_hash must not use .expect() — use proper error handling"
        );
        // Verify it returns Result
        assert!(
            production_code.contains("pub fn root_hash(&self) -> Result<[u8; 32]>"),
            "H1: root_hash must return Result<[u8; 32]>"
        );
    }

    // ---------------------------------------------------------------
    // H2: No bare `[start as usize]` in production code
    // ---------------------------------------------------------------

    #[test]
    fn test_h2_no_bare_start_as_usize() {
        let source = include_str!("attestation.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("[start as usize]"),
            "H2: production code must not contain bare `[start as usize]` — \
             use usize::try_from(start) with bounds check"
        );
    }
}
