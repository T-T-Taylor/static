//! Fragmentation layer for large messages over Sphinx
//!
//! Sphinx bodies are fixed at 1024 bytes. Chunk data is 1 MiB.
//! This module fragments large payloads across multiple Sphinx
//! bodies and reassembles them at the destination.
//!
//! Each fragment contains:
//! - Fragment header (8 bytes): fragment_id (4) + total_fragments (4)
//! - Fragment data (up to BODY_SIZE - 8 bytes)
//!
//! Fragments are sent as separate Sphinx packets (or SURB-wrapped
//! packets for responses). Each is indistinguishable from cover
//! traffic. An adversary cannot tell that fragments belong together.

use static_sphinx::BODY_SIZE;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Fragment header size in bytes (fragment_id + total_fragments + data_len)
pub const FRAGMENT_HEADER_SIZE: usize = 12;

/// Maximum fragment data size (BODY_SIZE - header)
pub const MAX_FRAGMENT_DATA: usize = BODY_SIZE - FRAGMENT_HEADER_SIZE;

/// Maximum fragments accepted for a single message.
///
/// Bounds per-message memory (`MAX * MAX_FRAGMENT_DATA` worst case) and
/// rejects attacker-claimed huge `total_fragments` values.
pub const MAX_FRAGMENTS_PER_MESSAGE: u32 = 2048;

/// Maximum concurrent reassembly sessions tracked by [`ReassemblyManager`].
///
/// Bounds total reassembly memory; oldest session is evicted on overflow.
pub const MAX_REASSEMBLER_MESSAGES: usize = 64;

/// Default per-message reassembly timeout in seconds (10 minutes).
pub const REASSEMBLER_TIMEOUT_SECS: u64 = 600;

/// A fragment of a larger message
#[derive(Debug, Clone)]
pub struct Fragment {
    /// The fragment ID (0-indexed)
    pub fragment_id: u32,
    /// Total number of fragments
    pub total_fragments: u32,
    /// The fragment data
    pub data: Vec<u8>,
}

/// Fragment a payload into Sphinx-body-sized pieces
pub fn fragment_payload(payload: &[u8]) -> Vec<Fragment> {
    let total_fragments = ((payload.len() + MAX_FRAGMENT_DATA - 1) / MAX_FRAGMENT_DATA) as u32;
    let total_fragments = std::cmp::max(total_fragments, 1);

    let mut fragments = Vec::with_capacity(total_fragments as usize);

    for i in 0..total_fragments {
        let start = i as usize * MAX_FRAGMENT_DATA;
        let end = std::cmp::min(start + MAX_FRAGMENT_DATA, payload.len());
        let data = if start < payload.len() {
            payload[start..end].to_vec()
        } else {
            vec![]
        };

        fragments.push(Fragment {
            fragment_id: i,
            total_fragments,
            data,
        });
    }

    fragments
}

/// Serialize a fragment into a Sphinx body (fixed BODY_SIZE bytes)
pub fn serialize_fragment(fragment: &Fragment) -> Vec<u8> {
    let mut buf = vec![0u8; BODY_SIZE];

    // Write header: fragment_id (4) + total_fragments (4) + data_len (4)
    buf[0..4].copy_from_slice(&fragment.fragment_id.to_be_bytes());
    buf[4..8].copy_from_slice(&fragment.total_fragments.to_be_bytes());
    let data_len = fragment.data.len().min(MAX_FRAGMENT_DATA) as u32;
    buf[8..12].copy_from_slice(&data_len.to_be_bytes());

    // Write data
    buf[12..12 + data_len as usize].copy_from_slice(&fragment.data[..data_len as usize]);

    buf
}

/// Deserialize a fragment from a Sphinx body
pub fn deserialize_fragment(body: &[u8]) -> Result<Fragment, FragmentError> {
    if body.len() < FRAGMENT_HEADER_SIZE {
        return Err(FragmentError::TooShort);
    }

    let fragment_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let total_fragments = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let data_len = u32::from_be_bytes([body[8], body[9], body[10], body[11]]) as usize;

    // Only read data_len bytes, not the full padded body
    let data_end = FRAGMENT_HEADER_SIZE + data_len;
    if data_end > body.len() {
        return Err(FragmentError::TooShort);
    }
    let data = body[FRAGMENT_HEADER_SIZE..data_end].to_vec();

    Ok(Fragment {
        fragment_id,
        total_fragments,
        data,
    })
}

/// Reassembler for collecting fragments and rebuilding the original payload
pub struct Reassembler {
    /// Total fragments expected (from first received fragment)
    total_expected: Option<u32>,
    /// Received fragments (fragment_id -> data)
    fragments: HashMap<u32, Vec<u8>>,
    /// When this reassembly session started (for expiry)
    pub created_at: Instant,
}

impl Reassembler {
    /// Create a new reassembler
    pub fn new() -> Self {
        Self {
            total_expected: None,
            fragments: HashMap::new(),
            created_at: Instant::now(),
        }
    }

    /// Add a fragment to the reassembler
    ///
    /// Returns true if this fragment was new, false if duplicate or invalid.
    ///
    /// Enforces DoS bounds: rejects `total_fragments == 0`,
    /// `total_fragments > MAX_FRAGMENTS_PER_MESSAGE`,
    /// `fragment_id >= total_fragments`, oversized data, and inconsistent
    /// `total_fragments` across fragments of the same message.
    pub fn add_fragment(&mut self, fragment: Fragment) -> bool {
        // Bound total_fragments first (attacker-controlled).
        if fragment.total_fragments == 0
            || fragment.total_fragments > MAX_FRAGMENTS_PER_MESSAGE
        {
            return false;
        }
        if fragment.fragment_id >= fragment.total_fragments {
            return false;
        }
        if fragment.data.len() > MAX_FRAGMENT_DATA {
            return false;
        }
        match self.total_expected {
            None => {
                self.total_expected = Some(fragment.total_fragments);
            }
            Some(expected) => {
                if expected != fragment.total_fragments {
                    return false; // Inconsistent total; possible spoofing.
                }
            }
        }

        if self.fragments.contains_key(&fragment.fragment_id) {
            return false; // Duplicate
        }

        self.fragments.insert(fragment.fragment_id, fragment.data);
        true
    }

    /// Check whether this reassembler already holds `fragment_id`.
    pub fn contains_fragment(&self, fragment_id: u32) -> bool {
        self.fragments.contains_key(&fragment_id)
    }

    /// Check whether `fragment` would be accepted (bounds + not duplicate).
    ///
    /// Read-only helper so callers can find a matching session without
    /// cloning fragment data for every candidate.
    pub fn can_accept(&self, fragment: &Fragment) -> bool {
        if fragment.total_fragments == 0
            || fragment.total_fragments > MAX_FRAGMENTS_PER_MESSAGE
        {
            return false;
        }
        if fragment.fragment_id >= fragment.total_fragments {
            return false;
        }
        if fragment.data.len() > MAX_FRAGMENT_DATA {
            return false;
        }
        match self.total_expected {
            None => true,
            Some(expected) => {
                expected == fragment.total_fragments
                    && !self.fragments.contains_key(&fragment.fragment_id)
            }
        }
    }

    /// Check whether this session has expired.
    pub fn is_expired(&self, timeout_secs: u64) -> bool {
        self.created_at.elapsed() >= Duration::from_secs(timeout_secs)
    }

    /// Drop buffered fragments if this session is older than `timeout_secs`.
    ///
    /// Returns true if the session was expired (and cleared).
    pub fn cleanup_expired(&mut self, timeout_secs: u64) -> bool {
        if self.is_expired(timeout_secs) {
            self.fragments.clear();
            self.total_expected = None;
            self.created_at = Instant::now();
            true
        } else {
            false
        }
    }

    /// Check if all fragments have been received
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.total_expected {
            return self.fragments.len() == total as usize;
        }
        false
    }

    /// Get the number of received fragments
    pub fn received_count(&self) -> usize {
        self.fragments.len()
    }

    /// Get the total expected fragments
    pub fn total_expected(&self) -> Option<u32> {
        self.total_expected
    }

    /// Get progress (0.0 to 1.0)
    pub fn progress(&self) -> f64 {
        if let Some(total) = self.total_expected {
            if total == 0 {
                return 1.0;
            }
            return self.fragments.len() as f64 / total as f64;
        }
        0.0
    }

    /// Reassemble the original payload
    ///
    /// Only call this after is_complete() returns true.
    pub fn reassemble(&self) -> Result<Vec<u8>, FragmentError> {
        let total = self.total_expected.ok_or(FragmentError::NoFragments)?;

        let mut result = Vec::new();

        for i in 0..total {
            let data = self.fragments.get(&i)
                .ok_or(FragmentError::MissingFragment(i))?;
            result.extend_from_slice(data);
        }

        Ok(result)
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for multiple concurrent reassembly sessions.
///
/// Each message gets its own [`Reassembler`] (with its own `created_at`).
/// The table is bounded by [`MAX_REASSEMBLER_MESSAGES`]; when a new
/// message would exceed the cap, the oldest session is evicted first.
/// Call [`ReassemblyManager::cleanup_expired`] to drop sessions older
/// than the timeout (default [`REASSEMBLER_TIMEOUT_SECS`]).
pub struct ReassemblyManager {
    /// Sessions keyed by caller-provided message id
    sessions: HashMap<u64, Reassembler>,
    /// Insertion order for FIFO eviction (oldest front)
    order: VecDeque<u64>,
}

impl ReassemblyManager {
    /// Create a new empty manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Number of tracked sessions
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no sessions are tracked
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Whether `message_id` is tracked
    pub fn contains(&self, message_id: u64) -> bool {
        self.sessions.contains_key(&message_id)
    }

    /// Get a session by id
    pub fn get(&self, message_id: u64) -> Option<&Reassembler> {
        self.sessions.get(&message_id)
    }

    /// Get a mutable session by id
    pub fn get_mut(&mut self, message_id: u64) -> Option<&mut Reassembler> {
        self.sessions.get_mut(&message_id)
    }

    /// Get or create the session for `message_id`.
    ///
    /// Evicts the oldest session first if creation would exceed
    /// [`MAX_REASSEMBLER_MESSAGES`].
    pub fn get_or_create(&mut self, message_id: u64) -> &mut Reassembler {
        if !self.sessions.contains_key(&message_id) {
            if self.sessions.len() >= MAX_REASSEMBLER_MESSAGES {
                if let Some(oldest) = self.order.pop_front() {
                    self.sessions.remove(&oldest);
                }
            }
            self.sessions.insert(message_id, Reassembler::new());
            self.order.push_back(message_id);
        }
        self.sessions.get_mut(&message_id).expect("just inserted")
    }

    /// Add a fragment to the session for `message_id`.
    ///
    /// Creates the session on demand (with oldest-first eviction when over
    /// the cap). Returns false for invalid/duplicate fragments.
    pub fn add_fragment(&mut self, message_id: u64, fragment: Fragment) -> bool {
        // Validate bounds before creating a session (no state for junk).
        if fragment.total_fragments == 0
            || fragment.total_fragments > MAX_FRAGMENTS_PER_MESSAGE
            || fragment.fragment_id >= fragment.total_fragments
        {
            return false;
        }
        let session = self.get_or_create(message_id);
        session.add_fragment(fragment)
    }

    /// Remove a session, returning true if one existed.
    pub fn remove(&mut self, message_id: u64) -> bool {
        let existed = self.sessions.remove(&message_id).is_some();
        if existed {
            self.order.retain(|id| *id != message_id);
        }
        existed
    }

    /// Drop sessions older than `timeout_secs`.
    ///
    /// Returns the number of sessions removed.
    pub fn cleanup_expired(&mut self, timeout_secs: u64) -> usize {
        let expired: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired(timeout_secs))
            .map(|(id, _)| *id)
            .collect();
        let n = expired.len();
        for id in expired {
            self.sessions.remove(&id);
            self.order.retain(|kept| *kept != id);
        }
        n
    }

    /// Drop sessions older than [`REASSEMBLER_TIMEOUT_SECS`].
    ///
    /// Returns the number of sessions removed.
    pub fn cleanup_expired_default(&mut self) -> usize {
        self.cleanup_expired(REASSEMBLER_TIMEOUT_SECS)
    }
}

impl Default for ReassemblyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during fragmentation
#[derive(Debug, thiserror::Error)]
pub enum FragmentError {
    /// Fragment body too short
    #[error("fragment body too short")]
    TooShort,
    /// No fragments received
    #[error("no fragments received")]
    NoFragments,
    /// Missing fragment at index
    #[error("missing fragment at index {0}")]
    MissingFragment(u32),
    /// Fragment id out of range (must be < total_fragments)
    #[error("invalid fragment id")]
    InvalidFragmentId,
    /// Too many fragments claimed (exceeds limit)
    #[error("too many fragments")]
    TooManyFragments,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_small_payload() {
        let payload = b"small payload";
        let fragments = fragment_payload(payload);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].fragment_id, 0);
        assert_eq!(fragments[0].total_fragments, 1);
        assert_eq!(fragments[0].data, payload);
    }

    #[test]
    fn test_fragment_empty_payload() {
        let payload: Vec<u8> = vec![];
        let fragments = fragment_payload(&payload);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].total_fragments, 1);
        assert!(fragments[0].data.is_empty());
    }

    #[test]
    fn test_fragment_large_payload() {
        let payload = vec![0x42u8; MAX_FRAGMENT_DATA * 3 + 100];
        let fragments = fragment_payload(&payload);

        assert_eq!(fragments.len(), 4);
        assert_eq!(fragments[0].fragment_id, 0);
        assert_eq!(fragments[3].fragment_id, 3);
        assert_eq!(fragments[0].total_fragments, 4);

        // First 3 fragments should be full
        for i in 0..3 {
            assert_eq!(fragments[i].data.len(), MAX_FRAGMENT_DATA);
        }
        // Last fragment should be partial
        assert_eq!(fragments[3].data.len(), 100);
    }

    #[test]
    fn test_fragment_exact_multiple() {
        let payload = vec![0x42u8; MAX_FRAGMENT_DATA * 3];
        let fragments = fragment_payload(&payload);

        assert_eq!(fragments.len(), 3);
        for f in &fragments {
            assert_eq!(f.data.len(), MAX_FRAGMENT_DATA);
        }
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let fragment = Fragment {
            fragment_id: 5,
            total_fragments: 10,
            data: b"fragment data".to_vec(),
        };

        let serialized = serialize_fragment(&fragment);
        assert_eq!(serialized.len(), BODY_SIZE);

        let deserialized = deserialize_fragment(&serialized).unwrap();
        assert_eq!(deserialized.fragment_id, 5);
        assert_eq!(deserialized.total_fragments, 10);
        assert_eq!(deserialized.data, b"fragment data");
    }

    #[test]
    fn test_deserialize_too_short() {
        let result = deserialize_fragment(&[0u8; 4]);
        assert!(matches!(result, Err(FragmentError::TooShort)));
    }

    #[test]
    fn test_reassembler_basic() {
        let reassembler = Reassembler::new();
        assert!(!reassembler.is_complete());
        assert_eq!(reassembler.progress(), 0.0);
    }

    #[test]
    fn test_reassembler_single_fragment() {
        let payload = b"single fragment payload";
        let fragments = fragment_payload(payload);

        let mut reassembler = Reassembler::new();
        reassembler.add_fragment(fragments[0].clone());

        assert!(reassembler.is_complete());
        assert_eq!(reassembler.received_count(), 1);
        assert_eq!(reassembler.progress(), 1.0);

        let reassembled = reassembler.reassemble().unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_reassembler_multiple_fragments() {
        let payload = vec![0x42u8; MAX_FRAGMENT_DATA * 3 + 50];
        let fragments = fragment_payload(&payload);

        let mut reassembler = Reassembler::new();

        for (i, fragment) in fragments.iter().enumerate() {
            reassembler.add_fragment(fragment.clone());
            if i < fragments.len() - 1 {
                assert!(!reassembler.is_complete());
            }
        }

        assert!(reassembler.is_complete());
        assert_eq!(reassembler.received_count(), 4);

        let reassembled = reassembler.reassemble().unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_reassembler_duplicate_fragment() {
        let payload = b"test payload";
        let fragments = fragment_payload(payload);

        let mut reassembler = Reassembler::new();
        assert!(reassembler.add_fragment(fragments[0].clone()));
        assert!(!reassembler.add_fragment(fragments[0].clone())); // Duplicate
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let payload = vec![0x42u8; MAX_FRAGMENT_DATA * 3];
        let fragments = fragment_payload(&payload);

        let mut reassembler = Reassembler::new();

        // Add in reverse order
        reassembler.add_fragment(fragments[2].clone());
        reassembler.add_fragment(fragments[0].clone());
        reassembler.add_fragment(fragments[1].clone());

        assert!(reassembler.is_complete());
        let reassembled = reassembler.reassemble().unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_reassembler_missing_fragment() {
        let payload = vec![0x42u8; MAX_FRAGMENT_DATA * 3];
        let fragments = fragment_payload(&payload);

        let mut reassembler = Reassembler::new();
        reassembler.add_fragment(fragments[0].clone());
        reassembler.add_fragment(fragments[2].clone()); // Skip fragment 1

        assert!(!reassembler.is_complete());
        let result = reassembler.reassemble();
        assert!(matches!(result, Err(FragmentError::MissingFragment(1))));
    }

    #[test]
    fn test_reassembler_no_fragments() {
        let reassembler = Reassembler::new();
        let result = reassembler.reassemble();
        assert!(matches!(result, Err(FragmentError::NoFragments)));
    }

    #[test]
    fn test_reassembler_progress() {
        let payload = vec![0x42u8; MAX_FRAGMENT_DATA * 4];
        let fragments = fragment_payload(&payload);

        let mut reassembler = Reassembler::new();
        reassembler.add_fragment(fragments[0].clone());
        assert!((reassembler.progress() - 0.25).abs() < 0.01);

        reassembler.add_fragment(fragments[1].clone());
        assert!((reassembler.progress() - 0.50).abs() < 0.01);

        reassembler.add_fragment(fragments[2].clone());
        assert!((reassembler.progress() - 0.75).abs() < 0.01);

        reassembler.add_fragment(fragments[3].clone());
        assert!((reassembler.progress() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_total_expected_tracking() {
        let payload = vec![0x42u8; MAX_FRAGMENT_DATA * 2];
        let fragments = fragment_payload(&payload);

        let mut reassembler = Reassembler::new();
        assert!(reassembler.total_expected().is_none());

        reassembler.add_fragment(fragments[0].clone());
        assert_eq!(reassembler.total_expected(), Some(2));
    }

    #[test]
    fn test_full_roundtrip_large_payload() {
        let payload = vec![0xABu8; 100_000]; // ~100 KB
        let fragments = fragment_payload(&payload);

        // Serialize each fragment
        let serialized: Vec<Vec<u8>> = fragments.iter()
            .map(|f| serialize_fragment(f))
            .collect();

        // Deserialize and reassemble
        let mut reassembler = Reassembler::new();
        for s in &serialized {
            let fragment = deserialize_fragment(s).unwrap();
            reassembler.add_fragment(fragment);
        }

        assert!(reassembler.is_complete());
        let reassembled = reassembler.reassemble().unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_reject_fragment_id_out_of_range() {
        let mut r = Reassembler::new();
        // fragment_id == total_fragments is invalid (must be < total).
        assert!(!r.add_fragment(Fragment {
            fragment_id: 4,
            total_fragments: 4,
            data: b"x".to_vec(),
        }));
        assert!(!r.add_fragment(Fragment {
            fragment_id: 99,
            total_fragments: 4,
            data: b"x".to_vec(),
        }));
        assert_eq!(r.received_count(), 0);
        assert!(r.total_expected().is_none());
    }

    #[test]
    fn test_reject_total_fragments_over_max() {
        let mut r = Reassembler::new();
        assert!(!r.add_fragment(Fragment {
            fragment_id: 0,
            total_fragments: MAX_FRAGMENTS_PER_MESSAGE + 1,
            data: b"x".to_vec(),
        }));
        assert!(!r.add_fragment(Fragment {
            fragment_id: 0,
            total_fragments: 0,
            data: b"x".to_vec(),
        }));
        assert_eq!(r.received_count(), 0);
    }

    #[test]
    fn test_reject_inconsistent_total() {
        let mut r = Reassembler::new();
        assert!(r.add_fragment(Fragment {
            fragment_id: 0,
            total_fragments: 3,
            data: b"a".to_vec(),
        }));
        // Same session claiming a different total is rejected.
        assert!(!r.add_fragment(Fragment {
            fragment_id: 1,
            total_fragments: 4,
            data: b"b".to_vec(),
        }));
        assert_eq!(r.total_expected(), Some(3));
        assert_eq!(r.received_count(), 1);
    }

    #[test]
    fn test_reassembler_expiry_and_cleanup() {
        let mut r = Reassembler::new();
        assert!(r.add_fragment(Fragment {
            fragment_id: 0,
            total_fragments: 2,
            data: b"a".to_vec(),
        }));
        assert!(!r.is_expired(600));
        // Age the session past the timeout.
        r.created_at = Instant::now() - Duration::from_secs(601);
        assert!(r.is_expired(600));
        assert!(r.cleanup_expired(600));
        assert_eq!(r.received_count(), 0);
        assert!(r.total_expected().is_none());
        // Fresh session does not clean.
        assert!(!r.cleanup_expired(600));
    }

    #[test]
    fn test_reassembly_manager_evicts_oldest() {
        let mut m = ReassemblyManager::new();
        for id in 0..MAX_REASSEMBLER_MESSAGES as u64 {
            assert!(m.add_fragment(
                id,
                Fragment {
                    fragment_id: 0,
                    total_fragments: 2,
                    data: b"a".to_vec()
                }
            ));
        }
        assert_eq!(m.len(), MAX_REASSEMBLER_MESSAGES);
        // One more session evicts message 0.
        assert!(m.add_fragment(
            MAX_REASSEMBLER_MESSAGES as u64,
            Fragment {
                fragment_id: 0,
                total_fragments: 2,
                data: b"a".to_vec()
            }
        ));
        assert_eq!(m.len(), MAX_REASSEMBLER_MESSAGES);
        assert!(!m.contains(0));
        assert!(m.contains(MAX_REASSEMBLER_MESSAGES as u64));
    }

    #[test]
    fn test_reassembly_manager_cleanup_expired() {
        let mut m = ReassemblyManager::new();
        m.add_fragment(
            1,
            Fragment {
                fragment_id: 0,
                total_fragments: 2,
                data: b"a".to_vec(),
            },
        );
        m.add_fragment(
            2,
            Fragment {
                fragment_id: 0,
                total_fragments: 2,
                data: b"b".to_vec(),
            },
        );
        // Age session 1 only.
        m.get_mut(1).unwrap().created_at = Instant::now() - Duration::from_secs(601);
        let removed = m.cleanup_expired(600);
        assert_eq!(removed, 1);
        assert!(!m.contains(1));
        assert!(m.contains(2));
    }

    #[test]
    fn test_reassembly_manager_rejects_invalid_without_growing() {
        let mut m = ReassemblyManager::new();
        assert!(!m.add_fragment(
            7,
            Fragment {
                fragment_id: 5,
                total_fragments: 2,
                data: b"x".to_vec()
            }
        ));
        assert!(m.is_empty());
    }
}
