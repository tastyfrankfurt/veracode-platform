//! Persistent progress cursor for Kinesis/Firehose streaming output
//!
//! Tracks the high-water mark timestamp and the xxh3 hashes of every record
//! delivered at that boundary second.  On the next cycle the service re-queries
//! from the cursor second (`query_start`), filters duplicates via
//! `is_duplicate`, and sends only new records downstream.
//!
//! # Sub-second precision
//!
//! The Veracode API accepts only second-granular time filters.  If the last
//! delivered record had `timestamp_utc = "2025-04-13 12:23:34.789"` the cursor
//! stores `"2025-04-13 12:23:34"`.  Re-querying from that second catches any
//! events at `.800`, `.950`, etc. that arrived after the previous cycle closed.
//! `last_second_hashes` prevents re-delivering what was already sent.
//!
//! # No staleness limit
//!
//! Unlike the file-output timestamp heuristic there is no maximum cursor age.
//! The cursor is intentional operator state; outage recovery of any length is
//! handled correctly as long as the file is present.  A missing or corrupt
//! file falls back to `--start-offset`.

use crate::error::{AuditError, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use xxhash_rust::xxh3::xxh3_64;

/// Persistent cursor written to disk between service cycles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCursor {
    /// Last successfully-delivered timestamp floored to second: `"YYYY-MM-DD HH:MM:SS"`.
    pub timestamp: String,
    /// xxh3-64 hashes of every record whose `timestamp_utc` matches `timestamp`.
    pub last_second_hashes: HashSet<u64>,
}

impl StreamCursor {
    /// Load cursor from `path`.
    ///
    /// Returns `None` when the file is absent or unparseable; the caller
    /// should then fall back to `--start-offset`.
    #[must_use]
    pub fn load(path: &Path) -> Option<Self> {
        if !path.exists() {
            debug!(
                "No cursor file at {}, starting from start_offset",
                path.display()
            );
            return None;
        }

        match std::fs::read_to_string(path) {
            Err(e) => {
                warn!(
                    "Could not read cursor file {}: {} — falling back to start_offset",
                    path.display(),
                    e
                );
                None
            }
            Ok(contents) => match serde_json::from_str::<Self>(&contents) {
                Err(e) => {
                    warn!(
                        "Cursor file {} is corrupt ({}): falling back to start_offset",
                        path.display(),
                        e
                    );
                    None
                }
                Ok(cursor) => {
                    info!(
                        "Loaded stream cursor: timestamp={}, boundary_hashes={}",
                        cursor.timestamp,
                        cursor.last_second_hashes.len()
                    );
                    Some(cursor)
                }
            },
        }
    }

    /// Persist cursor to `path`, creating parent directories if needed.
    ///
    /// # Errors
    ///
    /// Returns `AuditError` if the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| AuditError::InvalidConfig(format!("Failed to serialise cursor: {}", e)))?;
        std::fs::write(path, json)?;
        debug!(
            "Cursor saved: timestamp={}, boundary_hashes={}",
            self.timestamp,
            self.last_second_hashes.len()
        );
        Ok(())
    }

    /// Datetime string to use as `start_datetime` for the next query cycle.
    ///
    /// Returns `self.timestamp` (the floor second) directly — no `-1s`
    /// adjustment is needed because `last_second_hashes` already covers every
    /// record at that second.
    #[must_use]
    pub fn query_start(&self) -> &str {
        &self.timestamp
    }

    /// Returns `true` when `record` was already delivered and should be
    /// filtered from the outgoing batch.
    ///
    /// A record is a duplicate when both conditions hold:
    /// 1. Its `timestamp_utc` floored to second equals `self.timestamp`.
    /// 2. Its xxh3 hash is in `self.last_second_hashes`.
    #[must_use]
    pub fn is_duplicate(&self, record: &serde_json::Value) -> bool {
        let Some(ts) = record.get("timestamp_utc").and_then(|v| v.as_str()) else {
            return false;
        };
        let ts_floor = ts.get(..19).unwrap_or(ts);
        if ts_floor != self.timestamp {
            return false;
        }
        self.last_second_hashes
            .contains(&compute_record_hash(record))
    }
}

/// Accumulates the high-water mark across all batches in a single service cycle.
///
/// After the cycle completes, call [`CycleCursorState::into_cursor`] to obtain
/// the [`StreamCursor`] to persist.  Always pass the **original, unfiltered**
/// batch to [`update`](CycleCursorState::update) so the high-water mark
/// reflects the true latest event regardless of dedup filtering.
#[derive(Debug, Default)]
pub struct CycleCursorState {
    latest_timestamp: Option<String>,
    latest_hashes: HashSet<u64>,
}

impl CycleCursorState {
    /// Create a fresh tracker for a new cycle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the high-water mark with every record in `batch`.
    pub fn update(&mut self, batch: &[serde_json::Value]) {
        for record in batch {
            let Some(ts) = record.get("timestamp_utc").and_then(|v| v.as_str()) else {
                continue;
            };
            let ts_floor = ts.get(..19).unwrap_or(ts);
            let hash = compute_record_hash(record);

            match self.latest_timestamp.as_deref() {
                None => {
                    self.latest_timestamp = Some(ts_floor.to_string());
                    self.latest_hashes.insert(hash);
                }
                Some(current) if ts_floor > current => {
                    self.latest_timestamp = Some(ts_floor.to_string());
                    self.latest_hashes.clear();
                    self.latest_hashes.insert(hash);
                }
                Some(current) if ts_floor == current => {
                    self.latest_hashes.insert(hash);
                }
                Some(_) => {} // older record — ignore
            }
        }
    }

    /// Convert accumulated state into a [`StreamCursor`].
    ///
    /// Returns `None` if no records were seen this cycle (cursor unchanged).
    #[must_use]
    pub fn into_cursor(self) -> Option<StreamCursor> {
        self.latest_timestamp.map(|timestamp| StreamCursor {
            timestamp,
            last_second_hashes: self.latest_hashes,
        })
    }
}

/// Compute the xxh3-64 hash of a log record using its canonical JSON form.
fn compute_record_hash(record: &serde_json::Value) -> u64 {
    xxh3_64(serde_json::to_string(record).unwrap_or_default().as_bytes())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::test_utils::TempDir;
    use serde_json::json;

    fn record(ts: &str, action: &str) -> serde_json::Value {
        json!({ "timestamp_utc": ts, "action": action })
    }

    // --- StreamCursor::is_duplicate ---

    #[test]
    fn is_duplicate_same_second_and_hash() {
        let r = record("2025-04-13 12:23:34.789", "Login");
        let hash = compute_record_hash(&r);
        let cursor = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: [hash].into(),
        };
        assert!(cursor.is_duplicate(&r));
    }

    #[test]
    fn is_duplicate_different_second_returns_false() {
        let r = record("2025-04-13 12:23:35.000", "Login");
        let hash = compute_record_hash(&r);
        let cursor = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: [hash].into(),
        };
        assert!(!cursor.is_duplicate(&r));
    }

    #[test]
    fn is_duplicate_same_second_wrong_hash_returns_false() {
        let cursor = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: [999u64].into(),
        };
        let r = record("2025-04-13 12:23:34.500", "Logout");
        assert!(!cursor.is_duplicate(&r));
    }

    #[test]
    fn is_duplicate_missing_timestamp_field_returns_false() {
        let cursor = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: [1u64].into(),
        };
        assert!(!cursor.is_duplicate(&json!({ "action": "Login" })));
    }

    #[test]
    fn is_duplicate_exact_second_timestamp_no_subsecond() {
        let r = record("2025-04-13 12:23:34", "Login");
        let hash = compute_record_hash(&r);
        let cursor = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: [hash].into(),
        };
        assert!(cursor.is_duplicate(&r));
    }

    // --- CycleCursorState ---

    #[test]
    fn cycle_state_tracks_latest_timestamp_and_hashes() {
        let mut state = CycleCursorState::new();
        let a = record("2025-04-13 12:23:33.000", "A");
        let b = record("2025-04-13 12:23:34.789", "B");
        let c = record("2025-04-13 12:23:34.100", "C");
        state.update(&[a, b, c]);
        let cursor = state.into_cursor().expect("expected cursor");
        assert_eq!(cursor.timestamp, "2025-04-13 12:23:34");
        assert_eq!(cursor.last_second_hashes.len(), 2);
    }

    #[test]
    fn cycle_state_empty_yields_none() {
        assert!(CycleCursorState::new().into_cursor().is_none());
    }

    #[test]
    fn cycle_state_single_record() {
        let mut state = CycleCursorState::new();
        state.update(&[record("2025-04-13 12:23:34.000", "Login")]);
        let cursor = state.into_cursor().unwrap();
        assert_eq!(cursor.timestamp, "2025-04-13 12:23:34");
        assert_eq!(cursor.last_second_hashes.len(), 1);
    }

    #[test]
    fn cycle_state_ignores_older_records_after_newer() {
        let mut state = CycleCursorState::new();
        state.update(&[
            record("2025-04-13 12:23:35.000", "A"),
            record("2025-04-13 12:23:34.000", "B"), // older
        ]);
        let cursor = state.into_cursor().unwrap();
        assert_eq!(cursor.timestamp, "2025-04-13 12:23:35");
        assert_eq!(cursor.last_second_hashes.len(), 1);
    }

    #[test]
    fn cycle_state_update_across_multiple_batches() {
        let mut state = CycleCursorState::new();
        state.update(&[record("2025-04-13 12:23:33.000", "A")]);
        state.update(&[record("2025-04-13 12:23:35.000", "B")]);
        let cursor = state.into_cursor().unwrap();
        assert_eq!(cursor.timestamp, "2025-04-13 12:23:35");
    }

    // --- StreamCursor::load / save ---

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn save_and_load_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("cursor.json");
        let original = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: [1u64, 2u64, 3u64].into(),
        };
        original.save(&path).unwrap();
        let loaded = StreamCursor::load(&path).expect("should load");
        assert_eq!(loaded.timestamp, original.timestamp);
        assert_eq!(loaded.last_second_hashes, original.last_second_hashes);
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn load_returns_none_when_absent() {
        let temp_dir = TempDir::new().unwrap();
        assert!(StreamCursor::load(&temp_dir.path().join("nope.json")).is_none());
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn load_returns_none_on_corrupt_file() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("cursor.json");
        std::fs::write(&path, "not valid json {{{{").unwrap();
        assert!(StreamCursor::load(&path).is_none());
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn save_creates_parent_directories() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("subdir").join("cursor.json");
        let cursor = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: HashSet::new(),
        };
        assert!(cursor.save(&path).is_ok());
        assert!(path.exists());
    }

    // --- query_start ---

    #[test]
    fn query_start_returns_floor_timestamp() {
        let cursor = StreamCursor {
            timestamp: "2025-04-13 12:23:34".to_string(),
            last_second_hashes: HashSet::new(),
        };
        assert_eq!(cursor.query_start(), "2025-04-13 12:23:34");
    }
}
