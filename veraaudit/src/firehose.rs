//! AWS Kinesis Firehose output for audit logs
//!
//! Sends audit log entries to a Firehose delivery stream using the AWS default
//! credential provider chain (IRSA, ECS task role, Lambda execution role, env vars, profile).
//!
//! # Configuration
//!
//! - Delivery stream name: `--firehose-stream` CLI arg
//! - AWS region: `--firehose-region` CLI arg, falls back to `AWS_REGION` / `AWS_DEFAULT_REGION`
//! - Max retries: `VERAAUDIT_FIREHOSE_RETRIES` env var, default 3
//!
//! # Record format
//!
//! Each audit log entry is serialised as a JSON object and sent as a single
//! Firehose record. Batches of up to 500 records (max 4 MiB total) are sent
//! per `PutRecordBatch` call.
//!
//! # Downstream destinations
//!
//! Firehose delivery streams can be configured to route to Splunk (via HTTP Event
//! Collector), S3, `OpenSearch`, Redshift, and others — all managed by AWS without
//! requiring a consumer application.

use crate::error::{AuditError, Result};
use aws_config::BehaviorVersion;
use aws_sdk_firehose::primitives::Blob;
use aws_sdk_firehose::types::Record;
use log::{debug, error, info, warn};

/// Maximum records per `PutRecordBatch` call (Firehose hard limit)
const MAX_RECORDS_PER_BATCH: usize = 500;

/// Maximum bytes per Firehose record (1,000 KiB)
const MAX_RECORD_SIZE_BYTES: usize = 1_024_000;

/// Maximum total bytes per `PutRecordBatch` call (4 MiB)
const MAX_BATCH_SIZE_BYTES: usize = 4_194_304;

/// Base delay in milliseconds for exponential backoff between retries
const RETRY_BASE_DELAY_MS: u64 = 100;

/// Default number of retry attempts when `VERAAUDIT_FIREHOSE_RETRIES` is not set
const DEFAULT_MAX_RETRIES: usize = 3;

/// Configuration for the Firehose output sink
pub struct FirehoseConfig {
    /// Firehose delivery stream name (not ARN)
    pub delivery_stream_name: String,
    /// AWS region override
    pub region: Option<String>,
    /// Maximum number of retry attempts for failed records
    pub max_retries: usize,
}

impl FirehoseConfig {
    /// Create config, reading `VERAAUDIT_FIREHOSE_RETRIES` from the environment.
    #[must_use]
    pub fn new(delivery_stream_name: String, region: Option<String>) -> Self {
        let max_retries = std::env::var("VERAAUDIT_FIREHOSE_RETRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_RETRIES);

        Self {
            delivery_stream_name,
            region,
            max_retries,
        }
    }
}

/// Firehose output sink — wraps the AWS SDK client
pub struct FirehoseOutput {
    client: aws_sdk_firehose::Client,
    config: FirehoseConfig,
}

impl FirehoseOutput {
    /// Build a `FirehoseOutput` using the AWS default credential provider chain.
    ///
    /// Authentication is resolved automatically in order:
    /// 1. EKS IRSA (`AWS_WEB_IDENTITY_TOKEN_FILE` / `AWS_ROLE_ARN`)
    /// 2. ECS task role (container credentials endpoint)
    /// 3. Lambda execution role
    /// 4. Environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`)
    /// 5. AWS profile (`~/.aws/credentials`)
    /// 6. EC2 instance metadata (`IMDSv2`)
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Firehose` if the SDK client cannot be constructed.
    pub async fn new(config: FirehoseConfig) -> Result<Self> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(ref region_str) = config.region {
            let region = aws_sdk_firehose::config::Region::new(region_str.clone());
            loader = loader.region(region);
        }

        let aws_cfg = loader.load().await;
        let client = aws_sdk_firehose::Client::new(&aws_cfg);

        info!(
            "Firehose output initialised: delivery_stream={}, region={}",
            config.delivery_stream_name,
            config.region.as_deref().unwrap_or("(from environment)")
        );

        Ok(Self { client, config })
    }

    /// Send a slice of log entries to the Firehose delivery stream.
    ///
    /// Splits into batches respecting both the 500-record and 4 MiB limits, then
    /// calls `PutRecordBatch` for each. Partial failures are retried with
    /// exponential backoff up to `config.max_retries` times.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Firehose` if records cannot be delivered after all retries.
    pub async fn send_records(&self, logs: &[serde_json::Value]) -> Result<()> {
        if logs.is_empty() {
            return Ok(());
        }

        info!(
            "Sending {} log entries to Firehose delivery stream '{}'",
            logs.len(),
            self.config.delivery_stream_name,
        );

        for (batch_idx, chunk) in build_size_bounded_batches(logs).iter().enumerate() {
            debug!(
                "Sending Firehose batch {} ({} records)",
                batch_idx.saturating_add(1),
                chunk.len()
            );
            self.send_batch_with_retry(chunk).await?;
        }

        info!("All {} records delivered to Firehose", logs.len());
        Ok(())
    }

    /// Send a single batch with retry on partial failure.
    async fn send_batch_with_retry(&self, batch: &[serde_json::Value]) -> Result<()> {
        let mut pending: Vec<usize> = (0..batch.len()).collect();
        let mut attempt: usize = 0;

        loop {
            attempt = attempt.saturating_add(1);

            let entries: Vec<(usize, Record)> = pending
                .iter()
                .filter_map(|&idx| {
                    let entry = batch.get(idx)?;
                    match build_record(entry) {
                        Some(r) => Some((idx, r)),
                        None => {
                            warn!(
                                "Skipping log entry at index {} — serialisation failed or record exceeds 1,000 KiB",
                                idx
                            );
                            None
                        }
                    }
                })
                .collect();

            if entries.is_empty() {
                return Ok(());
            }

            let records: Vec<Record> = entries.iter().map(|(_, r)| r.clone()).collect();

            let response = self
                .client
                .put_record_batch()
                .delivery_stream_name(&self.config.delivery_stream_name)
                .set_records(Some(records))
                .send()
                .await
                .map_err(|e| {
                    AuditError::Firehose(format!(
                        "PutRecordBatch API call failed on attempt {}: {}",
                        attempt, e
                    ))
                })?;

            let failed_count = response.failed_put_count();

            if failed_count == 0 {
                debug!("Batch delivered: {} records", entries.len());
                return Ok(());
            }

            let record_results = response.request_responses();
            let mut failed_indices: Vec<usize> = Vec::new();

            for ((orig_idx, _), record_result) in entries.iter().zip(record_results.iter()) {
                if record_result.error_code().is_some() {
                    debug!(
                        "Record (original index {}) failed: {} — {}",
                        orig_idx,
                        record_result.error_code().unwrap_or("Unknown"),
                        record_result.error_message().unwrap_or("no message"),
                    );
                    failed_indices.push(*orig_idx);
                }
            }

            warn!(
                "Attempt {}/{}: {} of {} records failed in delivery stream '{}'",
                attempt,
                self.config.max_retries,
                failed_indices.len(),
                entries.len(),
                self.config.delivery_stream_name,
            );

            if attempt >= self.config.max_retries {
                error!(
                    "Firehose delivery failed after {} retries: {} records could not be written to delivery stream '{}'",
                    self.config.max_retries,
                    failed_indices.len(),
                    self.config.delivery_stream_name,
                );
                return Err(AuditError::Firehose(format!(
                    "{} records failed after {} retries in delivery stream '{}'",
                    failed_indices.len(),
                    self.config.max_retries,
                    self.config.delivery_stream_name,
                )));
            }

            let delay_ms = RETRY_BASE_DELAY_MS
                .saturating_mul(2u64.saturating_pow(u32::try_from(attempt).unwrap_or(u32::MAX)));
            debug!("Backing off {}ms before retry", delay_ms);
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

            pending = failed_indices;
        }
    }
}

/// Split `logs` into sub-slices that each respect both the 500-record limit
/// and the 4 MiB total-batch limit.
fn build_size_bounded_batches(logs: &[serde_json::Value]) -> Vec<Vec<serde_json::Value>> {
    let mut batches: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut current_batch: Vec<serde_json::Value> = Vec::new();
    let mut current_batch_bytes: usize = 0;

    for entry in logs {
        let size = serde_json::to_vec(entry).map_or(0, |b| b.len());

        if size > MAX_RECORD_SIZE_BYTES {
            warn!(
                "Log entry is {} bytes — exceeds Firehose 1,000 KiB record limit, skipping",
                size
            );
            continue;
        }

        let would_exceed_records = current_batch.len() >= MAX_RECORDS_PER_BATCH;
        let would_exceed_bytes = current_batch_bytes.saturating_add(size) > MAX_BATCH_SIZE_BYTES;

        if (would_exceed_records || would_exceed_bytes) && !current_batch.is_empty() {
            batches.push(std::mem::take(&mut current_batch));
            current_batch_bytes = 0;
        }

        current_batch.push(entry.clone());
        current_batch_bytes = current_batch_bytes.saturating_add(size);
    }

    if !current_batch.is_empty() {
        batches.push(current_batch);
    }

    batches
}

/// Serialise a single log entry into a Firehose `Record`.
///
/// Returns `None` if serialisation fails or the record exceeds the 1,000 KiB limit.
fn build_record(entry: &serde_json::Value) -> Option<Record> {
    let json_bytes = serde_json::to_vec(entry).ok()?;

    if json_bytes.len() > MAX_RECORD_SIZE_BYTES {
        warn!(
            "Log entry is {} bytes — exceeds Firehose 1,000 KiB record limit, skipping",
            json_bytes.len()
        );
        return None;
    }

    Record::builder().data(Blob::new(json_bytes)).build().ok()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use serde_json::json;

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // --- build_record ---

    #[test]
    fn record_serialises_correctly() {
        let entry = json!({"event": "scan_complete", "app": "myapp"});
        let result = build_record(&entry);
        let record = result.expect("expected Some for a valid entry");
        let bytes = record.data().as_ref();
        let parsed: serde_json::Value =
            serde_json::from_slice(bytes).expect("data should be valid JSON");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn record_rejects_oversized() {
        // A bare JSON string serialises as `"...chars..."` (+2 bytes for quotes).
        // Using MAX_RECORD_SIZE_BYTES chars pushes the total to MAX + 2, exceeding the limit.
        let big_string = "x".repeat(MAX_RECORD_SIZE_BYTES);
        let entry = json!(big_string);
        assert!(build_record(&entry).is_none());
    }

    // --- build_size_bounded_batches ---

    #[test]
    fn batches_empty_input() {
        let batches = build_size_bounded_batches(&[]);
        assert!(batches.is_empty());
    }

    #[test]
    fn batches_single_entry_stays_in_one_batch() {
        let logs = vec![json!({"x": 1})];
        let batches = build_size_bounded_batches(&logs);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches.first().expect("batch 0").len(), 1);
    }

    #[test]
    fn batches_500_records_stays_in_one_batch() {
        let logs: Vec<serde_json::Value> = (0..500).map(|i| json!({"i": i})).collect();
        let batches = build_size_bounded_batches(&logs);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches.first().expect("batch 0").len(), 500);
    }

    #[test]
    fn batches_501_records_splits_into_two() {
        let logs: Vec<serde_json::Value> = (0..501).map(|i| json!({"i": i})).collect();
        let batches = build_size_bounded_batches(&logs);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches.first().expect("batch 0").len(), 500);
        assert_eq!(batches.get(1).expect("batch 1").len(), 1);
    }

    #[test]
    fn batches_splits_at_byte_limit() {
        // Each entry serialises to ~900_000 bytes (well under the 1_024_000 per-record cap).
        // 4 entries = ~3_600_000 bytes (fits); adding a 5th pushes to ~4_500_000 > 4_194_304,
        // so the function must open a second batch.
        let entry_string = "x".repeat(899_998); // + 2 JSON quote bytes = 900_000
        let logs: Vec<serde_json::Value> = (0..5).map(|_| json!(entry_string)).collect();
        let batches = build_size_bounded_batches(&logs);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches.first().expect("batch 0").len(), 4);
        assert_eq!(batches.get(1).expect("batch 1").len(), 1);
    }

    #[test]
    fn batches_skips_individual_oversized_records() {
        // An entry that exceeds the 1_024_000-byte per-record limit must be dropped entirely.
        let big_string = "x".repeat(MAX_RECORD_SIZE_BYTES); // serialises to MAX + 2 bytes
        let logs = vec![json!(big_string)];
        let batches = build_size_bounded_batches(&logs);
        assert!(batches.is_empty());
    }

    // --- FirehoseConfig ---

    #[test]
    fn config_uses_default_retries_when_env_unset() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("VERAAUDIT_FIREHOSE_RETRIES") };
        let config = FirehoseConfig::new("my-stream".to_string(), None);
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn config_reads_retries_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("VERAAUDIT_FIREHOSE_RETRIES", "5") };
        let config = FirehoseConfig::new("my-stream".to_string(), None);
        unsafe { std::env::remove_var("VERAAUDIT_FIREHOSE_RETRIES") };
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn config_falls_back_on_invalid_env_value() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("VERAAUDIT_FIREHOSE_RETRIES", "not-a-number") };
        let config = FirehoseConfig::new("my-stream".to_string(), None);
        unsafe { std::env::remove_var("VERAAUDIT_FIREHOSE_RETRIES") };
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }
}
