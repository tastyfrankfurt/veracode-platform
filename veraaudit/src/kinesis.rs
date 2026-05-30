//! AWS Kinesis Data Streams output for audit logs
//!
//! Sends audit log entries to a Kinesis stream using the AWS default credential
//! provider chain (IRSA, ECS task role, Lambda execution role, env vars, profile).
//!
//! # Configuration
//!
//! - Stream name: `--kinesis-stream` CLI arg
//! - AWS region: `--kinesis-region` CLI arg, falls back to `AWS_REGION` / `AWS_DEFAULT_REGION`
//! - Max retries: `VERAAUDIT_KINESIS_RETRIES` env var, default 3
//!
//! # Record format
//!
//! Each audit log entry is serialised as a JSON object and sent as a single
//! Kinesis record. Batches of up to 500 records are sent per `PutRecords` call.
//!
//! # Partition key
//!
//! Fixed per run: `"veraaudit-{veracode_region}"` (e.g. `"veraaudit-commercial"`).
//! At 2000 records / 30 min the load is well under 1% of a single shard's capacity,
//! so a fixed key gives strict global ordering without complexity.
//!
//! # TODO
//!
//! Investigate Kinesis Producer Library (KPL) aggregation / record-level caching
//! to reduce `PutRecords` call overhead for higher-volume deployments.

use crate::error::{AuditError, Result};
use aws_config::BehaviorVersion;
use aws_sdk_kinesis::primitives::Blob;
use aws_sdk_kinesis::types::PutRecordsRequestEntry;
use log::{debug, error, info, warn};

/// Maximum records per `PutRecords` call (Kinesis hard limit)
const MAX_RECORDS_PER_BATCH: usize = 500;

/// Maximum bytes per Kinesis record (Kinesis hard limit: 1 MiB)
const MAX_RECORD_SIZE_BYTES: usize = 1_048_576;

/// Base delay in milliseconds for exponential backoff between retries
const RETRY_BASE_DELAY_MS: u64 = 100;

/// Default number of retry attempts when `VERAAUDIT_KINESIS_RETRIES` is not set
const DEFAULT_MAX_RETRIES: usize = 3;

/// Configuration for the Kinesis output sink
pub struct KinesisConfig {
    /// Kinesis stream name (not ARN)
    pub stream_name: String,
    /// AWS region override. When `None`, the AWS SDK resolves the region via its
    /// standard chain (`AWS_REGION`, `AWS_DEFAULT_REGION`, instance metadata, etc.)
    pub region: Option<String>,
    /// Maximum number of retry attempts for failed records
    pub max_retries: usize,
}

impl KinesisConfig {
    /// Create config, reading `VERAAUDIT_KINESIS_RETRIES` from the environment.
    #[must_use]
    pub fn new(stream_name: String, region: Option<String>) -> Self {
        let max_retries = std::env::var("VERAAUDIT_KINESIS_RETRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_RETRIES);

        Self {
            stream_name,
            region,
            max_retries,
        }
    }
}

/// Kinesis output sink — wraps the AWS SDK client
pub struct KinesisOutput {
    client: aws_sdk_kinesis::Client,
    config: KinesisConfig,
}

impl KinesisOutput {
    /// Build a `KinesisOutput` using the AWS default credential provider chain.
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
    /// Returns `AuditError::Kinesis` if the SDK client cannot be constructed.
    pub async fn new(config: KinesisConfig) -> Result<Self> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(ref region_str) = config.region {
            let region = aws_sdk_kinesis::config::Region::new(region_str.clone());
            loader = loader.region(region);
        }

        let aws_cfg = loader.load().await;
        let client = aws_sdk_kinesis::Client::new(&aws_cfg);

        info!(
            "Kinesis output initialised: stream={}, region={}",
            config.stream_name,
            config.region.as_deref().unwrap_or("(from environment)")
        );

        Ok(Self { client, config })
    }

    /// Send a slice of log entries to Kinesis.
    ///
    /// Splits into batches of up to 500 records and calls `PutRecords` for each.
    /// Partial failures within a batch are retried with exponential backoff up to
    /// `config.max_retries` times. After exhausting retries the call fails hard.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Kinesis` if records cannot be delivered after all retries.
    pub async fn send_records(
        &self,
        logs: &[serde_json::Value],
        partition_key: &str,
    ) -> Result<()> {
        if logs.is_empty() {
            return Ok(());
        }

        info!(
            "Sending {} log entries to Kinesis stream '{}' (batches of up to {})",
            logs.len(),
            self.config.stream_name,
            MAX_RECORDS_PER_BATCH,
        );

        for (batch_idx, chunk) in logs.chunks(MAX_RECORDS_PER_BATCH).enumerate() {
            debug!(
                "Sending Kinesis batch {} ({} records)",
                batch_idx.saturating_add(1),
                chunk.len()
            );
            self.send_batch_with_retry(chunk, partition_key).await?;
        }

        info!("All {} records delivered to Kinesis", logs.len());
        Ok(())
    }

    /// Send a single chunk (≤ 500 entries) with retry on partial failure.
    async fn send_batch_with_retry(
        &self,
        batch: &[serde_json::Value],
        partition_key: &str,
    ) -> Result<()> {
        // Track which indices in `batch` are still pending delivery
        let mut pending: Vec<usize> = (0..batch.len()).collect();

        let mut attempt: usize = 0;

        loop {
            attempt = attempt.saturating_add(1);

            // Build Kinesis request entries for all pending indices
            let entries: Vec<(usize, PutRecordsRequestEntry)> = pending
                .iter()
                .filter_map(|&idx| {
                    let entry = batch.get(idx)?;
                    match build_record_entry(entry, partition_key) {
                        Some(e) => Some((idx, e)),
                        None => {
                            warn!(
                                "Skipping log entry at index {} — serialisation failed or record exceeds 1 MiB",
                                idx
                            );
                            None
                        }
                    }
                })
                .collect();

            if entries.is_empty() {
                // Nothing sendable remains (e.g. all oversized)
                return Ok(());
            }

            let records: Vec<PutRecordsRequestEntry> =
                entries.iter().map(|(_, e)| e.clone()).collect();

            let response = self
                .client
                .put_records()
                .stream_name(&self.config.stream_name)
                .set_records(Some(records))
                .send()
                .await
                .map_err(|e| {
                    AuditError::Kinesis(format!(
                        "PutRecords API call failed on attempt {}: {}",
                        attempt, e
                    ))
                })?;

            let failed_count = response.failed_record_count().unwrap_or(0);

            if failed_count == 0 {
                debug!("Batch delivered: {} records", entries.len());
                return Ok(());
            }

            // Identify which records failed
            let record_results = response.records();
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
                "Attempt {}/{}: {} of {} records failed in stream '{}'",
                attempt,
                self.config.max_retries,
                failed_indices.len(),
                entries.len(),
                self.config.stream_name,
            );

            if attempt >= self.config.max_retries {
                error!(
                    "Kinesis delivery failed after {} retries: {} records could not be written to stream '{}'",
                    self.config.max_retries,
                    failed_indices.len(),
                    self.config.stream_name,
                );
                return Err(AuditError::Kinesis(format!(
                    "{} records failed after {} retries in stream '{}'",
                    failed_indices.len(),
                    self.config.max_retries,
                    self.config.stream_name,
                )));
            }

            // Exponential backoff: 100ms, 200ms, 400ms, …
            let delay_ms = RETRY_BASE_DELAY_MS
                .saturating_mul(2u64.saturating_pow(u32::try_from(attempt).unwrap_or(u32::MAX)));
            debug!("Backing off {}ms before retry", delay_ms);
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

            pending = failed_indices;
        }
    }
}

/// Serialise a single log entry into a `PutRecordsRequestEntry`.
///
/// Returns `None` if serialisation fails or the record exceeds the Kinesis 1 MiB limit.
fn build_record_entry(
    entry: &serde_json::Value,
    partition_key: &str,
) -> Option<PutRecordsRequestEntry> {
    let json_bytes = serde_json::to_vec(entry).ok()?;

    if json_bytes.len() > MAX_RECORD_SIZE_BYTES {
        warn!(
            "Log entry is {} bytes — exceeds Kinesis 1 MiB record limit, skipping",
            json_bytes.len()
        );
        return None;
    }

    PutRecordsRequestEntry::builder()
        .data(Blob::new(json_bytes))
        .partition_key(partition_key)
        .build()
        .ok()
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

    #[test]
    fn record_entry_serialises_correctly() {
        let entry = json!({"event": "login", "user": "alice"});
        let result = build_record_entry(&entry, "test-partition-key");
        let record = result.expect("expected Some for a valid entry");
        assert_eq!(record.partition_key(), "test-partition-key");
        let bytes = record.data().as_ref();
        let parsed: serde_json::Value =
            serde_json::from_slice(bytes).expect("data should be valid JSON");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn record_entry_rejects_oversized() {
        // A bare JSON string serialises as `"...chars..."` (+2 bytes for quotes).
        // Using MAX_RECORD_SIZE_BYTES chars pushes the total to MAX + 2, exceeding the limit.
        let big_string = "x".repeat(MAX_RECORD_SIZE_BYTES);
        let entry = json!(big_string);
        assert!(build_record_entry(&entry, "key").is_none());
    }

    #[test]
    fn config_uses_default_retries_when_env_unset() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("VERAAUDIT_KINESIS_RETRIES") };
        let config = KinesisConfig::new("my-stream".to_string(), None);
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn config_reads_retries_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("VERAAUDIT_KINESIS_RETRIES", "7") };
        let config = KinesisConfig::new("my-stream".to_string(), None);
        unsafe { std::env::remove_var("VERAAUDIT_KINESIS_RETRIES") };
        assert_eq!(config.max_retries, 7);
    }

    #[test]
    fn config_falls_back_on_invalid_env_value() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("VERAAUDIT_KINESIS_RETRIES", "not-a-number") };
        let config = KinesisConfig::new("my-stream".to_string(), None);
        unsafe { std::env::remove_var("VERAAUDIT_KINESIS_RETRIES") };
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }
}
