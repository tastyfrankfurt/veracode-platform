#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::json;
use std::hint::black_box;
use veraaudit::output::write_audit_log_file;
use veraaudit::test_utils::TempDir;

/// Generate realistic audit log entries
fn generate_audit_logs(count: usize) -> serde_json::Value {
    let mut logs = Vec::new();

    let actions = ["Create", "Update", "Delete", "Login", "Logout"];
    let action_types = ["User", "Admin", "System", "API"];

    for i in 0..count {
        #[allow(clippy::arithmetic_side_effects)] // benchmark data generation, won't overflow
        let timestamp = format!(
            "2025-01-{:02} {:02}:{:02}:{:02}",
            (i / 86400) % 28 + 1, // Day
            (i / 3600) % 24,      // Hour
            (i / 60) % 60,        // Minute
            i % 60                // Second
        );

        let action = actions[i % 5];
        let action_type = action_types[i % 4];

        let log = json!({
            "timestamp_utc": timestamp,
            "action": action,
            "action_type": action_type,
            "username": format!("user_{}", i % 100),
            "resource": format!("resource_{}", i % 50),
            "details": format!("Action performed on resource by user at {}", timestamp),
            "ip_address": format!("192.168.{}.{}", (i / 256) % 256, i % 256),
            "status": "Success",
            "metadata": {
                "request_id": format!("req_{}", i),
                "session_id": format!("sess_{}", i % 1000),
                "application": "veracode-platform"
            }
        });

        logs.push(log);
    }

    json!(logs)
}

/// Benchmark `write_audit_log_file` without deduplication
fn bench_write_no_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_no_dedup");

    for size in [100, 1_000, 10_000, 100_000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let temp_dir = TempDir::new().unwrap();
                let output_dir = temp_dir.path().to_str().unwrap();
                let data = generate_audit_logs(size);

                write_audit_log_file(
                    black_box(output_dir),
                    black_box(data),
                    black_box(true), // skip_dedup = true
                    black_box(None),
                )
                .unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark `write_audit_log_file` with deduplication (no duplicates)
fn bench_write_with_dedup_no_duplicates(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_dedup_no_duplicates");

    for size in [100, 1_000, 10_000].iter() {
        // Smaller sizes for dedup
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let temp_dir = TempDir::new().unwrap();
                let output_dir = temp_dir.path().to_str().unwrap();
                let data = generate_audit_logs(size);

                write_audit_log_file(
                    black_box(output_dir),
                    black_box(data),
                    black_box(false), // skip_dedup = false
                    black_box(None),
                )
                .unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark `write_audit_log_file` with deduplication (50% duplicates)
fn bench_write_with_dedup_50_percent(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_dedup_50_percent");

    for size in [100, 1_000, 10_000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(
                || {
                    // Setup: create temp dir and previous file with 50% overlap
                    let temp_dir = TempDir::new().unwrap();
                    let output_dir = temp_dir.path().to_str().unwrap().to_string();

                    // Create previous file with first 50% of logs
                    let previous_data = generate_audit_logs(size / 2);
                    write_audit_log_file(
                        &output_dir,
                        previous_data,
                        true, // skip_dedup for setup
                        None,
                    )
                    .unwrap();

                    // Create new data that overlaps 50% with previous
                    let new_data = generate_audit_logs(size);

                    (temp_dir, output_dir, new_data)
                },
                |(temp_dir, output_dir, data)| {
                    // Benchmark: write with deduplication
                    write_audit_log_file(
                        black_box(&output_dir),
                        black_box(data),
                        black_box(false), // enable dedup
                        black_box(None),
                    )
                    .unwrap();
                    drop(temp_dir);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark hash computation
fn bench_hash_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_computation");

    let log = json!({
        "timestamp_utc": "2025-01-15 14:30:00",
        "action": "Login",
        "username": "test_user",
        "details": "User logged in successfully"
    });

    group.bench_function("compute_hash", |b| {
        b.iter(|| {
            // This would call the hash function - adjust based on actual API
            let json_str = serde_json::to_string(&log).unwrap();
            black_box(xxhash_rust::xxh3::xxh3_64(json_str.as_bytes()))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_write_no_dedup,
    bench_write_with_dedup_no_duplicates,
    bench_write_with_dedup_50_percent,
    bench_hash_computation
);

criterion_main!(benches);
