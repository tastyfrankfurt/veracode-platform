# veraaudit

CLI tool for retrieving and archiving Veracode audit logs using the Reporting REST API.

## Features

- 🔐 **Secure Credential Management** - Vault integration with environment variable fallback
- 📊 **Two Operation Modes**:
  - **CLI Mode**: One-time ad-hoc audit log retrieval
  - **Service Mode**: Continuous monitoring with configurable intervals (5-60 minutes)
- 📁 **Timestamped Output** - Automatic file naming with UTC timestamps
- 🧹 **Automatic Cleanup** - File retention by count or age
- 🌍 **Multi-Regional Support** - Commercial, European, and Federal regions
- 🔍 **Flexible Filtering** - Filter by audit actions and action types
- 🔄 **Robust Error Handling** - Automatic retries with exponential backoff
- ⚡ **Optimized Deduplication** - Fast hash-based deduplication scanning only the most recent file
- 🔁 **Chunked Retrieval** - Automatic chunking to handle backend refresh cycles (respects 2-hour data refresh window)
- 🎯 **Smart File Management** - Skips writing empty files after deduplication

## Installation

### From Source

```bash
cargo build --release --package veraaudit
```

The binary will be available at `target/release/veraaudit`.

## Usage

### CLI Mode (One-Time Retrieval)

Retrieve audit logs for a specific datetime range:

```bash
# With explicit datetime range
veraaudit run \
  --start "2025-01-01 10:00:00" \
  --end "2025-01-21 18:30:00" \
  --output-dir ./audit_logs

# Or use defaults (last 60 minutes)
veraaudit run

# Use time offset for start (easier than calculating exact datetime)
veraaudit run --start-offset 2h    # Last 2 hours
veraaudit run --start-offset 7d    # Last 7 days
veraaudit run --start-offset 30m   # Last 30 minutes

# Use interval for chunked retrieval (recommended for large time ranges)
veraaudit run --start-offset 3h --interval 30m   # Query last 3 hours in 30-min chunks
```

**New: Chunked Retrieval**

When using the `--interval` parameter, veraaudit automatically breaks large time ranges into smaller chunks:
- Respects backend refresh cycles (queries in smaller windows)
- Stops early if data not yet available (backend still refreshing)
- Single aggregated output file per run
- Optimal for catching up after downtime or large time windows

#### CLI Mode Options

- `--start` - Start datetime (formats: `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`)
  - Optional, defaults to 60 minutes before end time
  - **Default**: Interpreted as local timezone (converted to UTC for API)
  - **With `--utc`**: Treated as UTC (no conversion)
  - **Cannot be used with `--start-offset`**
- `--start-offset` - Start time as offset from now (formats: `Nm`, `Nh`, `Nd`)
  - Optional, computes start as current time minus offset
  - Examples: `30m` (30 minutes), `2h` (2 hours), `7d` (7 days)
  - Unit can be omitted, defaults to minutes: `30` = `30m`
  - **Cannot be used with `--start`**
- `--end` - End datetime (same formats as `--start`)
  - Optional, defaults to current time
  - **Default**: Interpreted as local timezone (converted to UTC for API)
  - **With `--utc`**: Treated as UTC (no conversion)
  - **Cannot be used with `--interval`**
- `--interval` - Interval/chunk size for queries (formats: `Nm`, `Nh`)
  - Optional, enables chunked retrieval mode
  - **Range: 5-60 minutes** (enforced)
  - Examples: `15m`, `30m`, `1h`
  - When specified, queries are broken into interval-sized chunks
  - Stops early if a chunk returns 0 logs (backend not ready)
  - **Cannot be used with `--end`**
- `--output-dir` - Output directory for audit log files (default: `./audit_logs`)
- `--audit-action` - Filter by audit actions. Can be specified multiple times. **Valid values:**
  - `Create`, `Delete`, `Update`, `Error`, `Email`, `Success`, `Failed`
  - `Locked`, `Unlocked`, `"Logged out"`, `Undelete`
  - `"Maintain Schedule"`, `"Permanent Delete"`, `"Update for Internal Only"`
- `--action-type` - Filter by action types. Can be specified multiple times. **Valid values:**
  - `"Login Account"`, `Admin`, `Auth`, `Login`
- `--region` - Veracode region (default: `commercial`). **Valid values:**
  - `commercial`, `european`, `federal`
- `--utc` - Treat input datetimes as UTC instead of local timezone (optional switch)
- `--no-file-timestamp` - Disable automatic detection of last log file timestamp (optional switch)
- `--no-dedup` - Disable log deduplication (optional switch)

### Service Mode (Continuous Monitoring)

Run continuously with automatic retrieval and cleanup:

```bash
veraaudit service \
  --interval 15m \
  --output-dir ./audit_logs \
  --cleanup-count 100 \
  --cleanup-hours 72
```

**Service Mode Behavior**:
- Queries are automatically chunked using the configured interval
- Each cycle queries from last log timestamp (or start-offset) to now
- Respects backend refresh cycles by stopping if data not yet available
- Automatic deduplication prevents duplicate log entries
- Skips writing files when no new logs are found

#### Service Mode Options

- `--interval` - Query interval and chunk size (formats: `Nm`, `Nh`)
  - **Range: 5-60 minutes** (enforced) (default: `15m`)
  - Service runs every interval duration and uses this for chunked queries
  - Examples: `15m`, `30m`, `1h`
- `--start-offset` - How far back to start querying on first run (formats: `Nm`, `Nh`, `Nd`)
  - Optional, defaults to `15m`
  - Examples: `30m`, `2h`, `7d`
- `--output-dir` - Output directory for audit log files (default: `./audit_logs`)
- `--cleanup-count` - Keep only the last N files, **must be > 0** (optional)
- `--cleanup-hours` - Delete files older than N hours, **must be > 0** (optional)
- `--audit-action` - Filter by audit actions. Can be specified multiple times. **Valid values:**
  - `Create`, `Delete`, `Update`, `Error`, `Email`, `Success`, `Failed`
  - `Locked`, `Unlocked`, `"Logged out"`, `Undelete`
  - `"Maintain Schedule"`, `"Permanent Delete"`, `"Update for Internal Only"`
- `--action-type` - Filter by action types. Can be specified multiple times. **Valid values:**
  - `"Login Account"`, `Admin`, `Auth`, `Login`
- `--region` - Veracode region (default: `commercial`). **Valid values:**
  - `commercial`, `european`, `federal`
- `--no-file-timestamp` - Disable automatic detection of last log file timestamp (optional switch)
- `--no-dedup` - Disable log deduplication (optional switch)

## Timezone Handling

### Input Timezone Behavior

By default, veraaudit interprets datetime inputs (`--start` and `--end`) in your **system's local timezone** and automatically converts them to UTC before sending to the Veracode API.

**Default Behavior (Local Timezone)**:
```bash
# If your system is in EST (UTC-5), this command:
veraaudit run --start "2025-01-15 10:00:00"
# Is interpreted as: 2025-01-15 10:00:00 EST
# Converted to UTC: 2025-01-15 15:00:00 UTC
# Sent to API: start_date=2025-01-15 15:00:00
```

**UTC Mode (with `--utc` flag)**:
```bash
# With --utc flag, datetime is treated as already in UTC:
veraaudit run --start "2025-01-15 10:00:00" --utc
# Interpreted as: 2025-01-15 10:00:00 UTC (no conversion)
# Sent to API: start_date=2025-01-15 10:00:00
```

### Output Timezone Information

The Veracode API returns audit log timestamps in **US-East-1 timezone** (America/New_York). veraaudit automatically adds a converted UTC timestamp to each log entry:

```json
{
  "action": "Delete",
  "timestamp": "2025-10-15 22:46:17.498",      // Original from API (US-East-1)
  "timestamp_utc": "2025-10-16 02:46:17.498",  // Converted to UTC
  "action_detail": "..."
}
```

### Daylight Saving Time (DST)

veraaudit automatically handles DST transitions for US-East-1 timezone:

- **EDT (Eastern Daylight Time)**: UTC-4 (second Sunday in March through first Sunday in November)
- **EST (Eastern Standard Time)**: UTC-5 (first Sunday in November through second Sunday in March)

**Summer Example (EDT)**:
```json
{
  "timestamp": "2025-06-15 14:30:00.000",      // US-East-1 (EDT)
  "timestamp_utc": "2025-06-15 18:30:00.000"   // UTC (+4 hours)
}
```

**Winter Example (EST)**:
```json
{
  "timestamp": "2025-12-15 14:30:00.000",      // US-East-1 (EST)
  "timestamp_utc": "2025-12-15 19:30:00.000"   // UTC (+5 hours)
}
```

### Timezone Best Practices

1. **For Automation**: Use `--utc` flag and provide UTC datetimes for consistent behavior across systems
2. **For Ad-hoc Queries**: Use local timezone (default) for convenience - think in your local time
3. **For Analysis**: Use the `timestamp_utc` field for time-based comparisons and sorting
4. **For Display**: Keep the original `timestamp` field if displaying to users in US-East-1 timezone

## Credential Configuration

veraaudit supports two credential methods with automatic fallback:

### 1. Vault (Priority)

When Vault environment variables are set, credentials are retrieved from Vault:

```bash
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="eyJ..."
export VAULT_CLI_ROLE="veracode-auditor"
export VAULT_CLI_SECRET_PATH="secret/veracode@kvv2"
export VAULT_CLI_NAMESPACE="optional-namespace"  # Optional
export VAULT_CLI_AUTH_PATH="auth/jwt"            # Optional, default: auth/jwt
```

Vault secret should contain:
- `api_id` - Your Veracode API ID
- `api_secret` - Your Veracode API key

### 2. Environment Variables (Fallback)

If Vault is not configured, credentials are read from environment variables:

```bash
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"
```

## Output Format

Audit logs are saved as timestamped JSON files:

```
audit_logs/
├── audit_log_20250121_143052_UTC.json
├── audit_log_20250121_153052_UTC.json
└── audit_log_20250121_163052_UTC.json
```

File naming format: `audit_log_YYYYMMDD_HHMMSS_UTC.json`

**Note**: Files are only created when new logs are found. After deduplication, if no new logs remain, no file is written (avoids empty files).

## File Cleanup

### Cleanup by Count

Keep only the N most recent files:

```bash
veraaudit service \
  --interval 15m \
  --cleanup-count 100
```

This will keep only the 100 most recent audit log files.

### Cleanup by Age

Delete files older than a specified number of hours:

```bash
veraaudit service \
  --interval 15m \
  --cleanup-hours 168  # 7 days
```

### Combined Cleanup

Both strategies can be used together - the more restrictive condition applies:

```bash
veraaudit service \
  --interval 15m \
  --cleanup-count 1000 \
  --cleanup-hours 720  # 30 days
```

## Advanced Configuration

### Proxy Support

Configure HTTP/HTTPS proxy via environment variables:

```bash
export HTTPS_PROXY="http://proxy.example.com:8080"
export PROXY_USERNAME="username"
export PROXY_PASSWORD="password"
```

Proxy credentials can also be stored in Vault with keys:
- `proxy_url`
- `proxy_username`
- `proxy_password`

### Certificate Validation

Disable certificate validation (development only):

```bash
export VERACMEK_DISABLE_CERT_VALIDATION="true"
```

**⚠️ WARNING**: Only use this in development environments with self-signed certificates.

### Logging

Control log verbosity with the `RUST_LOG` environment variable:

```bash
# Info level (default)
RUST_LOG=info veraaudit run --start "2025-01-01"

# Debug level
RUST_LOG=debug veraaudit run --start "2025-01-01"

# Warn level only
RUST_LOG=warn veraaudit run --start "2025-01-01"
```

## Usage Examples

### Example 1: Retrieve Logs Using Time Offset

Retrieve logs from the last 2 hours (easiest method):

```bash
# Last 2 hours
veraaudit run --start-offset 2h

# Last 24 hours
veraaudit run --start-offset 24h
# or equivalently
veraaudit run --start-offset 1d

# Last 7 days
veraaudit run --start-offset 7d

# Last 30 minutes
veraaudit run --start-offset 30m
# or just
veraaudit run --start-offset 30
```

### Example 2: Ad-hoc Compliance Audit

Retrieve last month's audit logs:

```bash
veraaudit run \
  --start "2024-12-01" \
  --end "2024-12-31" \
  --output-dir ./compliance_reports
```

### Example 3: Continuous Monitoring with Vault

Set up Vault credentials and run as service:

```bash
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="eyJ..."
export VAULT_CLI_ROLE="veracode-auditor"
export VAULT_CLI_SECRET_PATH="secret/veracode@kvv2"

veraaudit service \
  --interval 30m \
  --cleanup-hours 168 \
  --output-dir /var/log/veracode-audit
```

### Example 4: High-Frequency Monitoring

Monitor every 5 minutes (minimum interval), keep last 1000 files:

```bash
veraaudit service \
  --interval 5m \
  --cleanup-count 1000 \
  --audit-action Delete \
  --action-type Admin
```

### Example 6: Catching Up After Downtime

If service was down for 3 hours, use chunked retrieval:

```bash
veraaudit run --start-offset 3h --interval 30m --output-dir ./audit_logs
```

This queries the last 3 hours in 30-minute chunks, respecting backend refresh cycles.

### Example 5: Filtered Retrieval

Retrieve only deletion and admin action logs:

```bash
veraaudit run \
  --start "2025-01-01" \
  --audit-action Delete \
  --action-type Admin \
  --output-dir ./admin_deletions
```

## Docker Deployment

### Build Docker Image

Create a `Dockerfile`:

```dockerfile
FROM rust:1.75 as builder
WORKDIR /build
COPY . .
RUN cargo build --release --package veraaudit

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/veraaudit /usr/local/bin/veraaudit
ENTRYPOINT ["veraaudit"]
```

### Run as Docker Container

```bash
docker run -d \
  -v ./audit_logs:/audit_logs \
  -e VERACODE_API_ID=your-id \
  -e VERACODE_API_KEY=your-key \
  veraaudit:latest \
  service --interval 15m --cleanup-count 100
```

## API Limitations

### 6-Month Data Limit

The Veracode Reporting API can return a maximum of **6 months** of data per request.

**Mitigation Strategies**:

1. **Service Mode (Recommended)**: Run continuously to build archive over time
   - After 12 months of service mode, you'll have 12 months of historical data
2. **Multiple CLI Calls**: Make multiple requests with different date ranges
   - Example: Request Jan-Jun, then Jul-Dec separately
3. **Incremental Backfill**: Use service mode and occasionally run CLI mode for older data

## Troubleshooting

### "Missing credentials" error

Ensure either Vault or environment variables are configured:

```bash
# Check Vault variables
echo $VAULT_CLI_ADDR
echo $VAULT_CLI_ROLE

# Or check direct credentials
echo $VERACODE_API_ID
```

### "Invalid date range" error

Ensure dates are in YYYY-MM-DD format and start date is before end date.

### "Rate limit exceeded" error

The tool includes automatic retry logic. If you see this repeatedly, consider:
- Increasing the interval in service mode
- Reducing the frequency of CLI mode calls

### Service mode not starting

Check that interval is within valid range (5-60 minutes):

```bash
veraaudit service --interval 15m  # Valid
veraaudit service --interval 3m   # Invalid (too low)
veraaudit service --interval 2h   # Invalid (too high)
```

### No files being created

If the service is running but not creating files:
- Check logs for "No new logs found after deduplication" messages
- This is normal behavior - files are only created when new logs exist
- Deduplication prevents writing duplicate logs

## Security Considerations

- **Credentials**: All credentials are stored using `secrecy::SecretString` for secure memory handling
- **Vault Tokens**: Automatically revoked after successful credential retrieval
- **Proxy Authentication**: Properly redacted in debug logs
- **File Permissions**: Consider setting restrictive permissions on output directory
- **Network Security**: HTTPS/TLS enabled by default with certificate validation

## Development

### Running Tests

```bash
cargo test --package veraaudit
```

### Building Debug Version

```bash
cargo build --package veraaudit
./target/debug/veraaudit --help
```

### Code Formatting

```bash
cargo fmt --package veraaudit
```

### Linting

```bash
cargo clippy --package veraaudit
```

## Contributing

This tool is part of the veracode-workspace monorepo. Follow the existing patterns for:
- Error handling (thiserror)
- Logging (log + env_logger)
- Async operations (tokio)
- CLI parsing (clap)

## License

MIT OR Apache-2.0

## Performance Optimizations

### Deduplication
- **Fast Hash-Based**: Uses xxHash (xxh3_64) for extremely fast log entry hashing
- **Optimized Scanning**: Only scans the most recent log file (not all files)
- **Memory Efficient**: Loads hashes from single file instead of multiple files
- **Automatic Overlap**: Creates 1-second overlap between queries to catch sub-second logs

### Chunked Retrieval
- **Backend-Aware**: Respects Veracode's 2-hour backend refresh cycle
- **Early Stopping**: Stops querying if chunk returns 0 logs (data not ready)
- **Configurable**: Chunk size (5-60 minutes) balances API calls vs reliability
- **Single Output**: Aggregates all chunks into one deduplicated file

## Version

v0.5.9
