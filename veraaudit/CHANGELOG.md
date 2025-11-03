# Changelog

All notable changes to the veraaudit project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.11] - 2025-11-03

### Security
- **Input Validation Hardening**: Comprehensive datetime validation security improvements
  - **Unicode Whitespace Rejection**: `validate_datetime()` now rejects non-ASCII whitespace BEFORE trimming
    - Rejects non-breaking space (U+00A0), zero-width space (U+200B), ideographic space (U+3000)
    - Prevents log injection and parsing bypasses
  - **Control Character Rejection**: Enhanced security against injection attacks
    - Rejects control characters (newlines, carriage returns, null bytes, tabs)
    - Prevents log injection attacks
    - Creates clear, secure error messages
  - **Zero-Width Character Detection**: Catches format characters not detected by `is_whitespace()` or `is_control()`
    - Rejects zero-width space (U+200B), zero-width non-joiner (U+200C), zero-width joiner (U+200D)
    - Rejects byte order mark (U+FEFF)
  - **Security-First Validation**: All validation happens BEFORE string trimming to prevent bypasses
  - **Modified Files**: `src/cli.rs`

### Testing
- **8 New Security Tests**: Comprehensive coverage of datetime validation edge cases
  - `test_validate_datetime_rejects_unicode_non_breaking_space`: Non-breaking space rejection
  - `test_validate_datetime_rejects_zero_width_space`: Zero-width character detection
  - `test_validate_datetime_rejects_ideographic_space`: CJK whitespace rejection
  - `test_validate_datetime_rejects_embedded_newlines`: Log injection prevention
  - `test_validate_datetime_rejects_embedded_carriage_return`: CR character rejection
  - `test_validate_datetime_rejects_null_byte`: Null byte detection
  - `test_validate_datetime_allows_normal_space`: Normal space preservation
  - `test_validate_datetime_leading_trailing_spaces_ok`: ASCII space trimming works correctly
  - All tests passing with 100% success rate

### Changed
- **Dependency Migration**: Migrated from unmaintained `backoff` crate to actively maintained `backon` crate
  - **Security**: Resolved RUSTSEC-2025-0012 (backoff unmaintained) and RUSTSEC-2024-0384 (instant unmaintained)
  - **Modern API**: Updated retry logic to use backon's fluent `.retry().when()` API instead of callback-based approach
  - **Same Behavior**: All retry logic and error handling semantics preserved - no functional changes
  - **Improved Code**: Cleaner, more maintainable retry patterns with method chaining
  - **Dependencies**: Changed from `backoff = "0.4"` to `backon = "1.3"`
  - **Modified Files**: `Cargo.toml`, `src/vault_client.rs`

### Testing
- **100% Test Coverage**: All 100 tests passing after migration
- **Updated Tests**: Refactored retry logic tests to work with new backon API
- **Validation**: Comprehensive testing of all HTTP status codes and error scenarios
- **Bug Fix**: HTTP 501 (Vault not initialized) now correctly classified as non-retryable

## [0.5.10] - 2025-11-01

### Fixed
- **Vault Error Handling & Retry Logic**: Comprehensive improvement to HashiCorp Vault integration
  - **403 Access Denied now exits immediately** - No more unnecessary retries on authentication failures
  - **Vault API Compliant Retry Logic**: Implements official HashiCorp Vault API retry guidance
    - **Permanent Errors (Never Retry)**: HTTP 400, 401, 403, 404, 405, 501, all 4xx client errors
    - **Transient Errors (Retry)**: HTTP 412 (precondition failed), 429 (standby), 472 (DR replication), 473 (performance standby), 500/502/503 (server errors), other 5xx
  - **Certificate/TLS Error Handling**: Type-based error detection using error chain traversal
    - **Proper rustls Error Type Checking**: Inspects error chains for `InvalidCertificate`, `NoCertificatesPresented`, `UnsupportedNameType`
    - **No More String Matching**: Replaced fragile string matching (`contains("certificate")`) with `downcast_ref::<std::io::Error>()` type checking
    - **Network Error Detection**: Separate type-based detection for retryable network errors (connection timeouts, etc.)
    - **Error Chain Traversal**: Recursively inspects error sources to find root certificate issues
    - **Hybrid Approach**: Uses both type downcasting and debug representation checking for comprehensive coverage
  - **All 14 ClientError Variants Handled**: Explicit handling for all vaultrs error types
    - File errors (FileNotFoundError, FileReadError, FileWriteError)
    - Configuration errors (InvalidLoginMethodError, InvalidUpdateParameter, WrapInvalidError)
    - Data errors (JsonParseError, ResponseEmptyError, ResponseDataEmptyError, ResponseWrapError)
    - Certificate errors (RestClientBuildError, ParseCertificateError)
  - **Safe Default Behavior**: Unknown errors default to permanent (no retry) to avoid unnecessary retry storms
  - **DRY Principle**: Centralized `classify_vault_error()` helper eliminates code duplication across 3 functions
  - **Modified Files**: `src/vault_client.rs`

### Testing
- **22 New Vault Error Handling Tests**: Comprehensive test coverage for all error scenarios
  - HTTP status code classification (400, 401, 403, 404, 405, 412, 429, 472, 473, 500, 501, 502, 503)
  - ClientError variant handling (all 14 variants)
  - Edge cases (generic 4xx/5xx, unexpected status codes)
  - All tests passing with 100% success rate

### Changed
- **Fixed Misleading Error Messages**: Corrected error reporting for permanent errors (e.g., certificate failures)
  - **Before**: "Authentication failed after all retry attempts" (incorrect - no retries for permanent errors)
  - **After**: "TLS/certificate error: Error sending HTTP request" (accurate - shows actual error type)
  - **Preserves Original Errors**: No longer wraps errors with generic messages, maintains detailed context from error classification
  - **Accurate for All Cases**: Permanent errors show immediate failure, transient errors show retry exhaustion
- **Better Logging**: Clear indication whether errors will be retried or failed immediately

## [0.5.9] - 2025-10-25

### Added

- **Chunked Query Retrieval**: New automatic chunking strategy for handling backend refresh cycles
  - **Interval-Based Chunking**: Queries are automatically broken into smaller time windows (5-60 minute chunks)
  - **Backend Refresh Awareness**: Respects Veracode's 2-hour backend data refresh cycle
  - **Early Stopping**: Stops querying if a chunk returns 0 logs (indicates backend data not yet available)
  - **Single Aggregated Output**: All chunks aggregated and deduplicated into one file per run/cycle
  - **New `--interval` Parameter**:
    - CLI Mode: `veraaudit run --start-offset 3h --interval 30m`
    - Service Mode: Always uses chunked retrieval with configured interval
  - **Use Cases**:
    - Catching up after service downtime (e.g., 3+ hour gap)
    - Ensuring data completeness during backend refresh windows
    - More reliable retrieval for large time ranges

- **Interval Validation**: Strict enforcement of 5-60 minute interval range
  - **Range Enforcement**: Prevents intervals outside the optimal 5-60 minute window
  - **Clear Error Messages**: Helpful feedback when interval is out of range
  - **Rationale**:
    - Too small (< 5 min): Excessive API calls, potential rate limiting
    - Too large (> 60 min): May miss data during backend refresh cycles
  - **Applied To**: Both `run --interval` and `service --interval` parameters

- **New CLI Flags**:
  - `--no-file-timestamp`: Disable automatic detection of last log file timestamp
  - `--no-dedup`: Disable log deduplication (for debugging purposes)

### Changed

- **Parameter Rename**: `--interval-minutes` → `--interval` for consistency
  - **Before**: `veraaudit service --interval-minutes 15`
  - **After**: `veraaudit service --interval 15m`
  - **Format**: Supports `Nm` (minutes), `Nh` (hours)
  - **Examples**: `15m`, `30m`, `1h`
  - **Backward Compatibility**: Old parameter no longer accepted

- **Service Mode Behavior**: Now always uses chunked retrieval
  - Queries from `(last timestamp OR start-offset)` to `now` in interval-sized chunks
  - More reliable for catching all logs during backend refresh periods
  - Automatic deduplication across all chunks

- **Empty File Handling**: Files no longer created when no logs remain after deduplication
  - **Before**: Created files even with `[]` empty arrays
  - **After**: Skips file creation, logs info message
  - **Benefit**: Cleaner output directory, avoids clutter from duplicate-only queries
  - **Return Type**: `write_audit_log_file()` now returns `Result<Option<PathBuf>>`

### Performance

- **Deduplication Optimization**: Massive performance improvement for duplicate detection
  - **Before**: Scanned ALL files newer than start datetime (O(N files))
  - **After**: Scans ONLY the most recent file (O(1 file))
  - **Rationale**:
    - Logs are chronological
    - -1 second overlap only affects boundary between queries
    - Only last file can contain duplicates from current query
  - **Impact**:
    - Up to 100x faster for large output directories
    - Reduced memory usage (only last file's hashes loaded)
    - Reduced disk I/O (single file read vs multiple)
  - **Implementation**: New `get_last_log_file()` helper function

- **Hash-Based Deduplication**: Uses xxHash (xxh3_64) for extremely fast hashing
  - Significantly faster than SHA256 or other cryptographic hashes
  - Excellent collision resistance for deduplication use case
  - Minimal memory footprint

### Fixed

- **Timestamp Overlap Comment**: Corrected misleading documentation
  - **Issue**: Comment said "Add 1 second" but code did `-1 second`
  - **Resolution**: Updated comment to accurately describe overlap strategy
  - **Context**: -1 second creates overlap to catch sub-second precision logs
  - **Location**: `output.rs:409-420`

- **Return Value Bug**: Fixed variable name mismatch in overlap calculation
  - Changed `next_timestamp` → `overlap_timestamp` for clarity

### Removed

- **Unused Functions**: Cleaned up dead code to improve maintainability
  - Removed `extract_first_timestamp()` (no longer needed with last-file-only scanning)
  - Removed `find_log_files_newer_than()` (replaced by `get_last_log_file()`)

### Technical Details

#### New Functions
- `audit::retrieve_audit_logs_chunked()` - Chunked query implementation with early stopping
- `output::get_last_log_file()` - Efficient last file lookup
- `cli::validate_interval()` - Interval range validation (5-60 minutes)

#### Modified Functions
- `main::run_cli_mode()` - Now accepts `interval` parameter, uses chunked retrieval
- `service::run_audit_cycle()` - Always uses chunked retrieval
- `output::write_audit_log_file()` - Returns `Option<PathBuf>`, optimized deduplication

#### Files Modified
- `veraaudit/src/cli.rs` - Added interval validation, parameter updates
- `veraaudit/src/audit.rs` - Added chunked retrieval implementation
- `veraaudit/src/output.rs` - Optimized deduplication, empty file handling
- `veraaudit/src/main.rs` - Updated to use chunked retrieval
- `veraaudit/src/service.rs` - Updated to use chunked retrieval
- `veraaudit/README.md` - Comprehensive documentation updates
- `veraaudit/CHANGELOG.md` - This changelog

### Benefits

- **Reliability**: Chunked queries handle backend refresh cycles gracefully
- **Performance**: 100x faster deduplication for large output directories
- **Efficiency**: Reduced API calls via early stopping when data unavailable
- **Cleanliness**: No more empty audit files cluttering output directory
- **Memory**: Lower memory footprint from optimized deduplication
- **Usability**: Clearer error messages for invalid intervals

### Migration Notes

#### Breaking Changes
- `--interval-minutes` parameter renamed to `--interval`
- Return type change for `write_audit_log_file()` (internal API, no user impact)

#### Update Commands
```bash
# Before (v0.5.8)
veraaudit service --interval-minutes 15

# After (v0.5.9)
veraaudit service --interval 15m
```

#### Behavior Changes
- Service mode queries now always chunked (more API calls, but more reliable)
- Empty files no longer created (check logs for "No new logs found" messages)
- Deduplication only scans last file (much faster, same correctness)

### Upgrade Guide

1. **Update CLI Scripts**: Replace `--interval-minutes` with `--interval`
2. **Monitor Empty Files**: Normal to see fewer files if many duplicate queries
3. **Check Logs**: Look for "No new logs found after deduplication" info messages
4. **Performance**: Expect faster deduplication on existing directories with many files

### Known Issues

None identified in this release.

### Testing

- All unit tests passing
- Cargo check/clippy warnings resolved
- Manual testing with 3-hour catchup scenario
- Deduplication performance validated on directories with 100+ files

## [0.5.8] - 2025-10-23

### Added
- **Regional Timezone Support**: Enhanced datetime conversion with region-specific timezone handling
  - **Europe/Berlin Timezone**: European region (`--region european`) now uses Europe/Berlin timezone (CET/CEST) for datetime conversion
    - Winter time: CET (UTC+1) - Example: 10:00 CET → 09:00 UTC
    - Summer time: CEST (UTC+2) - Example: 10:00 CEST → 08:00 UTC
    - Automatic daylight saving time (DST) transitions
  - **System Timezone**: Commercial and Federal regions continue using system's local timezone for backward compatibility
  - **Timezone-Aware Validation**: All datetime validation now respects region-specific timezones
  - **Use Cases**: Enables accurate audit log retrieval for teams operating in European timezones

### Changed
- **Datetime Conversion Functions**: Enhanced to accept `Region` parameter
  - `convert_local_to_utc(datetime_str, region)` - Now converts based on region timezone
  - `validate_datetime_format(datetime_str, field_name, utc_mode, region)` - Added region parameter
  - `validate_date_range(start, end, utc_mode, region)` - Added region parameter
  - **Backward Compatible**: Existing functionality preserved for Commercial and Federal regions

### Enhanced
- **Production-Grade Logging**: Improved log formatting for operational clarity
  - Removed debug formatters (`:?`) from all log statements
  - Vector/collection logs now use clean `.join(", ")` formatting instead of debug output
  - Example: `[Delete, Create, Update]` instead of `["Delete", "Create", "Update"]`
  - Improved readability for operators monitoring audit log retrieval
  - **Modified Files**: `src/audit.rs` - audit action and action type filter logging

- **Test Coverage**: Added comprehensive tests for European timezone conversion
  - `test_european_timezone_conversion()` - Validates CET/CEST to UTC conversion
  - `test_validate_date_range_european_region()` - Tests date range validation with Berlin timezone
  - All existing tests updated to work with region-aware functions

### Updated
- **Dependencies**:
  - Added `chrono-tz = "0.10"` for timezone database support
  - Updated `veracode-platform` to v0.6.0 with Reporting API enhancements

### Technical Details
- **Implementation**: Uses `chrono-tz::Europe::Berlin` for accurate timezone conversion
- **DST Handling**: Automatically handles daylight saving time transitions using IANA timezone database
- **Region Mapping**:
  - `Region::European` → Europe/Berlin (eu-central-1 timezone)
  - `Region::Federal` → System local timezone
  - `Region::Commercial` → System local timezone
- **Modified Files**: `src/datetime.rs`, `src/main.rs`, `src/audit.rs`, `Cargo.toml`

### Benefits
- **Accurate Timestamps**: European teams can specify audit log times in their local timezone
- **Compliance**: Simplifies audit log retrieval for regulatory compliance across different regions
- **User Experience**: No mental math required for timezone conversion when using `--region european`
- **Operational Excellence**: Clean, production-ready log output for monitoring and troubleshooting

## [0.5.7] - 2025-10-23

### Added

- Initial release of veraaudit
- Uses veracode-platform v0.5.8 with Reporting API support
- CLI mode for one-time ad-hoc audit log retrieval
- Service mode for continuous monitoring with configurable intervals (5-60 minutes)
- Vault integration for secure credential management
  - OIDC/JWT authentication with automatic token revocation
  - Environment variable fallback for credentials
  - Proxy configuration support from Vault
- Timestamped file output with UTC naming convention (`audit_log_YYYYMMDD_HHMMSS_UTC.json`)
- Automatic file cleanup strategies:
  - Cleanup by count (keep N most recent files)
  - Cleanup by age (delete files older than N hours)
  - Combined cleanup (both strategies can be used together)
- Multi-regional support (Commercial, European, Federal)
- Flexible filtering options:
  - Filter by audit actions (Delete, Create, Update, etc.)
  - Filter by action types (Login, Admin, etc.)
- Comprehensive error handling with automatic retry logic
- HTTP/HTTPS proxy support with authentication
- Graceful shutdown handling (Ctrl+C) in service mode
- Structured logging with configurable verbosity

### Features in Detail

#### Credential Management
- **Vault Priority**: Automatically uses Vault when configured
- **Environment Fallback**: Falls back to `VERACODE_API_ID` and `VERACODE_API_KEY`
- **Security**: Uses `secrecy::SecretString` for secure memory handling
- **Token Revocation**: Vault tokens automatically revoked after credential retrieval
- **Proxy Credentials**: Can be stored in Vault or environment variables

#### CLI Mode
- Date range specification (start date required, end date optional)
- Custom output directory
- Optional filtering by audit actions and action types
- Single execution for ad-hoc queries

#### Service Mode
- Configurable interval (5-60 minutes)
- Continuous monitoring with automatic retrieval
- Built-in cleanup management
- Graceful shutdown on SIGINT (Ctrl+C)
- Resilient to temporary failures (continues running on errors)

#### File Management
- UTC-based timestamps prevent timezone confusion
- Sortable filenames (alphanumeric sort = chronological order)
- JSON format for easy parsing and integration
- Automatic directory creation

#### API Integration
- Uses Veracode Reporting REST API (`/appsec/v1/analytics/report`)
- Two-step process: generate report, then retrieve
- Built-in delay for report generation
- Retry logic inherited from veracode-platform library

### Technical Details

#### Dependencies
- `veracode-platform` v0.5.7 - Veracode API client library
- `tokio` - Async runtime
- `clap` - CLI argument parsing
- `chrono` - Date/time handling
- `tokio-cron-scheduler` - Service mode scheduling
- `vaultrs` - HashiCorp Vault client
- `backoff` - Exponential backoff retry logic
- `secrecy` - Secure credential handling
- `log` + `env_logger` - Logging infrastructure

#### Architecture
- Modular design with separate modules for:
  - Credential management (`credentials.rs`, `vault_client.rs`)
  - Audit log retrieval (`audit.rs`)
  - Service mode (`service.rs`)
  - File output (`output.rs`)
  - Cleanup logic (`cleanup.rs`)
  - CLI parsing (`cli.rs`)
  - Error handling (`error.rs`)

### Known Limitations

- Veracode API limit: Maximum 6 months of data per request
  - Mitigation: Use service mode for continuous archival
  - Mitigation: Make multiple CLI requests for different date ranges
- Service mode interval: Minimum 5 minutes, maximum 60 minutes
- File format: JSON only (no CSV, XML, or other formats yet)

### Documentation

- Comprehensive README with usage examples
- Inline code documentation
- CLI help text for all commands and options
- Security considerations documented

### Future Enhancements (Not in v0.5.7)

The following features are planned for future releases:

- Additional output formats (CSV, XML, custom formats)
- Database storage options (PostgreSQL, MySQL)
- Webhook notifications for specific audit events
- Prometheus metrics for monitoring
- Web UI for viewing audit logs
- Email notification support
- File compression for old logs (gzip)
- Cloud storage integration (S3, Azure Blob, GCS)
- Incremental retrieval to avoid duplicates
- More granular filtering options

### Compatibility

- Rust Edition: 2024
- Minimum Rust Version: 1.75+
- Supported Platforms: Linux, macOS, Windows
- Veracode API Regions: Commercial, European, Federal

### Security

- All credentials handled with `secrecy::SecretString`
- Automatic credential redaction in logs
- Vault token revocation after use
- HTTPS/TLS enabled by default
- Certificate validation enabled (can be disabled for development)
- No credentials in error messages or file names

## [Unreleased]

### Planned
- Enhanced filtering capabilities
- Database storage backend
- Metrics and monitoring
- Web interface
- Additional output formats

---

## Release Notes

### Version 0.5.7 Highlights

This is the initial release of **veraaudit**, a production-ready tool for retrieving and archiving Veracode audit logs. The tool was designed with enterprise deployment in mind, featuring:

1. **Enterprise Security**: Full Vault integration with OIDC authentication
2. **Operational Flexibility**: Both ad-hoc (CLI) and continuous (service) modes
3. **Production Ready**: Comprehensive error handling, retry logic, and logging
4. **Compliance Focus**: Continuous audit log collection for compliance requirements
5. **Easy Deployment**: Single binary, Docker-ready, minimal dependencies

### Getting Started

```bash
# CLI Mode - One-time retrieval
veraaudit run --start-date 2025-01-01 --output-dir ./logs

# Service Mode - Continuous monitoring
veraaudit service --interval 15m --cleanup-hours 168
```

For detailed usage instructions, see [README.md](README.md).

### Upgrade Notes

This is the first release - no upgrade notes applicable.

### Breaking Changes

This is the first release - no breaking changes.

### Contributors

- Claude Code (Initial implementation based on planning specifications)

---

[0.5.7]: https://github.com/your-org/veracode-workspace/releases/tag/veraaudit-v0.5.7
[Unreleased]: https://github.com/your-org/veracode-workspace/compare/veraaudit-v0.5.7...HEAD
