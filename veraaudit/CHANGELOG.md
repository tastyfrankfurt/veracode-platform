# Changelog

All notable changes to the veraaudit project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
veraaudit service --interval-minutes 15 --cleanup-hours 168
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
