# Verascan

[![Rust](https://img.shields.io/badge/rust-1.70%2B-brightgreen.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Crate Version](https://img.shields.io/badge/version-0.7.0-blue.svg)](Cargo.toml)

A comprehensive Rust CLI application for the Veracode platform to support pipeline, sandbox and policy scan submission and reporting.

## Features

### Intelligent File Discovery
- Recursive directory scanning with glob pattern support
- Smart file type detection using magic bytes (not just extensions)
- Support for JAR, WAR, ZIP, TAR, and various binary formats
- Configurable file filtering and validation

### Security Scanning
- Direct integration with Veracode Pipeline Scan API
- Multi-threaded concurrent file processing (2-10 threads)
- Real-time scan progress monitoring
- Configurable timeouts and retry logic
- Support for all Veracode regions (Commercial, European, Federal)
- **File Size Validation**: Automatic validation with scan-type specific limits
  - **Pipeline Scans**: 200MB per file maximum
  - **Assessment Scans**: 2GB per file maximum + 5GB total cumulative limit
- **Enhanced Security**: Comprehensive secure token handling with automatic credential redaction

### Baseline Comparison
- Create security baselines from scan results
- Compare current scans against historical baselines
- Identify new vulnerabilities and fixed issues
- Hash-based exact finding matching for precision

### Policy Management
- Download and apply Veracode platform policies
- Custom local policy file support
- Pass/fail criteria based on severity levels or CWE IDs
- Combined baseline and policy enforcement
- **Break Build Functionality**: CI/CD integration with Veracode platform policy compliance
  - `--break` flag enables build breaking on policy failures
  - Intelligent API fallback between REST and XML APIs
  - Works with any Veracode account permission level

### Multi-format Export
- **JSON**: Veracode baseline format for future comparisons
- **CSV**: Spreadsheet-compatible findings export
- **GitLab SAST**: Security Dashboard integration
- **Filtered JSON**: Policy violation reports

### Export from Completed Scans
- Findings retrieval from completed Veracode assessment scans
- Policy & Sandbox support
- Server-side filtering and automatic pagination
- Performance optimized with FindingsQuery builder

### GitLab Integration
- Automatic GitLab issue creation for findings
- SAST Security Dashboard reports
- Source code permalinks in issues
- CI/CD pipeline integration

### Performance Optimized
- Concurrent file processing and scan submission
- Efficient memory usage for large file sets
- Progress indicators and detailed logging
- Configurable threading and timeouts

### Production-Grade Security
- **Comprehensive Defensive Programming**: 15+ Clippy security lints enforced
- **Integer Safety**: All arithmetic operations protected with saturating operations
- **Memory Safety**: Zero panic-prone indexing/slicing in production code
- **Error Handling**: No unwrap/expect calls - proper error propagation throughout
- **Property-Based Testing**: 1800+ security tests with proptest fuzzing (WIP)
- **Miri-Validated**: Clean under Rust's undefined behavior detector (WIP)

## Installation

### Prerequisites

- **Rust 1.70+** (for building from source)
- **Veracode API Credentials** ([Generate here](https://docs.veracode.com/r/c_api_credentials3))
- **GitLab Token** (optional, for GitLab features)

### Build from Source

```bash
# From workspace root
cd veracode-workspace
cargo build --release -p verascan

# Binary will be at:
# target/release/verascan
```

### Environment Setup

```bash
# Required: Veracode API credentials
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Optional: GitLab integration
export PRIVATE_TOKEN="your-gitlab-token"
export CI_PROJECT_ID="12345"

# Optional: Development mode (allow HTTP URLs)
export VERASCAN_DISABLE_CERT_VALIDATION="true"
```

## Quick Start

```bash
# Set up authentication
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Run a basic pipeline scan
./target/release/verascan pipeline --filepath . --export-findings results.json

# Run a basic assessment scan
./target/release/verascan assessment --filepath . --app-profile-name "MyApp"

# Export findings from a completed scan
verascan export --app-profile-name "MyApplication" --output findings.json
```

## Usage Examples

### Basic Security Scanning

```bash
# Pipeline scan - current directory for vulnerabilities
verascan pipeline --filepath . --export-findings results.json

# Pipeline scan - specific file types with custom project info
verascan pipeline --filepath ./build \
  --filefilter "*.jar,*.war" \
  --project-name "MyApp-v1.0" \
  --project-url "https://github.com/user/repo" \
  --export-findings scan-results.json
```

### Assessment Scanning

```bash
# Basic assessment scan (policy scan)
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --export-results assessment-results.json

# Sandbox assessment scan
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --sandbox-name "development-sandbox" \
  --export-results sandbox-results.json

# Assessment scan with break build on policy failure
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --break \
  --export-results results.json

# Assessment scan with custom build version
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --build-version "v2.1.0-release" \
  --export-results results.json
```

### Export from Completed Scans

```bash
# Export findings from completed policy scan (default: GitLab SAST format)
verascan export --app-profile-name "MyApplication" \
  --output policy-findings.json

# Export findings from completed sandbox scan
verascan export --app-profile-name "MyApplication" \
  --sandbox-name "development-sandbox" \
  --output sandbox-findings.json

# Export with severity filtering (High and Very High only)
verascan export --app-profile-name "MyApplication" \
  --min-severity "high" \
  --output critical-findings.json

# Export to CSV format
verascan export --app-profile-name "MyApplication" \
  --format csv \
  --output findings.csv
```

### Baseline Security Management

```bash
# Create security baseline
verascan pipeline --filepath ./release \
  --export-findings baseline-v1.0.json

# Compare against baseline
verascan pipeline --filepath ./current \
  --baseline-file baseline-v1.0.json \
  --filtered-json-output-file new-findings.json \
  --export-findings current-results.json
```

### Policy Enforcement

```bash
# Fail on high severity vulnerabilities
verascan pipeline --filepath . \
  --fail-on-severity "High,Very High" \
  --export-findings results.json

# Fail on specific vulnerability types
verascan pipeline --filepath . \
  --fail-on-cwe "89,79,22" \
  --export-findings results.json

# Combined baseline and policy enforcement
verascan pipeline --filepath . \
  --baseline-file baseline.json \
  --fail-on-severity "Medium,High,Very High" \
  --filtered-json-output-file violations.json
```

### GitLab CI/CD Integration

```bash
# Complete GitLab pipeline integration
verascan pipeline --filepath ./build \
  --baseline-file security-baseline.json \
  --export-format gitlab \
  --export-findings gl-sast-report.json \
  --create-gitlab-issues \
  --fail-on-severity "High,Very High"
```

## Command Reference

### Pipeline Scan Command

```bash
verascan pipeline [OPTIONS] --filepath <PATH>
```

**Key Options:**
- `--filepath <PATH>` - Directory to scan for files (required)
- `--filefilter <PATTERNS>` - Comma-separated glob patterns (default: `"*"`)
- `--export-findings <FILE>` - Export findings to file
- `--export-format <FORMAT>` - json/csv/gitlab/all (default: `json`)
- `--fail-on-severity <LEVELS>` - Fail on severity levels (comma-separated)
- `--baseline-file <FILE>` - Baseline file for comparison
- `--threads <COUNT>` - Concurrent threads 2-10 (default: `4`)
- `--timeout <MINUTES>` - Scan timeout in minutes (default: `30`)
- `--region <REGION>` - commercial/european/federal (default: `commercial`)

### Assessment Scan Command

```bash
verascan assessment [OPTIONS] --filepath <PATH> --app-profile-name <NAME>
```

**Key Options:**
- `--filepath <PATH>` - Directory to scan for files (required)
- `--app-profile-name <NAME>` - Veracode application profile name (required)
- `--sandbox-name <NAME>` - Sandbox name for sandbox scans
- `--build-version <VERSION>` - Custom build version (auto-generated if not specified)
- `--export-results <FILE>` - Export assessment results
- `--break` - Break build on Veracode platform policy failure
- `--no-wait` - Submit scan and exit without waiting
- `--threads <COUNT>` - Concurrent threads 2-10 (default: `4`)
- `--timeout <MINUTES>` - Scan timeout in minutes (default: `60`)

### Export Command

```bash
verascan export [OPTIONS] --app-profile-name <NAME> --output <FILE>
```

**Key Options:**
- `--app-profile-name <NAME>` - Veracode application profile name (required)
- `--sandbox-name <NAME>` - Sandbox name for sandbox scan export
- `--output <FILE>` - Output file path (required)
- `--format <FORMAT>` - gitlab/json/csv/all (default: `gitlab`)
- `--min-severity <LEVEL>` - Filter by minimum severity
- `--project-dir <DIR>` - Project directory for file path resolution

## Environment Variables

### Authentication Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `VERACODE_API_ID` | ✅ | Your Veracode API ID credential |
| `VERACODE_API_KEY` | ✅ | Your Veracode API key credential |

### API Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `VERASCAN_FORCE_BUILDINFO_API` | - | Skip summary report API and use XML API for break build |
| `VERASCAN_GITLAB_SCHEMA` | `15.2.1` | GitLab SAST report schema version |

### Network Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `VERASCAN_CONNECT_TIMEOUT` | `30` | HTTP connection timeout in seconds |
| `VERASCAN_REQUEST_TIMEOUT` | `300` | HTTP request timeout in seconds |
| `VERASCAN_DISABLE_CERT_VALIDATION` | - | Disable TLS certificate validation |

### Retry Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `VERASCAN_MAX_RETRIES` | `5` | Maximum retry attempts |
| `VERASCAN_INITIAL_RETRY_DELAY_MS` | `1000` | Initial retry delay |
| `VERASCAN_MAX_RETRY_DELAY_MS` | `30000` | Maximum retry delay |
| `VERASCAN_BACKOFF_MULTIPLIER` | `2.0` | Exponential backoff multiplier |

### GitLab Integration
| Variable | Description |
|----------|-------------|
| `PRIVATE_TOKEN` | GitLab personal access token |
| `CI_PROJECT_ID` | GitLab project ID |
| `CI_API_V4_URL` | GitLab API v4 URL |
| `CI_COMMIT_SHA` | GitLab commit SHA |

## CI/CD Integration

### GitLab CI

```yaml
stages:
  - security

security_scan:
  stage: security
  image: rust:latest
  variables:
    VERACODE_API_ID: $VERACODE_API_ID
    VERACODE_API_KEY: $VERACODE_API_KEY
  before_script:
    - cargo build --release -p verascan
  script:
    - ./target/release/verascan pipeline --filepath ./target
        --baseline-file security-baseline.json
        --export-format gitlab
        --export-findings gl-sast-report.json
        --fail-on-severity "High,Very High"
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Build Verascan
        run: cargo build --release -p verascan
      - name: Security Scan
        env:
          VERACODE_API_ID: ${{ secrets.VERACODE_API_ID }}
          VERACODE_API_KEY: ${{ secrets.VERACODE_API_KEY }}
        run: |
          ./target/release/verascan pipeline --filepath . \
            --fail-on-severity "High,Very High" \
            --export-findings security-results.json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - no policy violations found |
| `1` | Policy violations detected or scan errors |
| `2` | Configuration or authentication errors |
| `4` | Veracode platform policy failure (when using `--break` flag) |

## Severity Levels

| Level | Numeric | Aliases |
|-------|---------|---------|
| Informational | 0 | info |
| Very Low | 1 | very-low, verylow, very_low |
| Low | 2 | - |
| Medium | 3 | med |
| High | 4 | - |
| Very High | 5 | very-high, veryhigh, very_high, critical |

## Supported File Types

Verascan automatically detects and validates:

- **Java**: JAR, WAR, EAR files
- **Archives**: ZIP, TAR, TAR.GZ, TAR.BZ2
- **Executables**: ELF, PE, Mach-O binaries
- **Libraries**: SO, DLL, DYLIB files
- **Source packages**: Various compressed source code formats

File type detection uses magic byte analysis, not just file extensions.

## Security Features

### Comprehensive Credential Protection

- All sensitive tokens show `[REDACTED]` in debug output
- Veracode API credentials are securely wrapped
- GitLab private tokens are protected
- Git repository passwords are redacted in URL logging
- Production-safe debug mode

### HashiCorp Vault Integration

Verascan supports secure credential management via HashiCorp Vault (inherited from veracode-platform library):

- Automatic credential retrieval from Vault
- Smart retry logic following Vault API best practices
- Fast failure on authentication errors
- Automatic recovery from transient errors

## Debugging and Troubleshooting

### Enable Debug Mode

```bash
verascan --debug pipeline --filepath . --export-findings results.json
```

Debug mode is safe to use - all credentials are automatically redacted.

### Common Issues

**Authentication Errors**
```
❌ Veracode API credentials are invalid
```
Solution: Verify `VERACODE_API_ID` and `VERACODE_API_KEY` environment variables.

**File Discovery Issues**
```
⚠️ No files found matching pattern: *.jar
```
Solutions:
- Check file patterns: `--filefilter "*.jar,*.war"`
- Verify directory path: `--filepath /correct/path`
- Enable debug mode: `--debug`

**GitLab Integration Issues**
```
❌ Failed to create GitLab issues: 401 Unauthorized
```
Solutions:
- Verify `PRIVATE_TOKEN` environment variable
- Check token has `api` and `write_repository` scopes
- Confirm `CI_PROJECT_ID` is correct

## Regional Support

| Region | Description | API Endpoint |
|--------|-------------|--------------|
| `commercial` | US Commercial Cloud (default) | `analysiscenter.veracode.com` |
| `european` | European Union Cloud | `analysiscenter.veracode.eu` |
| `federal` | US Federal Cloud | `analysiscenter.veracode.us` |

## Development

### Running Tests

```bash
# Run all tests
cargo test -p verascan

# Run with output
cargo test -p verascan -- --nocapture

# Run property-based security tests
cargo test -p verascan security_tests

# Run with miri (undefined behavior detection)
cargo +nightly miri test -p verascan
```

### Security Testing

Verascan includes comprehensive property-based security tests:

```bash
# Run all security property tests (1800+ test cases)
cargo test -p verascan security_tests -- --test-threads=1

# Run specific security test modules
cargo test -p verascan test_timeout_overflow_prevention
cargo test -p verascan test_file_size_boundary_validation
cargo test -p verascan test_path_traversal_prevention
```

Security properties validated:
- **Integer overflow prevention**: Timeout calculations, index operations, byte size formatting
- **Boundary validation**: File sizes (0, 2GB, 5GB, u64::MAX), thread counts, timeouts
- **Path safety**: Traversal prevention, Unicode handling, null bytes, symlinks
- **Injection prevention**: XSS, SQL injection patterns, control characters
- **Hash collision resistance**: SHA-256 uniqueness across 100K inputs

### Linting and Formatting

```bash
# Check code style (includes 15+ security lints)
cargo clippy --all-targets --all-features -- -D warnings -D clippy::all

# Format code
cargo fmt
```

### Security Lints

Verascan enforces production-grade security lints:

**Denied (Build Fails)**:
- `unwrap_used` - No `.unwrap()` in production code
- `panic` - No `panic!()` in production code
- `indexing_slicing` - No direct array/slice indexing
- `fallible_impl_from` - Safe type conversions
- `wildcard_enum_match_arm` - Explicit match handling
- `mem_forget` - No memory leaks

**Warned (Review Required)**:
- `arithmetic_side_effects` - Overflow detection
- `cast_possible_truncation` - Lossy numeric casts
- `cast_sign_loss` - Sign loss in casts
- `string_slice` - UTF-8 boundary safety
- `missing_errors_doc` - Error documentation
- `missing_panics_doc` - Panic documentation

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and version details.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

See the workspace-level [README.md](../README.md) for contribution guidelines.

---

*Part of the [Veracode Workspace](../README.md) - A comprehensive Rust ecosystem for Veracode platform integration*
