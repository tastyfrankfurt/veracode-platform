# Veracode Workspace

[![Rust](https://img.shields.io/badge/rust-1.70%2B-brightgreen.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A comprehensive Rust workspace for Veracode security platform integration, featuring a complete API client library and powerful CLI application for security scanning, policy management, and CI/CD integration.

## 🚀 Quick Start

```bash
# Clone and build
git clone <repository-url>
cd veracode-workspace
cargo build --release

# Set up authentication
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Run a basic pipeline scan
./target/release/verascan pipeline --filepath . --export-findings results.json

# Run a basic assessment scan
./target/release/verascan assessment --filepath . --app-profile-name "MyApp"

# Enable CMEK encryption on an application
./target/release/veracmek enable --app "MyApp" --kms-alias "alias/my-encryption-key"

# Check encryption status across all applications
./target/release/veracmek status
```

## 📁 Project Structure

```
veracode-workspace/
├── veracode-api/          # 🔧 Core Veracode API client library
│   ├── src/               # Library source code
│   └── examples/          # API usage examples
├── verascan/              # 🛡️ CLI security scanning application
│   ├── src/               # Application source code
│   ├── examples/          # CLI usage examples
│   └── gitlab/            # GitLab integration samples
├── veracmek/              # 🔐 CLI CMEK encryption management tool
│   └── src/               # Application source code
└── resources/             # 📦 Test files and samples
```

## 🏗️ Components

### Veracode API Library (`veracode-api`)

A comprehensive Rust client library for the Veracode security platform APIs:

- **🔗 Applications API** - Application lifecycle management
- **👥 Identity API** - User and team administration  
- **🔄 Pipeline Scan API** - Automated CI/CD security scanning
- **🏖️ Sandbox API** - Development environment management
- **📋 Policy API** - Security policy and compliance management
- **🔨 Build API** - Static application security testing (SAST)
- **📊 Scan API** - General scan utilities and management

### Verascan CLI Application (`verascan`)

A powerful command-line application for security scanning and Veracode integration.

### Veracmek CLI Application (`veracmek`)

A specialized command-line tool for managing Customer Managed Encryption Keys (CMEK) on Veracode application profiles:

## ✨ Key Features

### 🔍 **Intelligent File Discovery**
- Recursive directory scanning with glob pattern support
- Smart file type detection using magic bytes (not just extensions)
- Support for JAR, WAR, ZIP, TAR, and various binary formats
- Configurable file filtering and validation

### 🛡️ **Security Scanning**
- Direct integration with Veracode Pipeline Scan API
- Multi-threaded concurrent file processing (2-10 threads)
- Real-time scan progress monitoring
- Configurable timeouts and retry logic
- Support for all Veracode regions (Commercial, European, Federal)
- **File Size Validation**: Automatic validation with scan-type specific limits
  - **Pipeline Scans**: 200MB per file maximum
  - **Assessment Scans**: 2GB per file maximum + 5GB total cumulative limit
  - Early validation with clear error messages before processing begins
  - Oversized files are automatically filtered during file discovery
- **Enhanced Security**: Comprehensive secure token handling with automatic credential redaction
  - All Veracode API credentials (`VERACODE_API_ID`, `VERACODE_API_KEY`) are securely wrapped
  - GitLab private tokens are automatically redacted in debug output
  - Custom secure wrappers prevent accidental credential exposure
- **Safe Logging**: Password redaction for Git URLs showing `username:[REDACTED]@host` format
- **Debug Protection**: All sensitive credentials show `[REDACTED]` in debug logs

### 📊 **Baseline Comparison**
- Create security baselines from scan results
- Compare current scans against historical baselines
- Identify new vulnerabilities and fixed issues
- Hash-based exact finding matching for precision

### 📋 **Policy Management**
- Download and apply Veracode platform policies
- Custom local policy file support
- Pass/fail criteria based on severity levels or CWE IDs
- Combined baseline and policy enforcement
- **Break Build Functionality**: CI/CD integration with Veracode platform policy compliance
  - `--break` flag enables build breaking on policy failures
  - **Intelligent API Fallback**: Automatic fallback from summary report API to getbuildinfo.do XML API on permission errors (401/403)
  - `--force-buildinfo-api` flag or `VERASCAN_FORCE_BUILDINFO_API` env var to skip REST API and use XML API directly
  - **Enhanced Compatibility**: Works with any Veracode account permission level (REST+XML, XML-only, or restricted access)
  - Standard exit codes: 0 for success, 4 for policy failure (matches Veracode Java wrapper)
  - Works with both regular application scans and sandbox scans
  - Graceful error handling - API failures don't break builds
  - **Transparent Operation**: Clear logging shows which API path was used (summary report vs buildinfo)

### 📤 **Multi-format Export**
- **JSON**: Veracode baseline format for future comparisons
- **CSV**: Spreadsheet-compatible findings export
- **GitLab SAST**: Security Dashboard integration
- **Filtered JSON**: Policy violation reports

### 📊 **Export from Completed Scans**
- **Findings Retrieval**: Export security findings from completed Veracode assessment scans
- **Policy & Sandbox Support**: Export from both policy scans and sandbox scans
- **Server-Side Filtering**: API-level severity filtering to reduce network traffic
- **Automatic Pagination**: Handles large result sets with intelligent pagination
- **Performance Optimized**: Uses FindingsQuery builder pattern for efficient data retrieval

### 🦊 **GitLab Integration**
- Automatic GitLab issue creation for findings
- SAST Security Dashboard reports
- Source code permalinks in issues
- CI/CD pipeline integration
- **Improved URL Generation**: Fixed line number linking by removing problematic `ref_type=heads` parameter
- **Project Name Resolution**: Uses actual GitLab project name instead of "Unknown" fallback

### ⚡ **Performance Optimized**
- Concurrent file processing and scan submission
- Efficient memory usage for large file sets
- Progress indicators and detailed logging
- Configurable threading and timeouts

## 🛠️ Installation

### Prerequisites

- **Rust 1.70+** (for building from source)
- **Veracode API Credentials** ([Generate here](https://docs.veracode.com/r/c_api_credentials3))
- **GitLab Token** (optional, for GitLab features)

### Build from Source

```bash
git clone <repository-url>
cd veracode-workspace
cargo build --release
```

The `verascan` binary will be available at `target/release/verascan`.

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

## 📚 Usage Examples

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

> **📏 File Size Limits**: Pipeline scans accept files up to 200MB each. Assessment scans accept files up to 2GB each with a 5GB total limit across all files. Files exceeding these limits are automatically detected and rejected with clear error messages.

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

# Assessment scan with --no-wait (submit and exit)
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --no-wait \
  --export-results results.json

# Assessment scan with no-wait option
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --no-wait

# Assessment scan with break build on policy failure
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --break \
  --export-results results.json

# Assessment scan with break build using buildinfo API directly (for restricted permissions)
verascan assessment --filepath ./target \
  --app-profile-name "MyApplication" \
  --break \
  --force-buildinfo-api \
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

# Export to JSON format
verascan export --app-profile-name "MyApplication" \
  --format json \
  --output findings.json

# Export to CSV format
verascan export --app-profile-name "MyApplication" \
  --format csv \
  --output findings.csv

# Export to multiple formats
verascan export --app-profile-name "MyApplication" \
  --format all \
  --output comprehensive-report

# Export with custom project directory for GitLab file path resolution
verascan export --app-profile-name "MyApplication" \
  --format gitlab \
  --output gitlab-sast-report.json \
  --project-dir /path/to/project

# Export with debug output
verascan export --app-profile-name "MyApplication" \
  --output findings.json \
  --debug
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

### Policy Management

```bash
# Download Veracode platform policy
verascan policy "Veracode Recommended High"

# Use downloaded policy
verascan pipeline --filepath . \
  --policy-name "Veracode Recommended High" \
  --filtered-json-output-file violations.json
```

### Advanced Configuration

```bash
# High-performance pipeline scanning with custom settings
verascan pipeline --filepath ./artifacts \
  --threads 8 \
  --timeout 60 \
  --region european \
  --app-profile-name "Production App" \
  --development-stage release \
  --export-format all \
  --export-findings comprehensive-report \
  --show-findings \
  --debug

# Advanced assessment scan with custom settings
verascan assessment --filepath ./artifacts \
  --app-profile-name "Production App" \
  --sandbox-name "qa-testing" \
  --threads 8 \
  --timeout 120 \
  --modules "web-app,api-service" \
  --teamname "Security Team" \
  --bus-cri high \
  --export-results assessment-comprehensive.json \
  --debug
```

## 🌍 Environment Variables

Verascan supports comprehensive HTTP client configuration through VERASCAN_ prefixed environment variables. These variables provide unified configuration for network timeouts, retry behavior, and certificate validation across all Veracode API calls and GitLab integrations.

### Authentication Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `VERACODE_API_ID` | ✅ | Your Veracode API ID credential |
| `VERACODE_API_KEY` | ✅ | Your Veracode API key credential |

### API Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `VERASCAN_FORCE_BUILDINFO_API` | - | Skip summary report API and use getbuildinfo.do XML API directly for break build evaluation (set any value) |

### Network Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `VERASCAN_CONNECT_TIMEOUT` | `30` | HTTP connection timeout in seconds |
| `VERASCAN_REQUEST_TIMEOUT` | `300` | HTTP request timeout in seconds (5 minutes) |
| `VERASCAN_DISABLE_CERT_VALIDATION` | - | Disable TLS certificate validation (set any value) |

### Retry Configuration  
| Variable | Default | Description |
|----------|---------|-------------|
| `VERASCAN_MAX_RETRIES` | `5` | Maximum number of retry attempts |
| `VERASCAN_INITIAL_RETRY_DELAY_MS` | `1000` | Initial retry delay in milliseconds |
| `VERASCAN_MAX_RETRY_DELAY_MS` | `30000` | Maximum retry delay in milliseconds (30 seconds) |
| `VERASCAN_BACKOFF_MULTIPLIER` | `2.0` | Exponential backoff multiplier |
| `VERASCAN_DISABLE_JITTER` | - | Disable retry timing randomization (set any value) |

### GitLab Integration (CI/CD environments)
| Variable | Description |
|----------|-------------|
| `PRIVATE_TOKEN` | GitLab personal access token |
| `CI_TOKEN` | GitLab CI job token |
| `GITLAB_TOKEN` | Alternative GitLab token |
| `CI_PROJECT_ID` | GitLab project ID |
| `CI_API_V4_URL` | GitLab API v4 URL |
| `CI_PIPELINE_ID` | GitLab pipeline ID |
| `CI_PROJECT_URL` | GitLab project web URL |
| `CI_COMMIT_SHA` | GitLab commit SHA |

### Example Configuration

```bash
# Authentication (required)
export VERACODE_API_ID="your-api-id-here"
export VERACODE_API_KEY="your-api-key-here"

# API configuration for restricted permissions
export VERASCAN_FORCE_BUILDINFO_API="1"     # Force XML API usage for break build

# Network optimization for slow connections
export VERASCAN_CONNECT_TIMEOUT="60"        # 60 second connection timeout
export VERASCAN_REQUEST_TIMEOUT="900"       # 15 minute request timeout

# Aggressive retry for CI/CD environments
export VERASCAN_MAX_RETRIES="10"            # More retries for reliability
export VERASCAN_INITIAL_RETRY_DELAY_MS="500" # Faster initial retry
export VERASCAN_BACKOFF_MULTIPLIER="1.5"    # Gentler backoff

# Development environment (disable certificate validation)
export VERASCAN_DISABLE_CERT_VALIDATION="true"

# Disable jitter for predictable timing in tests
export VERASCAN_DISABLE_JITTER="true"
```

### Benefits
- **Unified Configuration**: Same variables work for all HTTP operations (Veracode API, GitLab integration)
- **CI/CD Optimization**: Tune timeouts and retries for your specific environment
- **Development Support**: Disable certificate validation for local testing
- **Reliability**: Configurable retry strategies with jitter support
- **Security**: Automatic credential redaction in logs and debug output

## 🎛️ Command Reference

### Required Arguments

| Option | Description |
|--------|-------------|
| `--filepath <PATH>` | Directory to scan for files |

### File Discovery Options

| Option | Default | Description |
|--------|---------|-------------|
| `--filefilter <PATTERNS>` | `"*"` | Comma-separated glob patterns |
| `--recursive` | `true` | Search subdirectories recursively |
| `--validate` | `true` | Validate file types using magic bytes |

### Pipeline Scan Options

| Option | Default | Description |
|--------|---------|-------------|
| `--pipeline-scan` | - | Enable Veracode pipeline scanning |
| `--app-profile-name <NAME>` | - | Veracode application profile name |
| `--project-name <NAME>` | - | Project name (max 70 characters) |
| `--project-url <URL>` | - | Project URL (https:// required) |
| `--region <REGION>` | `commercial` | Veracode region (commercial/european/federal) |
| `--timeout <MINUTES>` | `30` | Scan timeout in minutes |
| `--threads <COUNT>` | `4` | Concurrent threads (2-10) |
| `--development-stage <STAGE>` | `development` | development/testing/release |

### Assessment Scan Options

| Option | Default | Description |
|--------|---------|-------------|
| `--app-profile-name <NAME>` | - | Veracode application profile name (required) |
| `--sandbox-name <NAME>` | - | Sandbox name for sandbox assessment scans |
| `--no-wait` | `false` | Submit scan and exit without waiting for completion |
| `--modules <LIST>` | - | Specific modules to scan (comma-separated) |
| `--teamname <NAME>` | - | Team name for application creation |
| `--bus-cri <LEVEL>` | `very-high` | Business criticality (very-high/high/medium/low/very-low) |
| `--deleteincompletescan <POLICY>` | `1` | Build deletion policy (0=never, 1=safe builds, 2=any build) |
| `--timeout <MINUTES>` | `60` | Scan timeout in minutes |
| `--threads <COUNT>` | `4` | Concurrent threads (2-10) |
| `--export-results <FILE>` | `assessment-results.json` | Export assessment results |
| `--break` | `false` | Break build on Veracode platform policy compliance failure (conflicts with `--no-wait`) |

### Export Command Options

| Option | Default | Description |
|--------|---------|-------------|
| `--app-profile-name <NAME>` | - | Veracode application profile name (required) |
| `--sandbox-name <NAME>` | - | Sandbox name for sandbox scan export (optional) |
| `--output <FILE>` | `findings_export.json` | Output file path for exported findings |
| `--format <FORMAT>` | `gitlab` | Export format (gitlab/json/csv/all) |
| `--min-severity <LEVEL>` | - | Filter by minimum severity (informational/very-low/low/medium/high/very-high) |
| `--project-dir <DIR>` | `.` | Project directory for file path resolution in GitLab reports |
| `--debug` | `false` | Enable detailed diagnostic output (global option) |

### Export & Display Options

| Option | Default | Description |
|--------|---------|-------------|
| `--export-findings <FILE>` | - | Export findings to file |
| `--export-format <FORMAT>` | `json` | json/csv/gitlab/all |
| `--show-findings` | `false` | Display findings in CLI |
| `--findings-limit <NUM>` | `20` | Limit displayed findings (0=all) |
| `--min-severity <LEVEL>` | - | Filter by minimum severity |

### Policy & Baseline Options

| Option | Description |
|--------|-------------|
| `--baseline-file <FILE>` | Baseline file for comparison |
| `--policy-file <FILE>` | Local policy file path |
| `--policy-name <NAME>` | Veracode platform policy name |
| `--filtered-json-output-file <FILE>` | Policy violations export |
| `--fail-on-severity <LEVELS>` | Fail on severity levels (comma-separated) |
| `--fail-on-cwe <IDS>` | Fail on CWE IDs (comma-separated) |

### GitLab Integration Options

| Option | Description |
|--------|-------------|
| `--create-gitlab-issues` | Create GitLab issues from findings |
| `--project-dir <PATH>` | Project root for file path resolution |

### Utility Options

| Option | Description |
|--------|-------------|
| `--debug` | Enable detailed diagnostic output |
| `--request-policy <NAME>` | Download policy by name |

## 🔄 CI/CD Integration

### GitLab CI

Create `.gitlab-ci.yml`:

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
    - cargo build --release
  script:
    - ./target/release/verascan --pipeline-scan --filepath ./target
        --baseline-file security-baseline.json
        --export-format gitlab
        --export-findings gl-sast-report.json
        --fail-on-severity "High,Very High"
        --create-gitlab-issues
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - security-violations.json
    expire_in: 1 week
    when: always
  only:
    - merge_requests
    - main
```

### GitHub Actions

**NEW**: This project now includes comprehensive GitHub Actions workflows in `.github/workflows/`:

- **`build.yml`**: Continuous integration with formatting checks, clippy linting, and testing
- **`release.yml`**: Simple release workflow for tagged releases  
- **`multiplatform.yml`**: Cross-platform builds for Linux, Windows, and macOS

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
        run: cargo build --release
      - name: Security Scan
        env:
          VERACODE_API_ID: ${{ secrets.VERACODE_API_ID }}
          VERACODE_API_KEY: ${{ secrets.VERACODE_API_KEY }}
        run: |
          ./target/release/verascan --pipeline-scan --filepath . \
            --fail-on-severity "High,Very High" \
            --export-findings security-results.json
      - uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: security-results.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    environment {
        VERACODE_API_ID = credentials('veracode-api-id')
        VERACODE_API_KEY = credentials('veracode-api-key')
    }
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    cargo build --release
                    ./target/release/verascan --pipeline-scan --filepath ./target \
                        --fail-on-severity "High,Very High" \
                        --baseline-file baseline.json \
                        --export-findings security-results.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-results.json'
                }
            }
        }
    }
}
```

## 📖 Library Usage

### Add to Cargo.toml

```toml
[dependencies]
veracode-platform = { path = "veracode-api" }
# Or if published to crates.io:
# veracode-platform = "0.4.1"
```

### Basic API Usage

```rust
use veracode_platform::{VeracodeConfig, VeracodeRegion};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure client
    let config = VeracodeConfig::new(
        "your-api-id".to_string(),
        "your-api-key".to_string(),
        VeracodeRegion::Commercial,
    );

    // Use the API
    let client = veracode_platform::Client::new(config);
    let apps = client.get_applications().await?;
    
    println!("Found {} applications", apps.len());
    Ok(())
}
```

## 🧪 Running Examples

### API Library Examples

```bash
# Application lifecycle management
cargo run --example application_lifecycle -p veracode-api

# Pipeline scan workflow
cargo run --example pipeline_scan_lifecycle -p veracode-api

# Policy management
cargo run --example policy_lifecycle -p veracode-api

# Identity and user management
cargo run --example identity_lifecycle -p veracode-api

# Sandbox operations
cargo run --example sandbox_lifecycle -p veracode-api
```

### CLI Application Examples

```bash
# GitLab integration example
./verascan/examples/gitlab_issues_example.sh

# Manual testing
cargo run --example manual_test_example -p verascan

# Independent GitLab testing
./verascan/examples/test_independent_gitlab.sh
```

## 🔧 Development

### Building the Project

```bash
# Build everything
cargo build

# Build in release mode (optimized)
cargo build --release

# Build specific package
cargo build -p veracode-api
cargo build -p verascan
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific package
cargo test -p veracode-api
cargo test -p verascan

# Run with output
cargo test -- --nocapture
```

### Linting and Formatting

```bash
# Check code style
cargo clippy

# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Building Documentation

```bash
# Build and open documentation
cargo doc --open

# Build documentation for all packages
cargo doc --workspace
```

## 🔍 Debugging and Troubleshooting

### Enable Debug Mode

```bash
# Comprehensive debug output with secure credential handling
verascan --debug --pipeline-scan --filepath . --export-findings results.json
```

**Security Note**: Debug mode is now safe to use in production environments. All sensitive credentials (Veracode API keys, GitLab tokens, Git passwords) are automatically redacted as `[REDACTED]` in debug output.

Debug output includes:
- File discovery and validation process
- API request/response details
- Policy evaluation and baseline comparison
- Export operations and file writing
- **Enhanced Security**: All sensitive tokens are automatically redacted in debug logs
  - Veracode API credentials (`VERACODE_API_ID`, `VERACODE_API_KEY`) are securely wrapped
  - GitLab private tokens are protected with secure wrappers
  - Custom Debug implementations prevent accidental credential exposure
- **Safe URL Logging**: Git URLs with passwords are redacted as `username:[REDACTED]@host`
- **Comprehensive Protection**: 18+ tests ensure security measures work correctly

### Common Issues

#### Authentication Errors
```
❌ Veracode API credentials are invalid
```
**Solution**: Verify `VERACODE_API_ID` and `VERACODE_API_KEY` environment variables.

**Security Note**: All API credentials are automatically secured with protective wrappers that prevent accidental exposure in logs. Your credentials are safe even in debug mode.

#### File Discovery Issues
```
⚠️ No files found matching pattern: *.jar
```
**Solutions**:
- Check file patterns: `--filefilter "*.jar,*.war"`
- Verify directory path: `--filepath /correct/path`
- Enable debug mode: `--debug`

#### GitLab Integration Issues
```
❌ Failed to create GitLab issues: 401 Unauthorized
```
**Solutions**:
- Verify `PRIVATE_TOKEN` environment variable
- Check token has `api` and `write_repository` scopes
- Confirm `CI_PROJECT_ID` is correct
- **Note**: Private tokens are automatically redacted in debug logs for security

#### GitLab URL Issues
```
❌ GitLab issue links not working correctly
```
**Solutions**:
- This has been fixed by removing the problematic `ref_type=heads` parameter
- GitLab line number links now work correctly in issue descriptions

### Performance Tuning

```bash
# High throughput for large file sets
verascan --threads 8 --timeout 60 --pipeline-scan --filepath .

# Conservative settings for limited resources
verascan --threads 2 --timeout 30 --pipeline-scan --filepath .
```

## 📊 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - no policy violations found |
| `1` | Policy violations detected or scan errors |
| `2` | Configuration or authentication errors |
| `4` | Veracode platform policy failure (when using `--break` flag) |

## 🏷️ Severity Levels

| Level | Numeric | Aliases |
|-------|---------|---------|
| Informational | 0 | info |
| Very Low | 1 | very-low, verylow, very_low |
| Low | 2 | - |
| Medium | 3 | med |
| High | 4 | - |
| Very High | 5 | very-high, veryhigh, very_high, critical |

## 🧩 Supported File Types

Verascan automatically detects and validates:

- **Java**: JAR, WAR, EAR files
- **Archives**: ZIP, TAR, TAR.GZ, TAR.BZ2
- **Executables**: ELF, PE, Mach-O binaries
- **Libraries**: SO, DLL, DYLIB files
- **Source packages**: Various compressed source code formats

File type detection uses magic byte analysis, not just file extensions.

## 🔐 Security Features

### Comprehensive Credential Protection

This project implements industry-leading security measures to protect all sensitive credentials:

#### 🔒 **Automatic Credential Redaction**
- All sensitive tokens show `[REDACTED]` in debug output
- Veracode API credentials (`VERACODE_API_ID`, `VERACODE_API_KEY`) are securely wrapped
- GitLab private tokens are protected with secure containers
- Git repository passwords are redacted in URL logging

#### 🛡️ **Secure Wrapper Implementation**
```rust
// Example: Veracode API credentials are automatically secured
let config = VeracodeConfig::new(
    env::var("VERACODE_API_ID")?,
    env::var("VERACODE_API_KEY")?,
);

// Debug output safely shows:
// VeracodeConfig { api_id: [REDACTED], api_key: [REDACTED], ... }
println!("{:?}", config);
```

#### 🧪 **Production-Safe Debug Mode**
- Debug mode can be safely enabled in production environments
- Comprehensive logging without credential exposure
- All sensitive information is automatically sanitized

#### 🔄 **Backward Compatibility**
- All existing code continues to work unchanged
- No breaking changes to public APIs
- Security improvements are transparent to users
- Examples and documentation remain valid

#### ✅ **Comprehensive Test Coverage**
- 18+ security-focused tests ensure protection works correctly
- Debug redaction verified for all credential types
- Integration tests confirm secure credential handling
- Continuous validation of security measures

### Security Best Practices

1. **Environment Variables**: Store credentials in environment variables, never in code
2. **Debug Safety**: Debug mode is now production-safe with automatic redaction
3. **Token Scopes**: Use minimum required scopes for GitLab and Veracode tokens
4. **Regular Updates**: Keep dependencies updated for security patches
5. **Access Control**: Limit access to systems with these credentials

## 🌍 Regional Support

| Region | Description | API Endpoint |
|--------|-------------|--------------|
| `commercial` | US Commercial Cloud (default) | `analysiscenter.veracode.com` |
| `european` | European Union Cloud | `analysiscenter.veracode.eu` |
| `federal` | US Federal Cloud | `analysiscenter.veracode.us` |

## 📄 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- 📚 **Documentation**: See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed usage guide
- 🐛 **Issues**: Report bugs and request features via GitHub Issues
- 💬 **Discussions**: Join community discussions for help and best practices

---

*Built with ❤️ in Rust for the security community*