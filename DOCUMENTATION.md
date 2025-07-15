# Verascan - Veracode Security Scanning CLI

Verascan is a comprehensive command-line interface for the Veracode security platform, designed to integrate security scanning into CI/CD pipelines. It provides automated vulnerability scanning, baseline comparison, policy assessment, and seamless GitLab integration.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Examples](#examples)
- [CI/CD Integration](#cicd-integration)
- [GitLab Integration](#gitlab-integration)
- [Policy Management](#policy-management)
- [Baseline Comparison](#baseline-comparison)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

## Features

### Core Capabilities
- **Pipeline Scanning**: Submit files to Veracode for security analysis
- **Baseline Comparison**: Track new vulnerabilities against historical baselines
- **Policy Assessment**: Enforce security policies with pass/fail criteria
- **Multi-format Export**: JSON, CSV, and GitLab SAST report formats
- **GitLab Integration**: Automatic issue creation and SAST dashboard support
- **Concurrent Processing**: Multi-threaded file processing for improved performance

### Supported File Types
- Java Archives (JAR, WAR)
- Compressed files (ZIP, TAR, TAR.GZ)
- Binary executables and libraries
- Source code packages

### Export Formats
- **JSON**: Veracode baseline format for future comparisons
- **CSV**: Spreadsheet-compatible findings export
- **GitLab SAST**: Security Dashboard integration
- **Filtered JSON**: Policy violation reports

## Installation

### Prerequisites
- Rust 1.70+ (for building from source)
- Veracode API credentials
- GitLab access token (for GitLab features)

### Build from Source
```bash
git clone <repository-url>
cd veracode-workspace
cargo build --release
```

The binary will be available at `target/release/verascan`.

### Environment Setup
```bash
# Required for Veracode API access
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Optional: GitLab integration
export PRIVATE_TOKEN="your-gitlab-token"
```

## Quick Start

### Basic Security Scan
```bash
# Scan current directory for vulnerabilities
verascan --pipeline-scan --filepath . --export-findings results.json

# Scan with specific file types
verascan --pipeline-scan --filepath ./build \
  --filefilter "*.jar,*.war" \
  --export-findings vulnerabilities.json
```

### Baseline Comparison
```bash
# Create initial baseline
verascan --pipeline-scan --filepath . --export-findings baseline.json

# Compare against baseline
verascan --pipeline-scan --filepath . \
  --baseline-file baseline.json \
  --filtered-json-output-file new-findings.json \
  --export-findings current-results.json
```

### Policy Enforcement
```bash
# Fail on High or Very High severity findings
verascan --pipeline-scan --filepath . \
  --fail-on-severity "High,Very High" \
  --export-findings results.json

# Fail on specific CWE types
verascan --pipeline-scan --filepath . \
  --fail-on-cwe "89,79,22" \
  --export-findings results.json
```

## Authentication

### Veracode API Credentials

Verascan requires Veracode API credentials for authentication:

1. **Generate API Credentials**: Log into Veracode Platform → Account → API Credentials
2. **Set Environment Variables**:
   ```bash
   export VERACODE_API_ID="your-api-id"
   export VERACODE_API_KEY="your-api-key"
   ```

### Regional Support
```bash
# Commercial cloud (default)
verascan --region commercial --pipeline-scan --filepath .

# European cloud
verascan --region european --pipeline-scan --filepath .

# Federal cloud
verascan --region federal --pipeline-scan --filepath .
```

## Usage

### Command Structure
```bash
verascan [OPTIONS] --filepath <PATH>
```

### Required Options
- `--filepath <PATH>`: Directory to scan for files

### File Discovery Options
```bash
--filefilter <PATTERNS>     # File patterns (default: "*")
--recursive                 # Recursive search (default: true)
--validate                  # Validate file types (default: true)
```

### Pipeline Scan Options
```bash
--pipeline-scan                    # Enable Veracode scanning
--app-profile-name <NAME>          # Veracode application profile
--project-name <NAME>              # Project name (max 70 chars)
--project-url <URL>                # Project URL (https:// required)
--timeout <MINUTES>                # Scan timeout (default: 30)
--threads <COUNT>                  # Concurrent threads (2-10, default: 4)
--development-stage <STAGE>        # development/testing/release
```

### Export Options
```bash
--export-findings <FILE>           # Export findings to file
--export-format <FORMAT>           # json/csv/gitlab/all
--show-findings                    # Display in CLI
--findings-limit <NUM>             # Limit displayed findings (0=all)
--min-severity <LEVEL>             # Filter by minimum severity
```

### Policy & Baseline Options
```bash
--baseline-file <FILE>             # Baseline for comparison
--policy-file <FILE>               # Local policy file
--policy-name <NAME>               # Veracode platform policy
--filtered-json-output-file <FILE> # Policy violations export
--fail-on-severity <LEVELS>        # Fail criteria by severity
--fail-on-cwe <IDS>                # Fail criteria by CWE ID
```

### GitLab Integration Options
```bash
--create-gitlab-issues             # Create GitLab issues
--project-dir <PATH>               # Project root for file paths
```

### Utility Options
```bash
--debug                            # Enable debug output
--request-policy <NAME>            # Download policy by name
```

## Configuration

### Environment Variables

#### Required for Veracode
```bash
VERACODE_API_ID          # Veracode API ID
VERACODE_API_KEY         # Veracode API Key
```

#### Optional Configuration
```bash
VERASCAN_DISABLE_CERT_VALIDATION  # Allow HTTP in development
```

#### GitLab CI/CD Variables
```bash
PRIVATE_TOKEN            # GitLab API token
CI_PROJECT_ID            # GitLab project ID
CI_PIPELINE_ID           # GitLab pipeline ID
CI_PROJECT_URL           # GitLab project URL
GITLAB_USER_NAME         # GitLab username
```

### File Patterns

File filtering supports glob patterns:
```bash
# Single pattern
--filefilter "*.jar"

# Multiple patterns
--filefilter "*.jar,*.war,*.zip"

# Complex patterns
--filefilter "**/*.jar,target/**/*.war"
```

## Security Features

### Comprehensive Credential Protection

Verascan implements industry-leading security measures to protect all sensitive credentials and prevent accidental exposure.

#### 🔐 **Automatic Credential Redaction**

All sensitive information is automatically redacted in debug output and logs:

- **Veracode API Credentials**: `VERACODE_API_ID` and `VERACODE_API_KEY` show as `[REDACTED]`
- **GitLab Tokens**: `PRIVATE_TOKEN`, `CI_TOKEN`, `GITLAB_TOKEN` are securely wrapped
- **Git Passwords**: Repository URLs show as `username:[REDACTED]@host`
- **Configuration Structures**: All credential-containing structures are protected

#### 🛡️ **Secure Wrapper Implementation**

```bash
# Debug mode is now production-safe
verascan --debug --pipeline-scan --filepath . --export-findings results.json

# Example debug output (credentials are safely redacted):
# VeracodeConfig { api_id: [REDACTED], api_key: [REDACTED], base_url: "https://api.veracode.com" }
# GitLabConfig { api_token: [REDACTED], project_id: "12345", gitlab_url: "https://gitlab.com/api/v4/projects/" }
```

#### 🔄 **Backward Compatibility**

- All existing scripts and configurations continue to work unchanged
- No breaking changes to command-line interface
- Security improvements are transparent to users
- All examples and documentation remain valid

#### ✅ **Comprehensive Test Coverage**

- 18+ security-focused tests ensure protection works correctly
- Debug redaction verified for all credential types
- Integration tests confirm secure credential handling
- Continuous validation of security measures

### Security Best Practices

1. **Environment Variables**: Always store credentials in environment variables
2. **Debug Safety**: Debug mode is now production-safe with automatic redaction
3. **Token Scopes**: Use minimum required scopes for GitLab and Veracode tokens
4. **Regular Updates**: Keep verascan updated for security patches
5. **Access Control**: Limit access to systems with these credentials

### Production Deployment

```bash
# Safe to enable debug mode in production
verascan --debug --pipeline-scan --filepath . \
  --baseline-file security-baseline.json \
  --export-findings results.json \
  --create-gitlab-issues

# All sensitive information is automatically redacted:
# - API credentials show as [REDACTED]
# - Git URLs show as username:[REDACTED]@host
# - GitLab tokens are securely wrapped
```

## Examples

### Development Workflow

#### 1. Initial Security Assessment
```bash
# Comprehensive scan with all outputs
verascan --pipeline-scan --filepath ./target \
  --project-name "MyApp-v1.0" \
  --export-findings scan-results.json \
  --export-format all \
  --show-findings \
  --debug
```

#### 2. Establish Security Baseline
```bash
# Create baseline from clean build
verascan --pipeline-scan --filepath ./release \
  --project-name "MyApp-Release-v1.0" \
  --export-findings baseline-v1.0.json \
  --filefilter "*.jar,*.war"
```

#### 3. Continuous Security Monitoring
```bash
# Check for new vulnerabilities
verascan --pipeline-scan --filepath ./target \
  --baseline-file baseline-v1.0.json \
  --filtered-json-output-file new-vulnerabilities.json \
  --fail-on-severity "Medium,High,Very High" \
  --export-findings current-scan.json
```

### GitLab CI Integration

#### 4. Complete GitLab Pipeline
```bash
# Full CI/CD integration with GitLab
verascan --pipeline-scan --filepath ./build \
  --baseline-file security-baseline.json \
  --export-format gitlab \
  --export-findings gitlab-sast-report.json \
  --create-gitlab-issues \
  --fail-on-severity "High,Very High" \
  --filtered-json-output-file security-violations.json
```

### Policy Enforcement Examples

#### 5. Strict Security Policy
```bash
# Zero tolerance for critical vulnerabilities
verascan --pipeline-scan --filepath . \
  --fail-on-severity "Very High" \
  --fail-on-cwe "89,79,22,78,352" \
  --export-findings results.json
```

#### 6. Development Stage Policy
```bash
# Relaxed policy for development
verascan --pipeline-scan --filepath ./dev-build \
  --development-stage development \
  --fail-on-severity "Very High" \
  --min-severity "Medium" \
  --export-findings dev-results.json
```

### Advanced Use Cases

#### 7. Multi-format Reporting
```bash
# Generate all report formats
verascan --pipeline-scan --filepath ./artifacts \
  --export-format all \
  --export-findings security-report \
  --show-findings \
  --findings-limit 50
```

#### 8. Baseline Comparison with Policy
```bash
# Baseline + policy enforcement
verascan --pipeline-scan --filepath . \
  --baseline-file previous-scan.json \
  --policy-name "Veracode Recommended Medium" \
  --filtered-json-output-file violations.json \
  --export-findings full-results.json
```

## CI/CD Integration

### GitLab CI Configuration

Create `.gitlab-ci.yml`:

```yaml
security_scan:
  stage: security
  image: rust:latest
  variables:
    VERACODE_API_ID: $VERACODE_API_ID
    VERACODE_API_KEY: $VERACODE_API_KEY
  script:
    - cargo build --release
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
  only:
    - merge_requests
    - main
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
                    ./verascan --pipeline-scan --filepath ./target \
                        --export-findings security-results.json \
                        --fail-on-severity "High,Very High" \
                        --baseline-file baseline.json
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

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Build Verascan
        run: cargo build --release
      - name: Run Security Scan
        env:
          VERACODE_API_ID: ${{ secrets.VERACODE_API_ID }}
          VERACODE_API_KEY: ${{ secrets.VERACODE_API_KEY }}
        run: |
          ./target/release/verascan --pipeline-scan --filepath . \
            --export-findings security-results.json \
            --fail-on-severity "High,Very High"
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: security-results.json
```

## GitLab Integration

### Security Dashboard Integration

Verascan generates GitLab-compatible SAST reports:

```bash
# Generate GitLab SAST report
verascan --pipeline-scan --filepath . \
  --export-format gitlab \
  --export-findings gl-sast-report.json
```

The report will appear in GitLab's Security Dashboard and merge request security widgets.

### Automatic Issue Creation

```bash
# Create GitLab issues for findings
verascan --pipeline-scan --filepath . \
  --create-gitlab-issues \
  --project-dir /path/to/repo/root \
  --min-severity "Medium"
```

Features:
- Automatic issue creation for each finding
- Source code permalinks
- Detailed vulnerability descriptions
- CWE references and remediation guidance

### Environment Variables for GitLab

```bash
# Required for issue creation
export PRIVATE_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
export CI_PROJECT_ID="12345"

# Optional for enhanced features
export CI_PIPELINE_ID="67890"
export CI_PROJECT_URL="https://gitlab.com/user/project"
export GITLAB_USER_NAME="security-bot"
```

## Policy Management

### Using Veracode Platform Policies

```bash
# Download and apply platform policy
verascan --request-policy "Veracode Recommended High"

# Use downloaded policy
verascan --pipeline-scan --filepath . \
  --policy-name "Veracode Recommended High" \
  --filtered-json-output-file violations.json
```

### Custom Policy Files

Create a local policy file `security-policy.json`:

```json
{
  "name": "Custom Security Policy",
  "description": "Organization security standards",
  "rules": [
    {
      "type": "severity",
      "action": "fail",
      "target": ["Very High", "High"]
    },
    {
      "type": "cwe",
      "action": "fail", 
      "target": ["89", "79", "22", "78"]
    },
    {
      "type": "max_findings",
      "action": "fail",
      "severity": "Medium",
      "threshold": 10
    }
  ]
}
```

Apply custom policy:
```bash
verascan --pipeline-scan --filepath . \
  --policy-file security-policy.json \
  --filtered-json-output-file violations.json
```

### Pass/Fail Criteria

#### Severity-based Criteria
```bash
# Fail on specific severity levels
--fail-on-severity "Very High,High"
--fail-on-severity "Medium,High,Very High"

# Single severity level
--fail-on-severity "High"
```

#### CWE-based Criteria
```bash
# Fail on specific CWE types
--fail-on-cwe "89,79,22"          # SQL Injection, XSS, Path Traversal
--fail-on-cwe "78,352,601"        # Command Injection, Authentication, CSRF
```

#### Combined Criteria
```bash
# Both severity and CWE criteria must pass
verascan --pipeline-scan --filepath . \
  --fail-on-severity "High,Very High" \
  --fail-on-cwe "89,79,22" \
  --export-findings results.json
```

### Pass/Fail Logic

#### Baseline with Policy Criteria
When both baseline and pass/fail criteria are specified:
- **Policy criteria take precedence**
- Pass/fail criteria are applied to **new baseline findings only**
- If policy criteria pass (no violations) → exit 0 (success)
- If policy criteria fail (violations found) → exit 1 (failure)

#### Standalone Baseline
When only baseline comparison is specified:
- **Baseline comparison determines pass/fail**
- New findings detected → exit 1 (failure)
- No new findings → exit 0 (success)

#### Standalone Policy Criteria
When only pass/fail criteria are specified:
- **Policy criteria determine pass/fail**
- Criteria applied to all findings
- Violations found → exit 1 (failure)
- No violations → exit 0 (success)

## Baseline Comparison

### Creating Baselines

```bash
# Initial baseline from production release
verascan --pipeline-scan --filepath ./release-artifacts \
  --project-name "MyApp-v1.0-Release" \
  --export-findings baseline-v1.0.json
```

### Comparing Against Baselines

```bash
# Check for new vulnerabilities
verascan --pipeline-scan --filepath ./current-build \
  --baseline-file baseline-v1.0.json \
  --filtered-json-output-file new-findings.json \
  --export-findings current-results.json
```

### Baseline with Policy Enforcement

```bash
# Only fail on policy violations in new findings
verascan --pipeline-scan --filepath . \
  --baseline-file baseline.json \
  --fail-on-severity "High,Very High" \
  --filtered-json-output-file violations.json
```

### Understanding Baseline Results

The filtered output shows:
- **New Findings**: Vulnerabilities not present in baseline
- **Fixed Findings**: Issues resolved since baseline
- **Unchanged Findings**: Existing issues (not in filtered output)

### Baseline File Format

Baseline files contain:
```json
{
  "metadata": {
    "version": "1.0",
    "created_at": "2024-01-15T10:30:00Z",
    "source_scan": { ... },
    "finding_count": 25
  },
  "findings": [ ... ],
  "summary": {
    "total": 25,
    "very_high": 0,
    "high": 3,
    "medium": 12,
    "low": 8,
    "informational": 2
  }
}
```

## API Reference

### Exit Codes

- **0**: Success (no policy violations)
- **1**: Policy violations found or scan errors
- **2**: Configuration or authentication errors

### Severity Levels

| Level | Numeric | Aliases |
|-------|---------|---------|
| Informational | 0 | info |
| Very Low | 1 | very-low, verylow, very_low |
| Low | 2 | - |
| Medium | 3 | med |
| High | 4 | - |
| Very High | 5 | very-high, veryhigh, very_high, critical |

### File Type Support

Verascan automatically detects and validates:
- **Java**: JAR, WAR, EAR files
- **Archives**: ZIP, TAR, TAR.GZ, TAR.BZ2
- **Executables**: ELF, PE, Mach-O binaries
- **Libraries**: SO, DLL, DYLIB files

### Threading Configuration

```bash
--threads 2    # Minimum (conservative)
--threads 4    # Default (balanced)
--threads 8    # Higher throughput
--threads 10   # Maximum allowed
```

## Troubleshooting

### Common Issues

#### Authentication Errors
```
❌ Veracode API credentials are invalid
```
**Solution**: Verify VERACODE_API_ID and VERACODE_API_KEY are set correctly.

#### File Discovery Issues
```
⚠️ No files found matching pattern: *.jar
```
**Solutions**:
- Check file patterns: `--filefilter "*.jar,*.war"`
- Verify recursive search: `--recursive`
- Enable debug mode: `--debug`

#### GitLab Integration Issues
```
❌ Failed to create GitLab issues: 401 Unauthorized
```
**Solutions**:
- Verify PRIVATE_TOKEN is set
- Check token permissions (api, write_repository)
- Confirm CI_PROJECT_ID is correct

#### Policy Violations
```
❌ Pass-fail criteria FAILED - 5 violations detected
```
**Analysis**:
- Check `filtered-json-output-file` for violation details
- Review severity thresholds
- Examine baseline comparison results

### Debug Mode

Enable comprehensive logging:
```bash
verascan --debug --pipeline-scan --filepath . --export-findings results.json
```

Debug output includes:
- File discovery process
- API request/response details
- Policy evaluation steps
- Baseline comparison logic
- Export file operations

### Performance Optimization

#### Large File Sets
```bash
# Optimize for many files
verascan --threads 8 --timeout 60 --pipeline-scan --filepath .
```

#### Network Issues
```bash
# Increase timeout for slow connections
verascan --timeout 45 --pipeline-scan --filepath .
```

#### Memory Constraints
```bash
# Reduce concurrent processing
verascan --threads 2 --pipeline-scan --filepath .
```

### Log Analysis

Common log patterns:
```
✅ File validation successful
🔍 Baseline comparison analysis
⚠️ Policy evaluation warnings
❌ Critical errors requiring attention
📊 Statistics and summaries
```

### Support

For additional support:
1. Enable debug mode for detailed logs
2. Check environment variable configuration
3. Verify file permissions and paths
4. Review Veracode API credential validity
5. Test with minimal configuration first

## Architecture

### Project Structure

```
veracode-workspace/
├── veracode-api/          # Core Veracode API library
│   ├── src/
│   │   ├── lib.rs         # Main library entry point
│   │   ├── client.rs      # HTTP client and authentication
│   │   ├── pipeline.rs    # Pipeline scan operations
│   │   ├── app.rs         # Application management
│   │   ├── identity.rs    # User and team management
│   │   ├── policy.rs      # Security policy operations
│   │   ├── sandbox.rs     # Sandbox scan management
│   │   ├── build.rs       # Build scan operations
│   │   ├── scan.rs        # General scan utilities
│   │   └── workflow.rs    # Workflow validation
│   └── examples/          # API usage examples
├── verascan/              # CLI application
│   ├── src/
│   │   ├── main.rs        # Application entry point
│   │   ├── cli.rs         # Command-line interface
│   │   ├── scan.rs        # Main scan orchestration
│   │   ├── findings.rs    # Results processing and export
│   │   ├── baseline.rs    # Baseline comparison logic
│   │   ├── policy.rs      # Policy assessment
│   │   ├── pipeline.rs    # Pipeline scan execution
│   │   ├── gitlab.rs      # GitLab SAST report generation
│   │   ├── gitlab_issues.rs # GitLab issue creation
│   │   ├── search.rs      # File discovery
│   │   ├── filefinder.rs  # File system scanning
│   │   ├── filevalidator.rs # File type validation
│   │   └── credentials.rs # Authentication handling
│   └── examples/          # CLI usage examples
└── resources/             # Test files and samples
```

### Key Components

#### Core Library (veracode-api)
- **HTTP Client**: Handles authentication and API communication
- **API Modules**: Specialized interfaces for each Veracode API
- **Data Models**: Structured representations of API responses
- **Error Handling**: Comprehensive error types and handling

#### CLI Application (verascan)
- **Command Interface**: Argument parsing and validation
- **Scan Orchestration**: Coordinates all scanning operations
- **File Management**: Discovery, validation, and processing
- **Results Processing**: Aggregation, filtering, and export
- **Integration**: GitLab and CI/CD platform support

### Data Flow

1. **Input Processing**: File discovery and validation
2. **Authentication**: Veracode API credential verification
3. **Scan Submission**: Upload files for analysis
4. **Results Retrieval**: Download and process findings
5. **Post-Processing**: Baseline comparison and policy assessment
6. **Output Generation**: Export in multiple formats
7. **Integration**: GitLab issues and CI/CD artifacts

## License

This project is licensed under the terms specified in the workspace configuration.

---

*Last updated: 2025-01-12*