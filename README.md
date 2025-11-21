# Veracode Workspace

[![Rust](https://img.shields.io/badge/rust-1.70%2B-brightgreen.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A comprehensive Rust workspace for Veracode security platform integration, featuring a complete API client library and powerful CLI applications for security scanning, policy management, and CI/CD integration.

## Quick Start

```bash
# Clone and build
git clone <repository-url>
cd veracode-workspace
cargo build --release

# Set up authentication
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Run a security scan
./target/release/verascan pipeline --filepath . --export-findings results.json

# Check encryption status
./target/release/veracmek status

# Retrieve audit logs
./target/release/veraaudit --output audit-logs.json
```

## Project Structure

```
veracode-workspace/
├── veracode-api/          # Core Veracode API client library
│   ├── src/               # Library source code
│   ├── examples/          # API usage examples
│   ├── README.md          # API library documentation
│   └── CHANGELOG.md       # API version history
├── verascan/              # CLI security scanning application
│   ├── src/               # Application source code
│   ├── examples/          # CLI usage examples
│   ├── gitlab/            # GitLab integration samples
│   ├── README.md          # Verascan documentation
│   └── CHANGELOG.md       # Verascan version history
├── veraaudit/             # CLI audit log retrieval tool
│   ├── src/               # Application source code
│   ├── README.md          # Veraaudit documentation
│   └── CHANGELOG.md       # Veraaudit version history
├── veracmek/              # CLI CMEK encryption management tool
│   ├── src/               # Application source code
│   ├── README.md          # Veracmek documentation
│   └── CHANGELOG.md       # Veracmek version history
├── fuzz/                  # Fuzzing infrastructure and targets
│   ├── fuzz_targets/      # 9 fuzz targets covering 65+ functions
│   ├── corpus/            # Seed corpus for fuzzing
│   └── *.md               # Comprehensive fuzzing documentation
└── resources/             # Test files and samples
```

## Components

### [Veracode API Library](veracode-api/) (`veracode-api`)

[![Crate Version](https://img.shields.io/badge/version-0.7.5-blue.svg)](veracode-api/Cargo.toml)

A comprehensive Rust client library for the Veracode security platform APIs.

**Key Capabilities:**
- Applications API - Application lifecycle management
- Identity API - User and team administration
- Pipeline Scan API - Automated CI/CD security scanning
- Sandbox API - Development environment management
- Policy API - Security policy and compliance management
- Build API - Static application security testing (SAST)
- Scan API - General scan utilities and management

[Read the full documentation](veracode-api/README.md)

### [Verascan CLI](verascan/) (`verascan`)

[![Crate Version](https://img.shields.io/badge/version-0.6.4-blue.svg)](verascan/Cargo.toml)

A powerful command-line application for security scanning and Veracode integration.

**Key Capabilities:**
- Intelligent file discovery with glob patterns and magic byte detection
- Pipeline and assessment security scanning
- Baseline comparison and policy enforcement
- Multi-format export (JSON, CSV, GitLab SAST)
- GitLab CI/CD integration
- Break build functionality for policy compliance
- Multi-threaded concurrent processing

[Read the full documentation](verascan/README.md)

### [Veraaudit CLI](veraaudit/) (`veraaudit`)

[![Crate Version](https://img.shields.io/badge/version-0.2.3-blue.svg)](veraaudit/Cargo.toml)

A production-ready tool for retrieving and archiving Veracode audit logs for compliance and monitoring.

**Key Capabilities:**
- Audit log retrieval with automated collection
- Service mode with continuous monitoring
- Timestamped archival with UTC-based file naming
- Vault integration for secure credential management
- Automatic cleanup with configurable retention policies
- Multi-regional support with timezone handling
- Production-ready error handling and retry logic

[Read the full documentation](veraaudit/README.md)

### [Veracmek CLI](veracmek/) (`veracmek`)

[![Crate Version](https://img.shields.io/badge/version-0.2.3-blue.svg)](veracmek/Cargo.toml)

A specialized command-line tool for managing Customer Managed Encryption Keys (CMEK) on Veracode application profiles.

**Key Capabilities:**
- CMEK management - Enable, change, and monitor encryption keys
- Bulk operations with dry-run support
- File-based configuration for batch processing
- Vault integration for secure credential management
- Multiple output formats (table and JSON)
- Multi-regional support
- Production-ready intelligent error handling

[Read the full documentation](veracmek/README.md)

### [Fuzzing Infrastructure](fuzz/) (`fuzz/`)

Comprehensive fuzzing infrastructure for security testing and vulnerability discovery.

**Key Capabilities:**
- 9 fuzz targets covering 65+ security-critical functions
- Prioritized testing for URL validation, HTML parsing, and credential handling
- Security-focused testing that discovered and fixed multiple high-severity vulnerabilities
- Extensive documentation with quick start guides
- Automated scripts for quick/standard/comprehensive testing
- 90+ security tests derived from fuzzing discoveries

[Read the fuzzing guide](fuzz/README.md)

## Installation

### Prerequisites

- **Rust 1.70+** (for building from source)
- **Veracode API Credentials** ([Generate here](https://docs.veracode.com/r/c_api_credentials3))
- **GitLab Token** (optional, for GitLab features)
- **HashiCorp Vault** (optional, for secure credential management)

### Build from Source

```bash
git clone <repository-url>
cd veracode-workspace
cargo build --release
```

The binaries will be available at:
- `target/release/verascan` - Security scanning CLI
- `target/release/veracmek` - CMEK encryption management CLI
- `target/release/veraaudit` - Audit log retrieval CLI

### Environment Setup

```bash
# Required: Veracode API credentials
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Optional: GitLab integration (for verascan)
export PRIVATE_TOKEN="your-gitlab-token"
export CI_PROJECT_ID="12345"

# Optional: Vault integration (for veracmek and veraaudit)
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="your_jwt_token"
export VAULT_CLI_ROLE="veracode-role"
export VAULT_CLI_SECRET_PATH="secret/veracode@kvv2"
```

## Key Features

### Security Hardening

This workspace implements comprehensive security measures:

- **Input Validation**: Extensive validation across all CLI inputs
- **Credential Protection**: Automatic redaction of sensitive data in logs
- **Secure Dependencies**: Zero security advisories, actively maintained dependencies
- **Property-Based Testing**: Comprehensive security testing with proptest
- **Undefined Behavior Detection**: Testing with miri for memory safety
- **Formal Verification**: Kani verification for critical security functions
- **Fuzzing**: 9 fuzz targets with 90+ derived security tests

### Production Ready

- **Intelligent Error Handling**: Smart retry logic following API best practices
- **Fast Failure**: Authentication errors exit immediately
- **Automatic Recovery**: Transient errors retry with exponential backoff
- **Multi-Regional Support**: All Veracode regions (Commercial, European, Federal)
- **Vault Integration**: HashiCorp Vault support with production-grade error handling
- **Comprehensive Logging**: Detailed diagnostics with secure credential handling

## Development

### Building the Project

```bash
# Build everything
cargo build

# Build in release mode (optimized)
cargo build --release

# Build specific package
cargo build -p veracode-api
cargo build -p verascan
cargo build -p veracmek
cargo build -p veraaudit
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific package
cargo test -p veracode-api
cargo test -p verascan
cargo test -p veracmek
cargo test -p veraaudit

# Run with output
cargo test -- --nocapture

# Run tests with miri (undefined behavior detection)
cargo +nightly miri test
```

### Linting and Formatting

```bash
# Check code style with strict linting
cargo clippy --all-targets --all-features -- -D warnings -D clippy::all

# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Security Auditing

```bash
# Check for security vulnerabilities in dependencies
cargo audit

# Install cargo-audit if not already installed
cargo install cargo-audit
```

### Fuzzing

```bash
# Quick security check (2 minutes per high-priority target)
cd fuzz && ./run_all_fuzz_tests.sh 120 quick

# Standard fuzzing run (10 minutes per target)
cd fuzz && ./run_all_fuzz_tests.sh 600 standard

# Comprehensive overnight test
cd fuzz && nohup ./run_all_fuzz_tests.sh 28800 comprehensive > fuzz.log 2>&1 &
```

For detailed fuzzing documentation, see [fuzz/README.md](fuzz/README.md).

### Building Documentation

```bash
# Build and open documentation
cargo doc --open

# Build documentation for all packages
cargo doc --workspace
```

## Running Examples

### API Library Examples

```bash
# Application lifecycle management
cargo run --example application_lifecycle -p veracode-api

# Pipeline scan workflow
cargo run --example pipeline_scan_lifecycle -p veracode-api

# Policy management
cargo run --example policy_lifecycle -p veracode-api
```

### CLI Application Examples

See individual component documentation:
- [Verascan Examples](verascan/README.md#usage-examples)
- [Veracmek Examples](veracmek/README.md#usage-examples)
- [Veraaudit Examples](veraaudit/README.md#usage-examples)

## CI/CD Integration

All CLI tools support integration with major CI/CD platforms:

- **GitLab CI** - Native SAST integration with Security Dashboard
- **GitHub Actions** - Artifact uploads and security scanning
- **Jenkins Pipeline** - Credential management and reporting

See individual component documentation for specific examples:
- [Verascan CI/CD Guide](verascan/README.md#cicd-integration)
- [Veracmek CI/CD Guide](veracmek/README.md#cicd-integration)
- [Veraaudit CI/CD Guide](veraaudit/README.md#cicd-integration)

## Regional Support

All tools support all Veracode regions:

| Region | Description | API Endpoint |
|--------|-------------|--------------|
| `commercial` | US Commercial Cloud (default) | `analysiscenter.veracode.com` |
| `european` | European Union Cloud | `analysiscenter.veracode.eu` |
| `federal` | US Federal Cloud | `analysiscenter.veracode.us` |

## Security Features

### Comprehensive Credential Protection

- Automatic credential redaction in all debug output
- Secure wrappers for Veracode API credentials
- Protected GitLab tokens and Git passwords
- Production-safe debug mode
- Comprehensive test coverage for security measures

### HashiCorp Vault Integration

- Automatic credential retrieval from Vault
- Smart retry logic following Vault API best practices
- Fast failure on authentication errors (no unnecessary retries)
- Automatic recovery from transient errors
- Safe defaults to prevent retry storms

### Dependency Security

- Zero security advisories across all dependencies
- Modern, actively maintained crates
- Regular dependency updates
- Security-focused dependency selection

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests and linting (`cargo test && cargo clippy`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Contribution Guidelines

- Follow the existing code style (run `cargo fmt`)
- Add tests for new functionality
- Update documentation for API changes
- Run security checks before submitting (`cargo clippy --all-targets --all-features -- -D warnings -D clippy::all`)
- Consider running fuzzing tests for security-critical changes

## Support

- **Documentation**: See component-specific README files for detailed guides
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join community discussions for help and best practices

## Component Documentation

- [veracode-api](veracode-api/README.md) - API client library documentation
- [verascan](verascan/README.md) - Security scanning CLI documentation
- [veraaudit](veraaudit/README.md) - Audit log retrieval CLI documentation
- [veracmek](veracmek/README.md) - CMEK encryption management CLI documentation
- [fuzz](fuzz/README.md) - Fuzzing infrastructure documentation

---

*Built with ❤️ in Rust for the security community*
