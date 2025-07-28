# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-01-XX

### Added
- **Alpine Linux Container Support**: Added musl static linking for Alpine container compatibility
  - New `x86_64-unknown-linux-musl` build target for fully static binaries
  - Rustls TLS implementation replacing OpenSSL dependencies
  - Static linking configuration in `.cargo/config.toml` for musl target
- **Enhanced GitHub Actions workflows**
  - `build.yml`: Multi-platform CI testing (Linux glibc/musl, Windows, macOS ARM)
  - `multiplatform.yml`: Cross-platform release builds with both glibc and musl variants

### Changed
- **Dependency Management**: Replaced OpenSSL with Rustls across all HTTP clients
  - Updated `reqwest` to use `rustls-tls-native-roots` feature in workspace and verascan
  - Eliminated native OpenSSL dependencies for better container compatibility
- **Build System**: Enhanced multi-platform build support
  - Updated `build.sh` script with musl target and improved artifact naming
  - Modified GitHub Actions to support both glibc and musl Linux builds

## [0.1.0] - 2024-XX-XX

### Added
- Initial release of veracode-workspace
- Comprehensive Veracode API client library
- verascan CLI application for security scanning
- GitLab integration for issue creation and SAST reports
- Pipeline scanning capabilities
- Baseline comparison functionality
- Multi-format export support (JSON, CSV, GitLab SAST)
- Policy management and enforcement
- Concurrent file processing and scanning
- Support for multiple Veracode regions
- Comprehensive test coverage
- GitHub Actions workflows for automated CI/CD and releases
  - `build.yml`: Continuous integration with formatting checks, clippy linting, and testing
  - `release.yml`: Simple release workflow for tagged releases  
- Comprehensive security improvements for sensitive token handling
  - `SecureToken` wrapper in `gitlab_issues.rs:14-36` to prevent token exposure
  - Custom Debug trait implementation for `GitLabConfig` in `gitlab_issues.rs:78-95`
  - Secure token access methods throughout the codebase
- Enhanced Git URL logging with password redaction
  - `redact_url_password` function in `scan.rs:324-347` for safe URL logging
  - Password redaction showing `username:[REDACTED]@host` format
- Improved GitLab integration
  - Project name resolution using GitLab API instead of "Unknown" fallback
  - Fixed GitLab issue line number linking by removing `ref_type=heads` parameter
  - Enhanced URL generation for better GitLab integration

### Changed
- Updated GitLab project name resolution to use actual project name from GitLab API
- Improved security token handling across all components
- Enhanced error handling and logging throughout the codebase
- Updated file discovery and validation processes

### Fixed
- Variable scope error in GitLab issues functionality
- GitLab URL linking issues with line numbers
- Token exposure vulnerability in debug logs
- Password exposure in Git remote URL logging

### Security
- **Comprehensive Token Security**: Implemented secure wrappers for all sensitive credentials
  - `SecureToken` wrapper for GitLab private tokens in `gitlab_issues.rs`
  - `SecureApiCredentials`, `SecureApiId`, and `SecureApiKey` wrappers for Veracode API credentials in `credentials.rs`
  - `SecureVeracodeApiId` and `SecureVeracodeApiKey` wrappers in veracode-api package
- **Automatic Debug Redaction**: All sensitive tokens show `[REDACTED]` in debug output
- **Enhanced URL Logging**: Git URLs with passwords redacted as `username:[REDACTED]@host`
- **Comprehensive Test Coverage**: 18+ new tests covering all secure credential functionality
- **Backward Compatibility**: All existing code continues to work unchanged
- **Custom Debug Implementations**: Secure debug traits for all credential-containing structures