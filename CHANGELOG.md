# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2025-07-28

### Added
- **Sandbox Name Forward Slash Support**: Enhanced CLI to accept forward slashes in sandbox names
  - Added `validate_sandbox_name` function that automatically replaces forward slashes (/) with underscores (_)
  - Updated `--sandbox-name` CLI option to accept names like `feature/bug-fix` → `feature_bug-fix`
  - Provides user feedback showing the transformation when replacements occur
  - Maintains all existing validation rules (length ≤ 70 characters, valid characters only)
  - Improves workflow integration with Git branch names and CI/CD pipelines

### Fixed
- **Double Slash URL Bug**: Fixed URL construction issue in HTTP client methods
  - Corrected `format!("{}/{}", base_url, endpoint)` to `format!("{}{}", base_url, endpoint)` in 5 client methods
  - Affects `post_with_query_params`, `get_with_query_params`, `upload_file_with_query_params`, `upload_large_file_chunked`, and `upload_file_binary`
  - Resolves malformed URLs like `https://api.veracode.com//api/5.0/deletebuild.do` that occurred when base_url ends with "/" and endpoint starts with "/"
  - Fixes build operations (create, update, delete, info retrieval) and file upload operations
  - Issue primarily manifested after deleting existing builds in build lifecycle operations
- **Build Recreation Race Condition**: Fixed timing issue in build deletion and recreation workflow
  - Added `wait_for_build_deletion` method with retry logic to ensure build is fully deleted before recreation
  - Implements 5 attempts with 3-second delays (15 seconds maximum wait time) to verify build deletion
  - Resolves build creation failures that occurred immediately after deleting existing builds
  - Fixed workflow in `ensure_build_exists_with_policy` method in `workflow.rs:824-840`
  - Addresses API eventual consistency issues where delete operations succeed but backend systems haven't fully synchronized

## [0.2.0] - 2025-07-28

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