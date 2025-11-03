# Changelog

All notable changes to verascan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.2] - 2025-11-03

### Security
- **Input Validation Hardening**: Comprehensive security improvements across CLI validators
  - **Project URL Validation**: Added control character and Unicode whitespace rejection to `validate_project_url()`
    - Rejects control characters (newlines, carriage returns, null bytes, tabs)
    - Rejects non-ASCII whitespace (non-breaking space U+00A0, ideographic space U+3000)
    - Rejects zero-width and format characters (U+200B, U+200C, U+200D, U+FEFF)
    - Prevents injection attacks and ensures clean URL input
  - **CMEK Alias Validation**: Enhanced `validate_cmek_alias()` security
    - Rejects Unicode whitespace characters
    - Rejects control characters in alias names
    - Rejects leading/trailing whitespace
    - 44+ new security tests for edge cases
  - **API Credential Validation**: Comprehensive testing of credential validators
    - Added tests for `validate_api_credential()` rejecting special characters
    - Added tests for rejecting Unicode whitespace and control characters
    - Added tests for `validate_api_credential_ascii()` validation
    - 27+ new security tests for credential validation
  - **Modified Files**: `src/cli.rs`, `src/credentials.rs`

### Testing
- **90+ New Security Tests**: Comprehensive fuzzing-discovered edge case coverage
  - Project URL validation tests (9 tests)
  - CMEK alias validation tests (8 tests)
  - API credential validation tests (10 tests)
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
- **100% Test Coverage**: All 189 tests passing after migration
- **Updated Tests**: Refactored retry logic tests to work with new backon API
- **Validation**: Comprehensive testing of all HTTP status codes and error scenarios
- **Bug Fix**: HTTP 501 (Vault not initialized) now correctly classified as non-retryable

## [0.6.1] - 2025-11-01

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

## [0.6.0] - 2025-10-30

### Added
- **Customer Managed Encryption Key (CMEK) CLI Support**: Enable AWS KMS encryption for application profiles
  - **New CLI Flag**: `--cmek <ALIAS>` for Assessment command to specify AWS KMS alias during application creation
  - **User-Friendly**: Simple CLI option (e.g., `--cmek alias/my-app-key`) for enabling encryption
  - **Validation**: Input validation for AWS KMS alias format
    - Allowed characters: `[a-zA-Z0-9-/_]`
    - Length: 8-256 characters
    - Clear error messages for invalid input
  - **Optional**: Only applies encryption when flag is specified, otherwise default behavior
  - **Modified Files**: `src/cli.rs`, `src/scan.rs`

### Testing
- **3 New Validation Tests**: Comprehensive CLI validation test coverage
  - `test_validate_cmek_alias_valid`: Tests various valid alias formats
  - `test_validate_cmek_alias_invalid_length`: Tests length boundary conditions
  - `test_validate_cmek_alias_invalid_characters`: Tests character validation

### Usage
```bash
# Create application profile with CMEK enabled
verascan assessment \
  --app-profile-name "MyApplication" \
  --cmek "alias/my-encryption-key" \
  --filepath ./target

# Create application profile without CMEK (default)
verascan assessment \
  --app-profile-name "MyApplication" \
  --filepath ./target
```

### Dependencies
- Updated `veracode-platform` dependency to 0.7.0 for CMEK support

## [0.5.10] - Previous Release

See git history for previous changes.
