# Changelog

All notable changes to verascan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
