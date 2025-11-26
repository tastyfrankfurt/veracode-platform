# Changelog

All notable changes to verascan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2025-11-26

### Security
- **Comprehensive Defensive Programming**: Production-grade security hardening across entire codebase
  - **Clippy Security Lints**: 15+ defensive programming and security lints enforced at package level
    - `deny(unwrap_used, panic, indexing_slicing, fallible_impl_from, wildcard_enum_match_arm, mem_forget)`
    - `warn(arithmetic_side_effects, cast_possible_truncation, cast_sign_loss, cast_possible_wrap, cast_precision_loss)`
    - `warn(string_slice, expect_used, must_use_candidate, fn_params_excessive_bools)`
    - `warn(missing_errors_doc, missing_panics_doc, missing_safety_doc, doc_markdown)`
  - **Integer Safety**: All arithmetic operations protected against overflow/underflow
    - Replaced all `+`, `-`, `*` operations with `saturating_add()`, `saturating_sub()`, `saturating_mul()`
    - Protected timeout calculations: `timeout_minutes.saturating_mul(60) / poll_interval`
    - Protected index operations: `index.saturating_add(1)`, `len().saturating_sub(1)`
    - Protected progress tracking and byte size formatting
  - **Array/String Safety**: Eliminated all panic-prone indexing and slicing
    - Replaced `arr[i]` with `arr.get(i)` and proper error handling
    - Replaced `str[..n]` with `str.get(..n).unwrap_or(&str)`
    - Protected UTF-8 string boundaries and file path operations
  - **Error Handling**: Eliminated all unwrap/expect calls in production code
    - Replaced with `?` operator and proper error propagation
    - Added fallbacks for optional values: `unwrap_or_else()`, `map_or_else()`
    - Safe handling of `None` cases throughout
  - **Precision Loss Handling**: Documented all intentional float conversions
    - Annotated with `#[allow(clippy::cast_precision_loss)]` where bytes→MB/GB conversion is acceptable
    - Added comments explaining why precision loss is safe for human-readable display
  - **Modified Files**: `Cargo.toml`, `src/assessment.rs`, `src/baseline.rs`, `src/cli.rs`, `src/credentials.rs`,
    `src/export.rs`, `src/filefinder.rs`, `src/filevalidator.rs`, `src/findings.rs`, `src/gitlab_*.rs`,
    `src/graphql_client.rs`, `src/http_client.rs`, `src/main.rs`, `src/path_resolver.rs`, `src/pipeline.rs`,
    `src/scan.rs`, `src/test_utils.rs`, `src/vault_client.rs`, `examples/*.rs`, `tests/proxy_integration_test.rs`

### Testing
- **36,900+ Property-Based Security Test Cases**: Comprehensive fuzzing with proptest across 45 security properties
  - **Baseline Module** (`src/baseline.rs`): 12 property tests × 1,000 cases = 12,000 test cases
    - Severity level bounds checking (all u32 values, 0-5 range validation)
    - Finding count overflow handling (usize → u32 conversion safety)
    - Net change calculation (i32 underflow/overflow prevention)
    - CWE ID validation (SQL injection, XSS patterns)
    - Hash collision resistance (SHA-256 uniqueness across extreme inputs)
    - String comparison safety (Unicode, control characters, empty strings)
    - JSON serialization safety (nested structures, special chars)
    - Collection operations (extreme sizes, boundary conditions)
  - **CLI Module** (`src/cli.rs`): 9 property tests × 1,000 cases = 9,000 test cases
    - Thread count bounds (2-10 range, overflow prevention, u32::MAX handling)
    - Timeout validation (0-u32::MAX, wraparound prevention)
    - File filter patterns (injection, path traversal, malicious globs)
    - Project name/URL validation (XSS, injection, control characters)
    - CMEK alias validation (Unicode, special chars, length bounds)
    - Severity filter validation (0-5 range, out-of-bounds rejection)
  - **Credentials Module** (`src/credentials.rs`): 5 property tests × 1,000 cases = 5,000 test cases
    - Validator panic prevention (all ASCII inputs 0-256 chars)
    - Alphanumeric string validation (1-128 chars always valid)
    - Non-alphanumeric rejection (injection prevention, control chars)
    - Validator consistency (ASCII vs UTF-8 validators agree)
    - Unicode whitespace rejection (U+00A0, U+3000, zero-width chars)
  - **Export Module** (`src/export.rs`): 9 property tests × 100 cases = 900 test cases
    - File path sanitization (traversal prevention, null bytes, Unicode)
    - Export format validation (JSON/CSV/GitLab SAST enum safety)
    - Severity bounds checking (0-5 validation, out-of-range rejection)
    - Filename generation safety (special chars, path separators)
    - Configuration validation (format/severity combinations)
  - **File Finder Module** (`src/filefinder.rs`): 10 property tests × 1,000 cases = 10,000 test cases
    - Path canonicalization safety (traversal, symlinks, absolute paths)
    - Max depth enforcement (0-10 range, overflow prevention)
    - Large file set handling (1-10,000 files without panic)
    - Glob pattern injection prevention (malicious patterns, wildcards)
    - UTF-8 path handling (Unicode normalization, invalid sequences)
    - Symlink attack prevention (circular links, escape attempts)
  - **100% Success Rate**: All 276 unit tests + 36,900 property-based test cases passing
  - **Miri-Compatible**: Tests run cleanly under Rust's undefined behavior detector (reduced to 10 cases/test for Miri)

### Changed
- **Code Quality**: Improved error documentation throughout
  - Added `/// # Errors` documentation to all fallible public functions
  - Enhanced panic documentation with `/// # Panics` sections
  - Improved inline comments explaining security-critical decisions
- **Test Infrastructure**: Added proptest development dependency for property-based testing

### Dependencies
- Updated `veracode-platform` dependency to 0.7.5 (benefits from upstream security hardening)
- Added `proptest = "1.5"` as dev dependency for property-based testing

## [0.6.4] - 2025-11-21

### Changed
- **veracode-platform Dependency Update**: Updated to version 0.7.5 for comprehensive security hardening
  - **Enhanced Security**: Benefits from security hardening across all API modules
  - **Improved Testing**: Leverages comprehensive security testing with proptest, miri, and kani
  - **Better Reliability**: Improved error handling and input validation throughout the platform
  - **Modified Files**: `Cargo.toml`

### Dependencies
- Updated `veracode-platform` dependency from 0.7.4 to 0.7.5

## [0.6.3] - 2025-11-12

### Changed
- **veracode-platform Dependency Update**: Updated to version 0.7.4 for enhanced policy compliance features
  - **Build-Specific Policy Checks**: Now supports checking policy compliance for specific builds via the new `build_id` parameter
  - **Enhanced API Compatibility**: Leverages new policy API methods with flexible build selection
  - **Current Implementation**: Assessment workflows continue to check latest builds by passing `None` for `build_id`
  - **Future Flexibility**: Infrastructure now in place to support build-specific policy verification when needed
  - **Modified Files**: `Cargo.toml`, `src/assessment.rs`

### Dependencies
- Updated `veracode-platform` dependency from 0.7.1 to 0.7.4

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
