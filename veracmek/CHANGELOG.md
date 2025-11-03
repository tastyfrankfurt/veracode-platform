# Changelog

All notable changes to veracmek will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.10] - 2025-11-03

### Security
- **Indirect Security Improvements**: Benefits from security hardening in veracode-api library
  - Enhanced HTML tag stripping prevents XSS vulnerabilities
  - JSON depth validation prevents DoS attacks from deeply nested structures
  - All Veracode API interactions protected by improved security measures

### Changed
- **Dependency Migration**: Migrated from unmaintained `backoff` crate to actively maintained `backon` crate
  - **Security**: Resolved RUSTSEC-2025-0012 (backoff unmaintained) and RUSTSEC-2024-0384 (instant unmaintained)
  - **Modern API**: Updated retry logic to use backon's fluent `.retry().when()` API instead of callback-based approach
  - **Same Behavior**: All retry logic and error handling semantics preserved - no functional changes
  - **Improved Code**: Cleaner, more maintainable retry patterns with method chaining
  - **Dependencies**: Changed from `backoff = "0.4"` to `backon = "1.3"`
  - **Modified Files**: `Cargo.toml`, `src/vault_client.rs`

### Testing
- **100% Test Coverage**: All 104 tests passing after migration
- **Updated Tests**: Refactored retry logic tests to work with new backon API
- **Validation**: Comprehensive testing of all HTTP status codes and error scenarios

## [0.5.9] - 2025-11-01

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

## [0.5.8] - 2025-10-23

### Enhanced
- **Production-Grade Logging**: Improved log formatting for operational clarity
  - **Removed Debug Formatting**: Replaced `:?` with clean formatting in all logs
  - **Path Display**: File paths now use `.display()` for proper formatting instead of debug output
  - **Command Line Args**: Application startup arguments use `.join(" ")` for clean, readable output
  - **Examples**:
    - File path: `./apps.json` instead of `"./apps.json"` (quoted debug format)
    - Args: `[veracmek enable --app MyApp]` instead of debug iterator representation
  - **Modified Files**: `src/main.rs` (startup logging, file processing)

### Technical Details
- Updated `info!` and `debug!` logs to use Display formatter (`{}`) instead of Debug formatter (`:?`)
- Replaced `std::env::args()` debug format with collected and joined string
- File paths now use `.display()` method for clean path formatting

### Benefits
- **Operational Excellence**: Clean log output for monitoring and troubleshooting
- **User Experience**: More readable logs for operators managing CMEK operations
- **Production Ready**: Follows Rust best practices for production logging

## [0.5.7] - 2025-10-15

### Added
- **HTTP/HTTPS Proxy Support**: Comprehensive proxy support for corporate network environments
  - **Standard Environment Variables**: Supports `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy`
  - **Proxy Authentication**: Optional username/password authentication via `PROXY_USERNAME` and `PROXY_PASSWORD`
  - **Vault Integration**: Proxy credentials can be stored in Vault secrets (`proxy_url`, `proxy_username`, `proxy_password`)
  - **Credential Hierarchy**: Vault credentials take precedence over environment variables
  - **Automatic Detection**: Automatically configures proxy from Vault or environment variables
  - **Non-Authenticated Proxies**: Full support for proxies without authentication
  - **Certificate Validation**: Proxy configuration preserves existing TLS certificate trust behavior
  - **Backward Compatible**: No breaking changes to existing configuration

### Technical Details
- **Modified Files**: `src/credentials.rs`, `src/vault_client.rs`
- **Credential Loading**: New `load_credentials_and_proxy_from_vault()` function for combined credential retrieval
- **Configuration Methods**: New `create_veracode_config_with_proxy()` function for applying proxy credentials
- **Environment Variables**: Updated `configure_veracode_with_env_vars()` to load proxy configuration
- **Vault Secret Fields**: Added support for optional `proxy_url`, `proxy_username`, and `proxy_password` in Vault secrets
- **Priority System**: Vault proxy config → Environment variables → Direct connection

## [0.5.6] - 2025-10-14

### Changed
- **Open Source Licensing**: Updated to dual MIT OR Apache-2.0 licensing
  - **License Field Added**: Added `license = "MIT OR Apache-2.0"` to Cargo.toml
  - **Alignment with Workspace**: Matches licensing used by veracode-api and verascan packages
  - **Rust Ecosystem Standard**: Follows standard dual-licensing practice in Rust community
  - **User Choice**: Users can choose to use the software under either MIT or Apache-2.0 terms
  - **Legal Compatibility**: Enhanced legal flexibility for commercial and open source integration
  - **No Functional Changes**: This is purely a licensing update with no code modifications

### Technical Details
- **Modified Files**: `Cargo.toml` (added license field)
- **License Files**: Project includes both `LICENSE-MIT` and `LICENSE-APACHE` at workspace root
- **Documentation**: README.md contains dual licensing notice for user clarity

## [0.5.5] - 2025-10-10 - First Release

### Added
- **Initial Release**: First release of veracmek - Customer Managed Encryption Key (CMEK) CLI Tool
- **Core CMEK Operations**: Complete command-line interface for managing application encryption
  - **`enable`**: Enable CMEK encryption on individual applications by name or GUID
  - **`change-key`**: Change encryption keys for applications that already have CMEK enabled
  - **`status`**: Check encryption status of individual applications or all applications in account
  - **`bulk`**: Enable CMEK on all applications in the account with dry-run support
  - **`from-file`**: Process applications from JSON configuration files for batch operations
  - **`help-env`**: Display comprehensive environment variable and configuration help

- **Multi-Authentication Support**: Flexible credential management for different environments
  - **Environment Variables**: Standard `VERACODE_API_ID` and `VERACODE_API_KEY` support
  - **CLI Arguments**: Direct credential specification via `--api-id` and `--api-key` flags
  - **HashiCorp Vault Integration**: Secure credential retrieval with comprehensive vault configuration
    - JWT-based authentication with configurable roles and auth paths
    - Secure secret retrieval with automatic token revocation
    - Support for custom vault namespaces and secret engines
    - Exponential backoff retry logic for vault operations
    - Certificate validation override for development environments

- **Output Formats**: Flexible output options for different use cases
  - **Table Format**: Human-readable console output with emojis and status indicators (default)
  - **JSON Format**: Machine-readable output for automation and integration workflows
  - **Structured Logging**: Configurable log levels with detailed operation tracking

- **Advanced Features**:
  - **Dry Run Mode**: Preview changes before applying with `--dry-run` flag
  - **Skip Encrypted Apps**: Intelligent filtering with `--skip-encrypted` flag for bulk operations
  - **Multi-Region Support**: Support for Commercial, European, and Federal Veracode regions
  - **Application Discovery**: Find applications by exact name or GUID with intelligent fallback
  - **KMS Alias Validation**: Comprehensive AWS KMS alias format validation
  - **Progress Reporting**: Detailed progress tracking for bulk operations

- **File-Based Configuration**: JSON configuration support for complex scenarios
  - **Application Lists**: Process multiple applications with individual KMS aliases
  - **Conditional Processing**: Per-application `skip_if_encrypted` settings
  - **Batch Operations**: Efficient processing of large application sets
  - **Validation**: Comprehensive input validation and error reporting

- **Error Handling & Resilience**: Production-ready error handling and recovery
  - **Comprehensive Error Types**: Detailed error classification and context
  - **Retry Logic**: Automatic retry with exponential backoff for transient failures
  - **Graceful Degradation**: Intelligent handling of API limitations and temporary outages
  - **User-Friendly Messages**: Clear error messages with actionable guidance

- **Security Features**:
  - **Secure Credential Handling**: Uses `secrecy` crate for protecting sensitive data in memory
  - **Vault Token Management**: Automatic token revocation after credential retrieval
  - **Input Validation**: Comprehensive validation of all user inputs and configuration
  - **Certificate Validation**: HTTPS enforcement with development override option

### Technical Implementation
- **Architecture**: Built on Rust 2024 edition with modern async/await patterns
- **Dependencies**:
  - **CLI Framework**: `clap` for argument parsing and command structure
  - **Async Runtime**: `tokio` for high-performance concurrent operations
  - **Serialization**: `serde` and `serde_json` for robust data handling
  - **API Client**: `veracode-platform` crate for Veracode API integration
  - **Vault Client**: `vaultrs` for secure HashiCorp Vault integration
  - **Error Handling**: `thiserror` and `anyhow` for comprehensive error management
  - **Logging**: `env_logger` and `log` for structured logging
  - **Retry Logic**: `backoff` for exponential backoff patterns
  - **Security**: `secrecy` for secure handling of sensitive data

### Usage Examples

#### Basic Operations
```bash
# Enable CMEK on a single application
veracmek enable --app "My Application" --kms-alias "alias/my-cmek-key"

# Check encryption status
veracmek status --app "My Application"
veracmek status  # Check all applications

# Change encryption key
veracmek change-key --app "My Application" --new-kms-alias "alias/new-key"
```

#### Bulk Operations
```bash
# Dry run to preview changes
veracmek bulk --kms-alias "alias/production-key" --dry-run

# Apply to all applications, skipping already encrypted ones
veracmek bulk --kms-alias "alias/production-key" --skip-encrypted
```

#### File-Based Processing
```bash
# Process applications from JSON configuration
veracmek from-file --file apps.json --dry-run
veracmek from-file --file apps.json
```

#### Using with Vault
```bash
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="your_jwt_token"
export VAULT_CLI_ROLE="veracode-role"
export VAULT_CLI_SECRET_PATH="secret/veracode@kvv2"

# Commands automatically use Vault for credentials
veracmek status
```

### Configuration
- **Environment Variables**: Comprehensive environment variable support for all configuration options
- **JSON File Format**: Well-defined JSON schema for batch application processing
- **Region Support**: Automatic endpoint routing for different Veracode regions
- **Development Mode**: Certificate validation override for development environments

### Documentation
- **Comprehensive README**: Complete usage guide with examples and security considerations
- **Built-in Help**: Extensive help system with `help-env` command for configuration guidance
- **Error Context**: Detailed error messages with specific guidance for resolution

### Features Summary
- 🔐 **CMEK Management** - Complete lifecycle management for customer-managed encryption keys
- 🌍 **Multi-Regional** - Support for all Veracode regions (Commercial, European, Federal)
- 🔄 **Bulk Operations** - Efficient processing of multiple applications with safety features
- 📁 **File-Based Config** - JSON configuration files for complex batch operations
- 🔑 **Vault Integration** - Secure credential management with HashiCorp Vault
- 📊 **Multiple Output Formats** - Table and JSON output for different use cases
- 🚀 **High Performance** - Async/await architecture for concurrent operations
- 🛡️ **Security First** - Comprehensive input validation and secure credential handling
- 🔧 **Production Ready** - Robust error handling, retry logic, and comprehensive logging
- 📖 **Well Documented** - Extensive documentation and built-in help system