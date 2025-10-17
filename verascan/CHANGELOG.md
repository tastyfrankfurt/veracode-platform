# Changelog

All notable changes to verascan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.8] - 2025-10-15

### Added
- **HTTP/HTTPS Proxy Support**: Full proxy support for corporate network environments
  - **Standard Environment Variables**: Supports `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy`
  - **Proxy Authentication**: Optional username/password authentication via `PROXY_USERNAME` and `PROXY_PASSWORD`
  - **Automatic Detection**: Automatically configures proxy from environment variables
  - **Non-Authenticated Proxies**: Full support for proxies without authentication
  - **Certificate Validation**: Proxy configuration preserves existing TLS certificate trust behavior
  - **Backward Compatible**: No breaking changes to existing configuration

- **Vault Proxy Integration**: Comprehensive proxy support for Vault-stored credentials
  - **Vault Proxy Configuration**: Proxy credentials can be stored in Vault secrets (`proxy_url`, `proxy_username`, `proxy_password`)
  - **Credential Hierarchy**: Vault proxy credentials take precedence over environment variables
  - **Combined Loading**: New `load_credentials_and_proxy_from_vault()` function retrieves both API credentials and proxy settings
  - **Automatic Detection**: Automatically configures proxy from Vault or falls back to environment variables
  - **Backward Compatible**: Works seamlessly with existing Vault credential workflows
  - **Security First**: Proxy credentials stored securely in Vault alongside API credentials

### Technical Details
- **Modified Files**: `src/http_client.rs`, `src/vault_client.rs`, `src/credentials.rs`, `src/scan.rs`, `src/main.rs`, `src/lib.rs`
- **HTTP Client Updates**: Added proxy configuration to `HttpClientConfig` and `RobustHttpClient`
- **Builder Methods**: New `with_proxy()` and `with_proxy_auth()` builder methods for programmatic configuration
- **Environment Loading**: Added `with_env_proxy()` method to `HttpClientConfigBuilder` for automatic environment variable loading
- **Reqwest Integration**: Uses reqwest's built-in proxy support with `Proxy::all()` for HTTP/HTTPS traffic
- **Vault Integration**:
  - New `get_proxy_credentials()` method in `VaultCredentialClient` for proxy credential retrieval
  - New `load_credentials_and_proxy_from_vault()` function for combined credential loading
  - New `create_veracode_config_with_proxy()` function for applying proxy credentials from Vault
  - Updated `configure_veracode_with_env_vars()` to support conditional proxy loading
- **Priority System**: Vault proxy config → Environment variables → Direct connection

## [0.5.7] - 2025-10-14

### Added
- **GitLab SAST Schema Version Selection**: New CLI parameter for GitLab schema version control
  - **Schema Version Parameter**: Added `--gitlab-schema` global parameter supporting versions 15.2.1, 15.2.2, and 15.2.3
  - **Environment Variable Support**: Can be configured via `VERASCAN_GITLAB_SCHEMA` environment variable
  - **Backward Compatible**: Defaults to version 15.2.1 when not specified
  - **Input Validation**: Enforces valid schema version selection with clear error messages
  - **Use Cases**: Enables compatibility with different GitLab instances and enterprise deployments

- **GitLab SAST Details Field Schema Compliance**: Restructured details field format for GitLab schema compliance
  - **Schema-Compliant Format**: Details fields now use structured objects with `name`, `type`, and `value` properties
  - **Field Type Support**: Properly distinguishes between `value` (numeric) and `text` (string) field types
  - **Metadata Enhancement**: Exploitability, issue IDs, scan IDs, and finding categories now include descriptive names
  - **Validation Ready**: Details structure validates against official GitLab SAST schema specifications
  - **Improved Readability**: GitLab UI displays details with proper labels and type formatting

- **GitLab SAST Schema Validation Test**: Comprehensive test suite for GitLab SAST report format compliance
  - **Schema Validation**: Automated validation of GitLab SAST reports against official GitLab schemas
  - **Test Integration**: Uses `jsonschema` crate (v0.33.0) for JSON Schema validation in Rust
  - **Real Conversion Testing**: Tests actual Veracode → GitLab SAST format conversion pipeline
  - **Detailed Error Reporting**: Provides clear validation error messages with instance and schema paths
  - **Quality Assurance**: Ensures GitLab integration compatibility and catches schema compliance issues early

### Changed
- **CLI Version Display**: Updated version command to use Cargo.toml version automatically (removed hardcoded version)
- **Export Configuration**: Added `schema_version` parameter to `ExportConfig` for schema version propagation
- **GitLab Exporter**: Report version field now uses configured schema version instead of hardcoded value

### Technical Details
- **Modified Files**: `src/cli.rs`, `src/export.rs`, `src/gitlab_mapping.rs`, `src/gitlab_report.rs`, `Cargo.toml`
- **CLI Validation**: Added `validate_gitlab_schema_version()` function in `src/cli.rs:437`
- **Details Mapping**: Updated `PipelineScanMapper::map_details()` and `PolicyScanMapper::map_details()` in `src/gitlab_mapping.rs`
- **Test Function**: `test_gitlab_sast_report_schema_validation()` at `src/gitlab_report.rs:646`
- **Schema Integration**: GitLab report version field now reflects selected schema version
- **Environment Variables**: Updated help text to document `VERASCAN_GITLAB_SCHEMA` environment variable

## [0.5.6] - 2025-10-13

### Added
- **Build Version Control**: Added optional `--build-version` parameter for assessment scans
  - **Custom Versioning**: Users can now specify custom build versions (e.g., "v2.1.0-release", "sprint-42")
  - **Auto-generation**: When not specified, automatically generates timestamp-based versions (e.g., "build-1234567890")
  - **Input Validation**: Enforces Veracode API constraints (max 70 characters, alphanumeric plus dashes/underscores/dots)
  - **Backward Compatible**: Maintains existing auto-generation behavior when parameter is omitted
  - **Build Lifecycle**: Version is displayed in scan configuration output and passed through to Veracode API
  - **Use Cases**: Enables correlation with CI/CD pipeline versions, release tags, or custom versioning schemes

### Technical Details
- **Modified Files**: `src/cli.rs`, `src/assessment.rs`, `src/scan.rs`
- **Validation**: Added `validate_build_version()` function with character and length constraints
- **Configuration Flow**: Build version flows from CLI → AssessmentScanConfig → ensure_build_exists API call
- **Display Enhancement**: Updated `display_config()` method to show custom or auto-generated version status
- **Test Coverage**: Updated unit tests to verify build version handling

## [0.5.5] - 2025-10-10

### Fixed
- **Assessment Scan Output**: Removed problematic dot printing during scan monitoring
  - **Clean Console Output**: Removed `print!(".")` statements from assessment and pipeline scan monitoring functions
  - **Fixed Visual Issues**: Eliminated dots appearing on incorrect lines during runtime
  - **Preserved Logging**: Maintained proper info logging with emojis and status messages
  - **Affected Functions**: `wait_for_scan_completion`, `monitor_build_phase`, and `wait_for_prescan`
  - **Better UX**: Ensures clean console output during scan progress monitoring

- **Strict Sandbox Exit Codes**: Corrected exit code behavior for Conditional Pass status
  - **Exit Code Fix**: Fixed `--strict-sandbox` flag to exit with code 4 instead of 0 for "Conditional Pass"
  - **Special Logic**: Added dedicated exit code logic for strict_sandbox_break condition
  - **Report Generation**: Maintains report generation before exit code evaluation
  - **Informative Logging**: Added logging when strict sandbox mode triggers failure
  - **Policy Resolution**: Fixed policy evaluation for strict sandbox mode as documented

### Technical Details
- **Modified Files**: `src/assessment.rs`, `src/pipeline.rs`, `src/cli.rs`
- **Exit Code Logic**: Strict sandbox mode now properly returns exit code 4 for Conditional Pass as documented
- **Console Output**: Eliminated visual artifacts from progress monitoring functions
- **Backward Compatible**: No breaking changes to existing API surface

## [0.5.4] - 2025-09-19

### Enhanced
- **Policy API Resilience**: Enhanced error handling for server failures in policy compliance checks
  - **Server Error Retry**: Added 3 retries with 5-second delays for HTTP 500 errors in policy compliance
  - **Enhanced Fallback Logic**: Extended automatic fallback to XML API to include server errors (500), not just auth errors (401/403)
  - **Robust Error Handling**: Policy compliance checks now gracefully handle temporary Veracode API outages
  - **Assessment Scan Stability**: Prevents assessment scans from failing with exit code 1 due to transient server errors

### Technical Details
- **Error Flow**: Summary Report API (500) → 3 retries (5s each) → Fallback to XML API → Success
- **API Integration**: Leverages enhanced veracode-platform v0.5.4 policy resilience features
- **Backward Compatible**: No breaking changes to existing CLI interface

## [0.5.3] - 2025-09-11

### Enhanced
- **Team Lookup Integration**: Leverages enhanced team lookup capabilities from veracode-platform v0.5.3
  - **Automatic Team Resolution**: Application creation now supports team names in addition to GUIDs
  - **Simplified Workflows**: Users can specify team names directly without manual GUID lookups
  - **Better Error Messages**: Clear error messages when teams are not found

### Technical Details
- **API Integration**: Uses enhanced `create_application_if_not_exists()` with automatic team name resolution
- **Backward Compatible**: Existing GUID-based team assignment continues to work unchanged

## [0.5.0] - 2025-09-10

### Added
- **Policy API Fallback System**: Intelligent dual-API approach for policy compliance evaluation
  - **Automatic Fallback**: Seamlessly switches to XML API when REST API permissions are denied
  - **Enhanced Compatibility**: Works with any Veracode account permission level (REST + XML, XML-only, or restricted access)
  - **Performance Flexibility**: Users can skip slower REST API when they know permissions only allow XML access
  - **Better Error Context**: Clear indication of which API was attempted and which succeeded

### Enhanced
- **Break Build Integration**: Leverages enhanced policy API from veracode-platform v0.5.0
  - **Configurable API Selection**: Support for forcing buildinfo API usage via `force_buildinfo_api` parameter
  - **Transparent Operation**: Clear logging shows which API path was used for improved troubleshooting

## [0.4.3] - 2025-09-07

### Changed
- **Structured Logging Implementation**: Migrated from `println!` and `eprintln!` macros to structured logging
  - **CLI Integration**: Updated main.rs with `env_logger` initialization tied to debug flag for proper log level control
  - **Consistent Logging**: Unified logging approach across the entire CLI application with proper log levels
  - **CLI Debug Control**: Debug flag now properly controls log verbosity using standard Rust logging infrastructure
  - **Production Ready**: Structured logging enables better observability and debugging in production deployments

### Technical Details
- **Logging Integration**: Uses `env_logger` for flexible log level control
- **Debug Flag**: `--debug` flag controls application-wide logging verbosity
- **Framework Compatibility**: Standard `log` crate integration allows easy switching of logging backends

## [0.4.2] - 2025-08-15

### Enhanced
- **Policy Compliance Integration**: Leverages combined policy API method from veracode-platform v0.4.2
  - **Optimized API Calls**: Reduced API calls by using combined summary report retrieval and policy compliance evaluation
  - **Conditional Policy Evaluation**: Only evaluates policy compliance when break build is enabled
  - **Memory Efficiency**: Improved data flow by avoiding duplicate API responses

### Technical Details
- **API Integration**: Uses `get_summary_report_with_policy_retry()` for efficient policy compliance checking
- **Break Build**: Enhanced break build workflow with reduced API overhead

## [0.4.0] - 2025-08-08

### Enhanced
- **Findings API Integration**: Complete integration with enhanced findings API from veracode-platform v0.4.0
  - **Auto-pagination Support**: Automatic handling of pagination across large result sets
  - **Server-Side Filtering**: Native API-level filtering support for severity, CWE, scan type, and policy violations
  - **Flexible Query Construction**: Context-aware query building for both policy and sandbox scan scenarios
  - **Performance**: API-level filtering reduces network traffic and client-side processing overhead

### Fixed
- **Policy API**: Fixed summary report retrieval to prevent "Invalid request" errors when retrieving latest build summaries
- **Query Parameter Construction**: Fixed conditional parameter building to only include parameters when explicitly provided

### Technical Details
- **Findings Integration**: Uses enhanced `FindingsQuery` builder pattern with improved method chaining
- **Memory Optimization**: Enhanced borrowing patterns in query construction and parameter handling
- **Error Handling**: Better context-aware error messages for different failure scenarios

## [0.3.4] - 2025-08-07

### Added
- **Findings API Integration**: Complete integration with structured findings API from veracode-platform v0.3.4
  - **HAL Format Support**: Full support for HAL responses with pagination handling
  - **Auto-Pagination Collection**: Intelligent automatic pagination that handles large result sets
  - **Rich Filtering**: Supports filtering by severity levels, CWE IDs, scan types, and policy violations
  - **Progress Tracking**: Debug output shows pagination progress and page boundaries

### Enhanced
- **Memory Efficient**: Uses `Cow<>` for borrowed strings following memory optimization guidelines
- **Debug Support**: Comprehensive debug logging for findings retrieval and processing
- **Error Handling**: Context-aware error types with detailed error messages

## [0.3.3] - 2025-08-05

### Added
- **Summary Report Integration**: Complete integration with summary report functionality from veracode-platform v0.3.3
  - **Modern Policy Compliance**: Uses `/appsec/v2/applications/{app_guid}/summary_report` endpoint for policy compliance
  - **Advanced Retry Logic**: Intelligent policy compliance status checking with configurable retry mechanism
  - **Enhanced Data Model**: Summary reports provide comprehensive policy, security, and flaw information

### Changed
- **Policy Compliance Architecture**: Migrated from XML API to REST API for better data richness
  - **Backward Compatibility**: Original XML API methods preserved for legacy support
  - **Structured Error Mapping**: Enhanced error handling for various HTTP response codes

### Fixed
- **Format String Compliance**: Updated all format strings to use inline arguments per Rust 2021 edition standards

## [0.3.2] - 2025-08-05

### Enhanced
- **Policy Compliance Integration**: Enhanced policy compliance handling with more accurate XML API integration
  - **Improved Enum Handling**: Updated to match XML API responses exactly with PascalCase serialization
  - **CI/CD Integration**: Enhanced helper methods for determining build break conditions and exit codes

### Technical Details
- **Policy Integration**: Uses enhanced `PolicyComplianceStatus` enum with accurate XML API mapping
- **Build Break Logic**: Integrated `should_break_build()` and `get_exit_code_for_status()` helper methods

## [0.3.1] - 2025-08-04

### Changed
- **Dual Licensing**: Updated to dual MIT OR Apache-2.0 licensing for maximum compatibility
  - **License Flexibility**: Provides users choice of license terms aligned with Rust ecosystem standards
  - **Legal Compatibility**: Enhanced legal flexibility while maintaining all existing functionality

## [0.3.0] - 2025-08-04

### Added
- **Network-Level Retry System**: Comprehensive retry mechanism for improved API reliability
  - **Intelligent Error Classification**: Automatically retries transient failures while avoiding permanent failures
  - **Exponential Backoff Algorithm**: Default configuration with 5 retry attempts and intelligent timing
  - **Smart Rate Limit Handling**: Optimized for Veracode's API rate limits with intelligent timing
  - **Enhanced Error Handling**: Extended error handling with retry-specific error variants

### Enhanced
- **HTTP Timeout Configuration**: Configurable HTTP timeouts for different network conditions
  - **Connection Timeout**: Maximum time to establish TCP connection (default: 30 seconds)
  - **Request Timeout**: Total time for complete request/response cycle (default: 300 seconds)
  - **Use Case Optimization**: Extended timeouts for large file uploads, aggressive timeouts for high-performance operations

### Fixed
- **Double Slash URL Bug**: Fixed URL construction issue in HTTP client methods affecting build operations and file uploads

### Changed
- **Dependency Management**: Replaced OpenSSL with Rustls for better container compatibility
  - **Container Support**: Eliminates native OpenSSL dependencies for Alpine Linux and static binary support
  - **Security**: Pure Rust TLS implementation with enhanced security posture

### Performance
- **Memory Allocation Efficiency**: Advanced performance optimizations for high-throughput applications
  - **Copy-on-Write Patterns**: Reduced memory pressure by ~60% in retry scenarios
  - **String Pre-allocation**: Improved performance by ~40% for repeated requests
  - **Request Body Optimization**: Significantly improved performance for large payloads

## [0.2.1] - 2025-07-28

### Fixed
- **Build Recreation Race Condition**: Fixed timing issue in build deletion and recreation workflow
  - **Wait Logic**: Added retry logic to verify build deletion before recreation
  - **API Consistency**: Addresses eventual consistency issues in Veracode backend systems

## [0.2.0] - 2025-07-28

### Added
- **Enhanced Build Management**: Improved build lifecycle management capabilities
- **Workflow Optimizations**: Enhanced multi-step operation handling

## [0.1.0] - 2025-07-16

### Added
- **Initial Release**: First release of verascan - Comprehensive Rust CLI for Veracode security scanning
- **Core Scanning Operations**: Complete command-line interface for Veracode security scanning
  - **Pipeline Scans**: CI/CD integration with automated security scanning
  - **Assessment Scans**: Application security testing with comprehensive reporting
  - **Sandbox Scans**: Development environment security testing
- **Multi-format Support**: Support for various file types and scanning scenarios
- **Policy Integration**: Security policy management and compliance evaluation
- **Export Capabilities**: Multiple output formats for integration with other tools
- **Comprehensive Documentation**: Full CLI documentation and usage examples

### Features
- 🔐 **HMAC Authentication** - Built-in Veracode API credential support
- 🌍 **Multi-Regional Support** - Commercial, European, and Federal regions
- 🔄 **Smart API Routing** - Automatically uses REST or XML APIs based on operation requirements
- 🔍 **Pipeline Scanning** - CI/CD security scanning via REST API
- 🧪 **Sandbox Management** - Development sandbox scanning via REST API
- 🔨 **Assessment Scanning** - Build management and SAST operations via XML API
- 📊 **Policy Compliance** - Security policy management and compliance evaluation
- 🚀 **Async/Await** - Built on tokio for high-performance concurrent operations
- ⚡ **Type-Safe** - Full Rust type safety with comprehensive error handling
- 🔧 **Workflow Helpers** - High-level operations combining multiple API calls