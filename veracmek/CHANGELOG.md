# Changelog

All notable changes to veracmek will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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