# Veracmek - Customer Managed Encryption Key (CMEK) CLI Tool

A command-line tool for managing Customer Managed Encryption Keys (CMEK) on Veracode application profiles. This tool enables users to encrypt application data using their own AWS KMS keys, providing enhanced security and compliance for Veracode applications.

## Overview

Veracmek is a Rust-based CLI tool that provides secure management of Customer Managed Encryption Keys for Veracode applications. It supports both individual application encryption and bulk operations, with optional integration with HashiCorp Vault for secure credential management.

## Features

- **Individual Application Encryption**: Enable CMEK on specific applications
- **Bulk Operations**: Process multiple applications at once with dry-run support
- **File-based Configuration**: Process applications from JSON configuration files
- **Encryption Status Checking**: View current encryption status across applications
- **Key Management**: Change encryption keys for existing encrypted applications
- **Vault Integration**: Secure credential retrieval from HashiCorp Vault
- **Multiple Output Formats**: Support for JSON and table output formats
- **Comprehensive Error Handling**: Detailed error reporting and validation

## Installation

### Prerequisites

- Rust 2024 edition
- Veracode API credentials (API ID and Key)
- AWS KMS access with appropriate permissions
- Optional: HashiCorp Vault for secure credential management

### Building from Source

```bash
cd veracmek
cargo build --release
```

The binary will be available at `target/release/veracmek`.

## Configuration

### Authentication

Veracmek supports multiple authentication methods:

#### 1. Environment Variables (Standard)
```bash
export VERACODE_API_ID="your_api_id"
export VERACODE_API_KEY="your_api_key"
```

#### 2. Command Line Arguments
```bash
veracmek --api-id your_api_id --api-key your_api_key [command]
```

#### 3. HashiCorp Vault Integration
Set the following environment variables to use Vault:

```bash
export VAULT_CLI_ADDR="https://vault.example.com"
export VAULT_CLI_JWT="your_jwt_token"
export VAULT_CLI_ROLE="your_vault_role"
export VAULT_CLI_SECRET_PATH="secret/veracode@kvv2"
export VAULT_CLI_NAMESPACE="optional_namespace"
export VAULT_CLI_AUTH_PATH="auth/jwt"  # Optional, defaults to "auth/jwt"
```

The Vault secret should contain:
- `api_id`: Your Veracode API ID
- `api_secret`: Your Veracode API Key

Optional proxy configuration fields in Vault secret:
- `proxy_url`: HTTP/HTTPS proxy URL (e.g., `http://proxy.company.com:8080`)
- `proxy_username`: Proxy authentication username (optional)
- `proxy_password`: Proxy authentication password (optional)

**Note**: Proxy configuration in Vault takes precedence over environment variables.

### Proxy Configuration

For corporate network environments requiring proxy access:

```bash
# Standard proxy configuration (environment variables)
export HTTPS_PROXY="http://proxy.company.com:8080"
export HTTP_PROXY="http://proxy.company.com:8080"

# Optional proxy authentication
export PROXY_USERNAME="proxy-user"
export PROXY_PASSWORD="proxy-password"
```

**Priority**: Vault proxy config → Environment variables → Direct connection

### Region Configuration

Specify the Veracode region:
- `commercial` (default)
- `european`
- `federal`

```bash
veracmek --region european [command]
```

### Development Configuration

For development environments, you can disable certificate validation:

```bash
export VERACMEK_DISABLE_CERT_VALIDATION=true
```

**⚠️ Warning**: Only use this in development environments!

## Usage

### Basic Commands

#### Enable CMEK on a Single Application

```bash
# By application name
veracmek enable --app "My Application" --kms-alias "alias/my-cmek-key"

# By application GUID
veracmek enable --app "12345678-1234-1234-1234-123456789012" --kms-alias "alias/my-cmek-key"
```

#### Change Encryption Key

```bash
veracmek change-key --app "My Application" --new-kms-alias "alias/new-cmek-key"
```

#### Check Encryption Status

```bash
# Check specific application
veracmek status --app "My Application"

# Check all applications
veracmek status
```

### Bulk Operations

#### Enable CMEK on All Applications

```bash
# Dry run (preview changes)
veracmek bulk --kms-alias "alias/my-cmek-key" --dry-run

# Apply changes
veracmek bulk --kms-alias "alias/my-cmek-key"

# Skip already encrypted applications
veracmek bulk --kms-alias "alias/my-cmek-key" --skip-encrypted
```

### File-based Processing

Create a JSON configuration file with application-specific settings:

```json
{
  "applications": [
    {
      "app": "my-app-guid-or-name",
      "kms_alias": "alias/my-cmek-key",
      "skip_if_encrypted": false
    },
    {
      "app": "another-application",
      "kms_alias": "alias/another-cmek-key",
      "skip_if_encrypted": true
    }
  ]
}
```

Process the file:

```bash
# Dry run
veracmek from-file --file apps.json --dry-run

# Apply changes
veracmek from-file --file apps.json
```

### Output Formats

#### Table Format (Default)
```bash
veracmek status --output table
```

#### JSON Format
```bash
veracmek status --output json
```

### Help and Documentation

```bash
# Get help for all commands
veracmek --help

# Get help for specific command
veracmek enable --help

# View environment variables and file format help
veracmek help-env
```

## Examples

### Common Workflows

#### 1. Preview and Apply Bulk Encryption

```bash
# First, see what would be encrypted
veracmek bulk --kms-alias "alias/production-cmek" --dry-run --skip-encrypted

# If satisfied, apply the changes
veracmek bulk --kms-alias "alias/production-cmek" --skip-encrypted
```

#### 2. Application-Specific Configuration

```bash
# Create configuration file
cat > apps.json << EOF
{
  "applications": [
    {
      "app": "critical-app-1",
      "kms_alias": "alias/critical-cmek-key",
      "skip_if_encrypted": false
    },
    {
      "app": "dev-app-1",
      "kms_alias": "alias/dev-cmek-key",
      "skip_if_encrypted": true
    }
  ]
}
EOF

# Apply configuration
veracmek from-file --file apps.json
```

#### 3. Status Monitoring

```bash
# Check overall encryption status
veracmek status --output json > encryption_status.json

# Check specific application
veracmek status --app "My Critical App"
```

### Using with Vault

```bash
# Set up Vault environment
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
export VAULT_CLI_ROLE="veracode-role"
export VAULT_CLI_SECRET_PATH="secret/veracode@kvv2"

# Commands will automatically use Vault for credentials
veracmek status
```

**Vault Secret with Proxy Configuration** (optional):

```json
{
  "api_id": "your-veracode-api-id",
  "api_secret": "your-veracode-api-secret",
  "proxy_url": "http://proxy.company.com:8080",
  "proxy_username": "proxy-user",
  "proxy_password": "proxy-password"
}
```

### Using with Proxy (Environment Variables)

```bash
# Set proxy configuration
export HTTPS_PROXY="http://proxy.company.com:8080"
export PROXY_USERNAME="proxy-user"        # Optional: for authenticated proxies
export PROXY_PASSWORD="proxy-password"    # Optional: for authenticated proxies

# Run commands normally - proxy is automatically used
veracmek status
veracmek enable --app "MyApp" --kms-alias "alias/my-key"
```

## Security Considerations

- **Credential Storage**: Use Vault integration for production environments
- **Proxy Security**: Proxy credentials can be stored securely in Vault or environment variables
  - Vault proxy configuration takes precedence over environment variables
  - Proxy authentication credentials are handled securely and not exposed in logs
  - Supports both authenticated and non-authenticated proxies
- **KMS Permissions**: Ensure your AWS credentials have appropriate KMS permissions
- **Network Security**: Always use HTTPS for Vault connections
- **Audit Logging**: Enable appropriate logging levels for audit trails
- **Key Rotation**: Regularly rotate your Veracode API credentials and KMS keys

## Error Handling

Veracmek provides detailed error messages and handles various failure scenarios:

- **Authentication failures**: Clear messages about credential issues
- **Network problems**: Automatic retry with exponential backoff
- **Application not found**: Specific guidance for resolution
- **Permission issues**: Detailed error context for troubleshooting

## Logging

Set logging levels using the `--log-level` flag or `RUST_LOG` environment variable:

```bash
# Available levels: error, warn, info, debug, trace
veracmek --log-level debug status

# Or using environment variable
export RUST_LOG=debug
veracmek status
```

## Dependencies

- **clap**: Command-line argument parsing
- **tokio**: Async runtime
- **serde/serde_json**: JSON serialization
- **veracode-platform**: Veracode API client library
- **vaultrs**: HashiCorp Vault client
- **backoff**: Retry logic with exponential backoff
- **secrecy**: Secure handling of sensitive data
- **anyhow/thiserror**: Error handling

## Contributing

1. Ensure all tests pass: `cargo test`
2. Format code: `cargo fmt`
3. Run clippy: `cargo clippy`
4. Update documentation as needed

## License

See the main project license for details.

## Support

For issues and questions:
1. Check the help output: `veracmek help-env`
2. Review error messages for specific guidance
3. Consult the Veracode API documentation
4. Contact your Veracode support team